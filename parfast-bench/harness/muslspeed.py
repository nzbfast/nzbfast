#!/usr/bin/env python3
"""muslspeed.py - timed A/B/A of parfast allocator builds on one Linux box
(claim parfast-musl-allocator-speed-15sep). Runs as root inside a wrapper
that holds ~/.parfast-rig.lock. Reuses pdrv.py's quiet gate, damage plan and
restore.

Layout under $R: fix/{pristine,work,gold.sha} (64 KiB, c4096) and fix1m/...
(1 MiB, c512), members m01..m16.bin, par2 set named set.par2.

env: ARMS "name=path,name=path,..." (order is the base rotation), REPS,
     CELLS (comma subset), OUT (jsonl), MODE=time|perf

Every leg runs under `perf stat -x, -e cycles,instructions` so a
cycles figure travels with wall and CPU, and under wait4 for utime / stime /
faults / context switches separately (allocator lock contention shows as
stime and voluntary switches, not only as user time).
"""
import hashlib, json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdrv import (apply_damage, damage_picks, harness_facts, remove_strays, restore_slices,  # noqa: E402
                  require_quiet_box, set_quiet_budget, foreign_cpu,
                  cpu_stat_jiffies, _steal_pct, warm)

R = os.environ.get("R", "/root/muslspeed-15sep")
REPS = int(os.environ.get("REPS", "5"))
MODE = os.environ.get("MODE", "time")
OUT = os.path.join(R, os.environ.get("OUT", "time.jsonl"))
LOGDIR = os.path.join(R, "tlegs")
os.makedirs(LOGDIR, exist_ok=True)
ARMS = [tuple(kv.split("=", 1)) for kv in os.environ["ARMS"].split(",")]
MEMBERS = ["m%02d.bin" % i for i in range(1, 17)]

# name: (fixture, slice, kind, extra args, damage m)
CELLS = {
    "c64":    ("fix", 65536, "c", ["-s65536", "-c4096"], 0),
    "c64m":   ("fix", 65536, "c", ["-s65536", "-c4096", "-m128"], 0),
    "c1m":    ("fix1m", 1048576, "c", ["-s1048576", "-c512"], 0),
    "c1mm":   ("fix1m", 1048576, "c", ["-s1048576", "-c512", "-m128"], 0),
    "r64":    ("fix", 65536, "r", [], 1024),
    "r64m":   ("fix", 65536, "r", ["-m128"], 1024),
    "r1m":    ("fix1m", 1048576, "r", [], 192),
    "r1mm":   ("fix1m", 1048576, "r", ["-m128"], 192),
    "v64":    ("fix", 65536, "v", [], 0),
}
ORDER = os.environ.get("CELLS", ",".join(CELLS)).split(",")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def fixture(name):
    fix = os.path.join(R, name)
    pristine, work = os.path.join(fix, "pristine"), os.path.join(fix, "work")
    gold = {}
    for line in open(os.path.join(fix, "gold.sha")):
        h, nm = line.split()
        gold[nm.lstrip("*")] = h
    return pristine, work, gold, set(os.listdir(pristine))


def bad_members(work, gold):
    return [m for m in MEMBERS if sha(os.path.join(work, m)) != gold[m]]


def loadavg():
    with open("/proc/loadavg") as f:
        return f.read().split()[:3]


def argv_for(cell):
    fixn, slicesize, kind, extra, m = CELLS[cell]
    if kind == "c":
        return ["c"] + extra + ["-q", "cnew.par2"] + MEMBERS
    return [kind] + extra + ["-q", "set.par2"]


def run_one(exe, argv, cwd, base, perfdata=None):
    require_quiet_box(os.path.basename(base))
    fb, _ = foreign_cpu()
    sb = cpu_stat_jiffies()
    la0 = loadavg()
    if perfdata:
        cmd = ["perf", "record", "-F", "999", "-o", perfdata, "--", exe] + argv
    else:
        cmd = ["perf", "stat", "-x,", "-e", "cycles,instructions", "-o", base + ".pstat", "--", exe] + argv
    with open(base + ".out", "wb") as fo, open(base + ".err", "wb") as fe:
        t0 = time.monotonic()
        p = subprocess.Popen(cmd, cwd=cwd, stdout=fo, stderr=fe, stdin=subprocess.DEVNULL,
                             preexec_fn=lambda: os.nice(19))
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.monotonic() - t0
    rc = os.waitstatus_to_exitcode(status)
    fa, _ = foreign_cpu()
    rec = {"rc": rc, "wall": round(wall, 3), "utime": round(ru.ru_utime, 3), "stime": round(ru.ru_stime, 3),
           "cpu": round(ru.ru_utime + ru.ru_stime, 3), "maxrss_mib": round(ru.ru_maxrss / 1024.0, 1),
           "minflt": ru.ru_minflt, "majflt": ru.ru_majflt, "nvcsw": ru.ru_nvcsw, "nivcsw": ru.ru_nivcsw,
           "foreign_cpu": round(fb, 1), "foreign_after": round(fa, 1),
           "steal_pct": _steal_pct(sb, cpu_stat_jiffies()), "load0": la0, "load1": loadavg()}
    if not perfdata:
        try:
            for line in open(base + ".pstat"):
                parts = line.strip().split(",")
                if len(parts) > 2 and parts[2] in ("cycles", "instructions"):
                    rec[parts[2]] = int(parts[0]) if parts[0].isdigit() else None
        except OSError:
            pass
    return rec


def leg(cell, arm, exe, rep, perfdata=None):
    fixn, slicesize, kind, extra, m = CELLS[cell]
    pristine, work, gold, keep = fixture(fixn)
    remove_strays(work, keep)
    picks = None
    if kind == "r":
        picks = damage_picks(work, MEMBERS, slicesize, m, 1000 + m)
        apply_damage(work, MEMBERS, slicesize, picks, 1)
    tag = "%s-%s-r%d%s" % (cell, arm, rep, "-perf" if perfdata else "")
    rec = run_one(exe, argv_for(cell), work, os.path.join(LOGDIR, tag), perfdata)
    rec.update({"cell": cell, "arm": arm, "rep": rep, "exe": exe, "argv": " ".join(argv_for(cell)),
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    if kind == "c":
        made = sorted(n for n in os.listdir(work) if n not in keep)
        h = hashlib.sha256()
        for n in made:
            h.update(n.encode())
            h.update(sha(os.path.join(work, n)).encode())
        rec["out_files"] = len(made)
        rec["out_hash"] = h.hexdigest()[:16]
        rec["ok"] = rec["rc"] == 0 and len(made) > 0
    elif kind == "r":
        bad = bad_members(work, gold)
        rec["ok"] = rec["rc"] == 0 and not bad
        rec["bad"] = len(bad)
        if bad:
            restore_slices(work, pristine, MEMBERS, slicesize, picks)
    else:
        rec["ok"] = rec["rc"] == 0
    remove_strays(work, keep)
    # par2 volumes must be untouched; members must be gold before the next leg
    for nm in keep:
        if not nm.endswith(".bin") and os.path.getsize(os.path.join(work, nm)) != os.path.getsize(os.path.join(pristine, nm)):
            raise SystemExit("par2 volume changed at " + tag)
    if kind == "r" and bad_members(work, gold):
        raise SystemExit("restore failed at " + tag)
    return rec


def main():
    # The HARNESS's own provenance, and the round-start twin of the
    # per-leg `rig=` token - see `pdrv.harness_facts`. Without it a
    # banked log cannot be traced to the harness revision that wrote
    # it (census an internal note).
    harness_facts()
    set_quiet_budget(60, 30)
    for fixn in ("fix", "fix1m"):
        warm(os.path.join(R, fixn, "work"))
    with open(OUT, "a") as out:
        if MODE == "perf":
            for cell in ORDER:
                for arm, exe in ARMS:
                    pd = os.path.join(LOGDIR, "%s-%s.perf.data" % (cell, arm))
                    rec = leg(cell, arm, exe, 0, perfdata=pd)
                    rec["perfdata"] = pd
                    out.write(json.dumps(rec) + "\n")
                    out.flush()
                    print("PERF %s %s rc=%s ok=%s wall=%.2f cpu=%.1f" % (cell, arm, rec["rc"], rec["ok"], rec["wall"], rec["cpu"]), flush=True)
            return
        n = len(ARMS)
        for rep in range(1, REPS + 1):
            for ci, cell in enumerate(ORDER):
                k = (rep + ci) % n
                order = ARMS[k:] + ARMS[:k]
                if rep % 2 == 0:
                    order = order[::-1]
                for arm, exe in order:
                    rec = leg(cell, arm, exe, rep)
                    out.write(json.dumps(rec) + "\n")
                    out.flush()
                    print("LEG %-5s %-7s r%d rc=%s ok=%s wall=%7.2f cpu=%7.2f u=%7.2f s=%6.2f cyc=%s vcs=%s flt=%s foreign=%s/%s steal=%s load=%s/%s%s"
                          % (cell, arm, rep, rec["rc"], rec["ok"], rec["wall"], rec["cpu"], rec["utime"], rec["stime"],
                             rec.get("cycles"), rec["nvcsw"], rec["minflt"], rec["foreign_cpu"], rec["foreign_after"],
                             rec["steal_pct"], rec["load0"][0], rec["load1"][0],
                             (" out=" + rec["out_hash"]) if "out_hash" in rec else ""), flush=True)
                    if not rec["ok"]:
                        print("LEG-FAILED see %s" % os.path.join(LOGDIR, "%s-%s-r%d.err" % (cell, arm, rep)), flush=True)


if __name__ == "__main__":
    main()
