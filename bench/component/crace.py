#!/usr/bin/env python3
"""Archive CREATION race: crace.py --payload DIR --work DIR --rounds N --tools a,b,c --bin name=path ... [--only s1,s2] [--label host]

Shapes are fixed below (the component corpus: rand.bin, mixed.bin, rep.bin,
small/ - 1 GiB each). Every round runs each shape over the tools in a
rotating order, then the reverse ("mirror"), one process per cell. Per cell:
outputs removed, the command run under the clock, wall from a monotonic
timer, user/sys/maxrss from the children's rusage delta, packed bytes summed
over the outputs, and for every RAR-format output an `unrar t` verification
(rar's own archives too, so the verifier is the same for both arms). Inputs
are pre-read once so both arms see a warm page cache. Results as `CELL`
lines plus per-shape medians at the end.

Tool names: rar (RARLab rar), ours (rar5cli at the WRITER'S DEFAULT
dictionary, whatever that is on the tree under test - 128 KiB through
7 Sep 2026, 2 MiB from 8 Sep 2026, so the `ours` column is NOT comparable
across that boundary and a round must say which it measured), ours32
(rar5cli -md 32 MiB, rar's -m3 default), ours32-mo
(ours32 plus `-mo`, the cost-based optimal parse, which is OFF by default in
the writer - added 7 Sep 2026), sevenz (7-Zip; a DIFFERENT format - context
column, never a RAR comparison).
"""
import argparse, os, resource, shutil, statistics, subprocess, sys, time, glob

MB125 = 125 * 1000 * 1000

SHAPES = {
    # name: (input glob, {tool: argv template}, verify kind)
    "store": ("rand.bin", {
        "rar":    "{rar} a -ma5 -m0 -ep -idq -y -o+ {out}.rar {inputs}",
        "ours":   "{ours} a -m0 {out}.rar {inputs}",
        "sevenz": "{sevenz} a -t7z -mx0 -bso0 -bsp0 -y {out}.7z {inputs}",
    }),
    "storev": ("rand.bin", {
        "rar":    "{rar} a -ma5 -m0 -ep -idq -y -o+ -v125m {out}.rar {inputs}",
        "ours":   "{ours} a -m0 -v%d {out}.rar {inputs}" % MB125,
    }),
    "m3": ("mixed.bin", {
        "rar":    "{rar} a -ma5 -m3 -ep -idq -y -o+ {out}.rar {inputs}",
        "ours":   "{ours} a -m3 {out}.rar {inputs}",
        "ours32": "{ours} a -m3 -md33554432 {out}.rar {inputs}",
        "ours32-mo": "{ours} a -m3 -mo -md33554432 {out}.rar {inputs}",
        "sevenz": "{sevenz} a -t7z -mx3 -bso0 -bsp0 -y {out}.7z {inputs}",
    }),
    "m3v": ("mixed.bin", {
        "rar":    "{rar} a -ma5 -m3 -ep -idq -y -o+ -v125m {out}.rar {inputs}",
        "ours":   "{ours} a -m3 -v%d {out}.rar {inputs}" % MB125,
        "ours32": "{ours} a -m3 -md33554432 -v%d {out}.rar {inputs}" % MB125,
        "ours32-mo": "{ours} a -m3 -mo -md33554432 -v%d {out}.rar {inputs}" % MB125,
    }),
    "rep": ("rep.bin", {
        "rar":    "{rar} a -ma5 -m3 -ep -idq -y -o+ {out}.rar {inputs}",
        "ours":   "{ours} a -m3 {out}.rar {inputs}",
        "ours32": "{ours} a -m3 -md33554432 {out}.rar {inputs}",
        "ours32-mo": "{ours} a -m3 -mo -md33554432 {out}.rar {inputs}",
    }),
    "small": ("small/*", {
        "rar":    "{rar} a -ma5 -m3 -ep -idq -y -o+ {out}.rar {inputs}",
        "ours":   "{ours} a -m3 {out}.rar {inputs}",
        "ours32": "{ours} a -m3 -md33554432 {out}.rar {inputs}",
        "ours32-mo": "{ours} a -m3 -mo -md33554432 {out}.rar {inputs}",
    }),
    "enc": ("rand.bin", {
        "rar":    "{rar} a -ma5 -m0 -ep -idq -y -o+ -hpbenchpw {out}.rar {inputs}",
        "ours":   "{ours} a -m0 -hpbenchpw {out}.rar {inputs}",
        "sevenz": "{sevenz} a -t7z -mx0 -mhe=on -pbenchpw -bso0 -bsp0 -y {out}.7z {inputs}",
    }),
}
ORDER = ["store", "storev", "m3", "m3v", "rep", "small", "enc"]

def outputs(out):
    return sorted(glob.glob(out + "*"))

def clear(out):
    for f in outputs(out):
        os.remove(f)

def run_cell(cmd):
    # Reap the child with wait4 ourselves so user/sys/maxrss are THIS cell's
    # (RUSAGE_CHILDREN's maxrss is a running maximum over every child).
    import tempfile
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        t0 = time.perf_counter()
        p = subprocess.Popen(cmd, shell=True, stdout=out, stderr=err)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.perf_counter() - t0
        p.returncode = os.waitstatus_to_exitcode(status)
        err.seek(0); out.seek(0)
        tail = (err.read() or out.read())[-300:].decode(errors="replace")
    return wall, ru.ru_utime, ru.ru_stime, ru.ru_maxrss, p.returncode, tail

def verify(kind_files, unrar, sevenz, password):
    rars = [f for f in kind_files if f.endswith(".rar")]
    if rars:
        first = sorted(rars)[0]
        pw = f"-p{password}" if password else "-p-"
        p = subprocess.run([unrar, "t", "-inul", pw, first], capture_output=True)
        return "ok" if p.returncode == 0 else f"UNRAR-T-FAIL({p.returncode})"
    sz = [f for f in kind_files if f.endswith(".7z")]
    if sz and sevenz:
        pw = f"-p{password}" if password else "-p-"
        p = subprocess.run([sevenz, "t", "-bso0", "-bsp0", pw, sz[0]], capture_output=True)
        return "ok" if p.returncode == 0 else f"7Z-T-FAIL({p.returncode})"
    return "unverified"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--tools", default="rar,ours,ours32,ours32-mo,sevenz")
    ap.add_argument("--bin", action="append", default=[])
    ap.add_argument("--unrar", required=True)
    ap.add_argument("--only", default=",".join(ORDER))
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    bins = dict(b.split("=", 1) for b in a.bin)
    tools = a.tools.split(",")
    shapes = [s for s in a.only.split(",") if s in SHAPES]
    os.makedirs(a.work, exist_ok=True)
    # warm the inputs once
    for s in shapes:
        for f in glob.glob(os.path.join(a.payload, SHAPES[s][0])):
            with open(f, "rb") as fh:
                while fh.read(1 << 24):
                    pass
    results = {}
    packed = {}
    for r in range(a.rounds):
        rot = tools[r % len(tools):] + tools[: r % len(tools)]
        for order in (rot, rot[::-1]):
            for s in shapes:
                inputs = " ".join(sorted(glob.glob(os.path.join(a.payload, SHAPES[s][0]))))
                for tool in order:
                    tmpl = SHAPES[s][1].get(tool)
                    if tmpl is None:
                        continue
                    key = "ours" if tool.startswith("ours") else tool
                    if key not in bins:
                        continue
                    out = os.path.join(a.work, f"{s}-{tool}")
                    clear(out)
                    cmd = tmpl.format(out=out, inputs=inputs, **{k: bins.get(k, k) for k in ("rar", "ours", "sevenz")})
                    wall, ut, st, rss, rc, tail = run_cell(cmd)
                    files = outputs(out)
                    size = sum(os.path.getsize(f) for f in files)
                    password = "benchpw" if s == "enc" else None
                    ver = verify(files, a.unrar, bins.get("sevenz"), password) if rc == 0 else f"RC={rc} {tail.strip()[-120:]}"
                    print(f"CELL {a.label} round={r} shape={s} tool={tool} wall_s={wall:.3f} user_s={ut:.2f} sys_s={st:.2f} maxrss_mb={rss / (1048576 if sys.platform == 'darwin' else 1024):.0f} bytes={size} files={len(files)} verify={ver}", flush=True)
                    results.setdefault((s, tool), []).append((wall, ut + st))
                    packed[(s, tool)] = size
                    clear(out)
    print("== medians (wall s, cpu s, packed bytes)")
    for s in shapes:
        for tool in tools:
            if (s, tool) in results:
                w = statistics.median(x[0] for x in results[(s, tool)])
                c = statistics.median(x[1] for x in results[(s, tool)])
                print(f"MED {a.label} {s:7s} {tool:7s} wall={w:8.3f} cpu={c:8.2f} bytes={packed[(s, tool)]}")

main()
