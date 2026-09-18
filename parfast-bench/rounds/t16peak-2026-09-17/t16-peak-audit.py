#!/usr/bin/env python3
"""Is the 19,082 MB peak what breaks `4m-t16`? NO - and it never was that arm's peak.

Written 17 Sep 2026 for lane `parfast-t16-peak-vs-budget-17sep`, whose brief was
to run a `-t16` ladder at a smaller `NZBFAST_NTT_BUDGET` against one at 20 GiB on
intel-core-ultra-9-386h and see whether moving the peak moves the arm's monotonicity. THE
ROUND WAS NOT RUN, because this script - box-free, over logs already banked -
answers the question three ways and the answer is no every time. The fleet's only
GFNI-256 part was held with a two-deep queue at the time; spending ~90 minutes of
it to confirm arithmetic would have been the wrong trade.

The three arms, each printed below:

  1. PROVENANCE. `peak_mb=19082.9` is the fixture CREATE's peak, on the line
     `CREATE rc=0 wall=19.79 cpu=280.875 peak_mb=19082.9`. It is in plt16.log and
     in no other arm's log because arm 1 of the pool round is the arm that BUILDS
     the 16 GiB fixture (the other four ran -NoBuild against what it made). So
     "19,082 against 16,429-16,490" compares a CREATE peak against FORCE-LEG
     peaks. `4m-t16`'s own force legs peak at 16,510-16,522 MB.

  2. THE LIKE-FOR-LIKE PEAK LADDER HAS NO STEP AT t16. Force-leg peaks across the
     pool round's five arms are linear in thread count at about 7 MB/thread, and
     t16 sits on the line, 0.5% above t4. There is no anomaly to explain.

  3. THE PEAK IS IDENTICAL IN THE SITTINGS WHERE THE ARM FAILED. All four
     sittings of this exact shape - unpinned, 4 MiB, n=4,096, resident, sixteen
     threads, 20 GiB budget - peak within 1.5 MB of each other, three of them
     non-monotone and one monotone. A quantity that is the same when the effect
     is present and when it is absent is not the cause. That is the same
     reasoning the landed round used to kill the no-spare-core hypothesis.

AND THE DISCRIMINATOR COULD NOT HAVE SEPARATED IT ANYWAY, which is arm 4 below.
Retention cuts a window at `retained_bytes > budget`
(par2repair/reconstruct.rs, the `if let Some(budget) = ntt_budget` block), and
`retained_bytes` stops at the corpus. The corpus here is
`n_present * block_size` = 14.25-14.75 GiB against a 20 GiB budget, so the budget
is NEVER the binding constraint: any budget above the corpus leaves the peak
exactly where it is, and any budget below it cuts a window, which
`-Residency resident` refuses (wcomb.ps1, "the forced arm WINDOWED"). The knob
moves the peak ONLY by changing which side of the gate the leg is on. The 12 GiB
the brief suggested is below the corpus at every rung, so it refuses at every
rung - that is arithmetic, not a prediction.

A FIFTH SUSPECT DIES HERE TOO, cheaply: foreign CPU does not explain the failures
either. The worst A/A floors sit at the LOWEST foreign readings (21.2% floor at
12% foreign) and the highest foreign reading in the corpus (116%) produced a
clean 3.1% rung. Printed as arm 5.

WHAT IS LEFT, and it is a lead rather than a finding: the perturbation is in the
FORCE arm only and is rung-localised. Fold is monotone and reproducible across
all four sittings at every rung; force is where the 10-24% A/A floors are.

RUN:  rounds/t16peak-2026-09-17/t16-peak-audit.py
from the repo root. No arguments, no box, no network.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

POOL = ROOT / "rounds/poolladder4m-2026-09-17/logs"
POOL_ARMS = [
    ("plt16.log", "4m-t16", 16, "unpinned, 4 P + 8 E + 4 LP-E"),
    ("ple4.log", "4m-e4", 4, "0xF0, four E-cores"),
    ("ple8.log", "4m-e8", 8, "0xFF0, eight E-cores"),
    ("plm12.log", "4m-m12", 12, "0xFFF, 4 P + 8 E"),
    ("plp4.log", "4m-p4", 4, "0xF, four P-cores"),
]

# The four sittings of ONE shape: unpinned, 4 MiB, n=4,096, resident, t16,
# 20 GiB budget. Verified same-shape on affinity/slice/n/residency before use.
T16 = [
    ("rounds/pinaff4m-2026-09-16/logs/attempt1/pint16.log", "attempt1"),
    ("rounds/pinaff4m-2026-09-16/logs/attempt2/pint16.log", "attempt2"),
    ("rounds/pinaff4m-2026-09-16/logs/attempt3/pint16.log", "attempt3"),
    ("rounds/poolladder4m-2026-09-17/logs/plt16.log", "poolladder"),
]

BLOCK = 4 * 1024 * 1024
N = 4096
RUNGS = [320, 352, 384, 416, 448]
GIB = 1024 ** 3

peak_re = re.compile(r"peak_mb=([\d.]+)")


def force_peaks(path):
    """Peaks of the `force`/`force2` measurement LEGS only - never the CREATE."""
    out = []
    for ln in Path(path).read_text(errors="replace").splitlines():
        if not ln.startswith("LEG "):
            continue
        if " arm=force" not in ln:
            continue
        m = peak_re.search(ln)
        if m:
            out.append(float(m.group(1)))
    return out


def create_lines(path):
    return [ln for ln in Path(path).read_text(errors="replace").splitlines()
            if ln.startswith("CREATE rc=")]


def rowgate(path):
    r = subprocess.run([sys.executable, "harness/rowgate.py", "read", str(path)],
                       capture_output=True, text=True, cwd=ROOT, timeout=300)
    return r.stdout


def main():
    print("=" * 78)
    print("1. WHERE 19,082 MB ACTUALLY COMES FROM")
    print("=" * 78)
    for fn, label, thr, mix in POOL_ARMS:
        p = POOL / fn
        cl = create_lines(p)
        print(f"  {label:<8} CREATE lines: {len(cl)}"
              + (f"   -> {cl[0]}" if cl else "   (ran -NoBuild, no fixture build)"))
    print("\n  The 19,082.9 MB is a CREATE peak and exists in one log because arm 1")
    print("  builds the fixture. It is not a measurement leg and not t16's leg peak.")

    print("\n  AND THE SAME FIGURE APPEARS IN A FOUR-THREAD ROUND, which settles it")
    print("  without any argument about CREATE-versus-LEG semantics at all:")
    for rel in ["rounds/t4m4-2026-09-16/"
                "coreultra9-gfni256-4m-n4096-t4-resident-ladder.log",
                "rounds/w4mib-2026-09-16/"
                "coreultra9-gfni256-4m-n4096-resident-ladder.log",
                "rounds/poolladder4m-2026-09-17/logs/plt16.log"]:
        pth = ROOT / rel
        cl = create_lines(pth)
        thr = sorted({int(t.split("=")[1]) for ln in pth.read_text(errors="replace").splitlines()
                      if ln.startswith("LEG ")
                      for t in ln.split() if t.startswith("threads=")})
        pk = peak_re.search(cl[0]).group(1) if cl else "-"
        print(f"    {Path(rel).name[:52]:<52} ladder t{thr} CREATE peak {pk} MB")
    print("  A `-t4` ladder's fixture create peaks at 19,077.9 MB, within 5 MB of the")
    print("  two t16 rounds. wcomb builds the fixture unpinned whatever the ladder's")
    print("  thread count, so ~19,080 MB is the CREATE's number on this fixture and")
    print("  belongs to no arm. It was never a property of sixteen threads.")

    print()
    print("=" * 78)
    print("2. THE LIKE-FOR-LIKE FORCE-LEG PEAK LADDER (no step at t16)")
    print("=" * 78)
    print(f"  {'arm':<8} {'thr':>3}  {'min peak':>9} {'max peak':>9}   core mix")
    base = None
    for fn, label, thr, mix in sorted(POOL_ARMS, key=lambda a: a[2]):
        pk = force_peaks(POOL / fn)
        if base is None:
            base = min(pk)
        print(f"  {label:<8} {thr:>3}  {min(pk):>9.1f} {max(pk):>9.1f}   {mix}")
    t4 = min(force_peaks(POOL / "ple4.log"))
    t16 = min(force_peaks(POOL / "plt16.log"))
    print(f"\n  t4 -> t16 is +{t16 - t4:.1f} MB over 12 threads = "
          f"{(t16 - t4) / 12:.1f} MB/thread, and +{100 * (t16 - t4) / t4:.2f}% of the peak.")
    print("  Monotone and evenly spaced in thread count: per-thread scratch, no anomaly.")

    print()
    print("=" * 78)
    print("3. THE PEAK IS THE SAME IN THE SITTINGS WHERE THE ARM FAILED")
    print("=" * 78)
    print(f"  {'sitting':<12} {'monotone':<9} {'min peak':>9} {'max peak':>9}  {'worst A/A':>9}")
    rows = []
    for rel, name in T16:
        p = ROOT / rel
        pk = force_peaks(p)
        txt = rowgate(p)
        # ANCHOR ON THE ROW, not on a bare column group: the F/T column and the
        # wF/wT column have the same shape, so an unanchored findall interleaves
        # the two and reports every ladder non-monotone. Same row regex the
        # pinaff round's ladder-monotonicity-audit.py uses.
        rowre = re.compile(
            r"^\s*(\d+) \|\s*[\d.]+\s+[\d.]+\s+([\d.]+) \|"
            r"\s*[\d.]+%\s+[\d.]+%\s+([\d.]+)%")
        ft, floors = [], []
        for ln in txt.splitlines():
            mm = rowre.match(ln)
            if mm:
                ft.append(float(mm.group(2)))
                floors.append(float(mm.group(3)))
        mono = all(b >= a for a, b in zip(ft, ft[1:])) if ft else None
        rows.append((name, mono, min(pk), max(pk), max(floors) if floors else 0.0))
        print(f"  {name:<12} {'yes' if mono else 'NO':<9} {min(pk):>9.1f} {max(pk):>9.1f}"
              f"  {max(floors) if floors else 0.0:>8.1f}%")
    lo = min(r[2] for r in rows)
    hi = max(r[3] for r in rows)
    print(f"\n  Across all four sittings the force-leg peak spans {lo:.1f}-{hi:.1f} MB,"
          f" a range of {hi - lo:.1f} MB.")
    print("  Three of these sittings are non-monotone and one is monotone, at the same")
    print("  peak. A cause present when the effect is absent is not the cause.")

    print()
    print("=" * 78)
    print("4. WHY THE BRIEFED DISCRIMINATOR COULD NOT HAVE SEPARATED IT")
    print("=" * 78)
    print("  Retention cuts a window at `retained_bytes > budget`; retained_bytes stops")
    print("  at the corpus, which is n_present * block_size:")
    print(f"\n  {'m':>5} {'n_present':>10} {'corpus':>14} {'resident @20GiB':>16} {'resident @12GiB':>16}")
    for m in RUNGS:
        npres = N - m
        corpus = npres * BLOCK
        print(f"  {m:>5} {npres:>10} {corpus / GIB:>11.2f} GiB"
              f" {'yes' if corpus <= 20 * GIB else 'NO':>16} {'yes' if corpus <= 12 * GIB else 'NO':>16}")
    widest = (N - min(RUNGS)) * BLOCK
    print(f"\n  The 20 GiB budget exceeds the widest corpus ({widest / GIB:.2f} GiB) by"
          f" {(20 * GIB - widest) / GIB:.2f} GiB, so it never binds:")
    print("  any budget above the corpus leaves the peak exactly where it is. Any budget")
    print("  below it cuts a window, which -Residency resident refuses. 12 GiB is below")
    print("  the corpus at EVERY rung, so it refuses at every rung.")
    print("  The knob moves the peak only by changing which side of the gate the leg is")
    print("  on, so peak and residency are not separable by it. There is no budget that")
    print("  moves the peak and keeps the leg resident.")

    print()
    print("=" * 78)
    print("5. FOREIGN CPU DOES NOT EXPLAIN THE FAILURES EITHER")
    print("=" * 78)
    print(f"  {'sitting':<12} {'rung':>5} {'A/A floor':>10} {'foreign max':>12}")
    pair = re.compile(r"^\s*(\d+) \|.*?%\s+([\d.]+)%\s+\|\s+\S+\s+\|.*?\|\s+(\d+)% ")
    allp = []
    for rel, name in T16:
        for ln in rowgate(ROOT / rel).splitlines():
            mm = pair.match(ln)
            if mm:
                allp.append((name, int(mm.group(1)), float(mm.group(2)), int(mm.group(3))))
    for name, m, floor, fg in sorted(allp, key=lambda r: -r[2])[:6]:
        print(f"  {name:<12} {m:>5} {floor:>9.1f}% {fg:>11}%")
    print("  ... and the highest foreign reading in the corpus:")
    for name, m, floor, fg in sorted(allp, key=lambda r: -r[3])[:2]:
        print(f"  {name:<12} {m:>5} {floor:>9.1f}% {fg:>11}%")
    print("\n  The worst A/A floors sit at low foreign readings and the highest foreign")
    print("  reading produced a clean rung, so the two are not tracking each other.")
    print("\n  WHAT IS LEFT (a lead, not a finding): the perturbation is FORCE-ARM ONLY")
    print("  and rung-localised. Fold is monotone and reproducible at every rung in all")
    print("  four sittings; every 10-24% A/A floor above is the force arm's.")


if __name__ == "__main__":
    main()
