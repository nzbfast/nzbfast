#!/usr/bin/env python3
"""Position-bias reader for shootout LEG lines: is a two-arm race SEPARABLE?

Written 3 Sep 2026 for the shootout-position-bias lane. `summarise.py` answers
"which tool is fastest" and cannot answer "is this delta real", which is the
question an A/A (one binary against a byte-identical copy of itself) asks and
the question audit round 24's stored column got wrong.

Reads any number of LEG logs and prints, per shape:

  * the per-arm median and the delta, over per-ROUND medians so `--reps N`
    and `--layout mirror` fold before the arms are compared rather than after;
  * the paired win count (how many rounds each arm won), which is the number
    that catches a 0/6 or 6/6 sweep - a sweep is a systematic effect however
    small the median delta is;
  * the median by POSITION IN THE ROUND, which is the bias itself, measured
    without reference to which binary held that position;
  * the between-leg instrumentation (gap/tear/fp), also by position, so a
    position effect can be attributed rather than guessed at.

A/A ACCEPTANCE, and it is the whole reason this file exists: a protocol is
flat when no shape reads over about 1.5% and no arm sweeps every round.

TWO LEG DIALECTS are read, because the same question is asked of both
harnesses and one reader is better than two that drift. `shootout`'s is
positional (`LEG <shape> <tool> <round> <secs> <verdict> pos=..`); the PAR2
round drivers' is all key=value (`LEG r=1 pos=1 leg=101 tool=sched16
wall=1.843 sha_ok=21/21`), carries no between-leg instrumentation, and
states its content gate as a ratio, which is `ok` only when it is whole.
"""
import sys, collections, statistics


def median(v):
    return statistics.median(v) if v else None


def parse_leg(line):
    """One LEG line in either dialect, or None."""
    f = line.split()
    if len(f) < 2:
        return None
    if f[1].count("=") and f[1].split("=")[0] in ("r", "pos", "leg"):
        # par2-round.{sh,ps1}: every field is key=value.
        kv = dict(tok.split("=", 1) for tok in f[1:] if "=" in tok)
        gate = kv.get("sha_ok", "")
        got, _, want = gate.partition("/")
        return dict(
            shape=kv.get("leg", "?"),
            tool=kv.get("tool", "?"),
            round=int(kv.get("r", 0)),
            secs=float(kv["wall"]),
            verdict="ok" if got and got == want else f"sha_ok={gate}",
            pos=int(kv.get("pos", -1)),
            gap=float("nan"),
            tear=float("nan"),
            fp=float("nan"),
            warm=float("nan"),
        )
    if len(f) < 6 or f[4] == "-":
        return None
    kv = {}
    for tok in f[6:]:
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k] = v
    return dict(
        shape=f[1],
        tool=f[2],
        round=int(f[3]),
        secs=float(f[4]),
        verdict=f[5],
        pos=int(kv.get("pos", -1)),
        gap=float(kv.get("gap_ms", "nan")),
        tear=float(kv.get("tear_ms", "nan")),
        fp=float(kv.get("fp_ms", "nan")),
        warm=float(kv.get("warm_ms", "nan")),
    )


def main(paths):
    legs = []
    for path in paths:
        for line in open(path):
            if not line.startswith("LEG "):
                continue
            leg = parse_leg(line)
            if leg is not None:
                legs.append(leg)
    bad = [l for l in legs if l["verdict"] != "ok"]
    if bad:
        print(f"!! {len(bad)} leg(s) did not pass the content gate - "
              f"{sorted({l['verdict'] for l in bad})}")
    legs = [l for l in legs if l["verdict"] == "ok"]

    shapes = sorted({l["shape"] for l in legs}, key=lambda s: [l["shape"] for l in legs].index(s))
    tools = sorted({l["tool"] for l in legs})

    print(f"# {len(legs)} ok legs, tools={','.join(tools)}")
    print()
    print(f"{'shape':<11}" + "".join(f"{t:>12}" for t in tools) + f"{'delta':>9}{'wins':>10}")
    for sh in shapes:
        per_round = collections.defaultdict(dict)  # round -> tool -> median secs
        for t in tools:
            for rnd in sorted({l["round"] for l in legs if l["shape"] == sh}):
                v = [l["secs"] for l in legs if l["shape"] == sh and l["tool"] == t and l["round"] == rnd]
                if v:
                    per_round[rnd][t] = median(v)
        row = f"{sh:<11}"
        med = {}
        for t in tools:
            v = [r[t] for r in per_round.values() if t in r]
            med[t] = median(v)
            row += f"{med[t]:>12.3f}" if med[t] is not None else f"{'--':>12}"
        if len(tools) == 2 and all(med[t] for t in tools):
            a, b = tools
            row += f"{(med[b] / med[a] - 1) * 100:>+8.1f}%"
            paired = [r for r in per_round.values() if a in r and b in r]
            wins_b = sum(1 for r in paired if r[b] < r[a])
            row += f"{f'{wins_b}/{len(paired)}':>10}"
        print(row)
    if len(tools) == 2:
        print(f"  (delta is arm 2 vs arm 1; wins is arm 2's, over per-round medians)")
    print()

    positions = sorted({l["pos"] for l in legs if l["pos"] >= 0})
    if positions:
        print("BY POSITION IN THE ROUND (the bias itself, arm-blind)")
        hdr = f"{'shape':<11}" + "".join(f"{'p' + str(p):>10}" for p in positions)
        print(hdr + f"{'spread':>9}")
        for sh in shapes:
            row = f"{sh:<11}"
            meds = []
            for p in positions:
                v = [l["secs"] for l in legs if l["shape"] == sh and l["pos"] == p]
                m = median(v)
                meds.append(m)
                row += f"{m:>10.3f}" if m is not None else f"{'--':>10}"
            ok = [m for m in meds if m is not None]
            if len(ok) > 1:
                row += f"{(max(ok) / min(ok) - 1) * 100:>+8.1f}%"
            print(row)
        # A dialect that carries no between-leg instrumentation (the PAR2
        # round drivers) has nothing to attribute a position effect TO, and
        # a table of nan reads like a measurement. Say so and stop.
        if all(l["gap"] != l["gap"] for l in legs):
            print("(no between-leg instrumentation in these legs)")
            return
        print()
        print("BETWEEN-LEG COST BY POSITION, median ms (gap = end of the previous")
        print("timed region to the start of this one; tear/fp are this leg's own)")
        print(f"{'shape':<11}{'pos':>5}{'gap':>9}{'prewarm':>9}{'tear':>9}{'fp':>9}")
        for sh in shapes:
            for p in positions:
                sel = [l for l in legs if l["shape"] == sh and l["pos"] == p]
                if not sel:
                    continue
                g = median([l["gap"] for l in sel])
                te = median([l["tear"] for l in sel])
                fp = median([l["fp"] for l in sel])
                wm = median([l["warm"] for l in sel])
                # gap is everything between: previous fp + previous tear +
                # settle + mkdir + this leg's prewarm. The residual is what
                # the harness cannot account for.
                print(f"{sh:<11}{p:>5}{g:>9.0f}{wm:>9.0f}{te:>9.0f}{fp:>9.0f}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
