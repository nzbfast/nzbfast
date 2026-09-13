#!/usr/bin/env python3
"""Read the scenario rig's LEG lines and print one row per shape and tool.

    scen-summarise.py [--markdown] <log> [<log> ...]

Both observations are printed, never a mean: a pair that disagrees is
the finding, and averaging it away is how a cold first pass gets
published as a tool's number. The rig runs each round forward and then
mirrored, so obs 1 and obs 2 hold opposite positions.

**A leg whose gate did not pass is not a time.** `sha=MISMATCH` (the
repair did not reproduce the pristine set), `sha=NO-REFERENCE` (the
reference was not there to check against - a missing gate is a failed
gate, never a pass) and a nonzero `rc` on an arm that does not use one
as success are all printed in place of the seconds. MultiPar's par2j
returns 16 after a SUCCESSFUL repair, so its rc is reported and the sha
gate is what decides it.
"""
import collections
import os
import re
import sys

ROW_ORDER = [
    "row1", "row2", "row3a", "row3b", "row4", "row6",
    "row5s100", "row5s110", "row5m100", "row5m110",
    "row7a", "row7b", "row8", "row9", "row10", "row10v",
]
# Exit codes that mean SUCCESS, per tool - par2j's 16 is a successful repair.
# NOT a copy of that knowledge: bench/rc-ok.tsv is the single definition and
# bench/lib/legrc.sh (the shell harnesses) reads the same file. A missing
# table is an error, never a default - defaulting would quietly turn par2j's
# 16 into a failed leg.
RC_TABLE = os.environ.get(
    "LEG_RC_TABLE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "rc-ok.tsv"),
)


def load_rc_ok(path=RC_TABLE):
    if not os.path.exists(path):
        sys.exit(f"scen-summarise: rc-ok table missing at {path}")
    table = {}
    with open(path) as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            tool, _, codes = line.strip().partition("\t")
            table[tool] = set(codes.split())
    return table


RC_OK = load_rc_ok()


def parse(paths):
    legs = collections.defaultdict(list)
    tools = []
    for path in paths:
        for line in open(path, errors="replace"):
            if not line.lstrip().startswith("LEG row="):
                continue
            f = dict(
                kv.split("=", 1)
                for kv in re.findall(r"\S+=\S*", line.strip())
            )
            row, tool = f.get("row"), f.get("tool")
            if not row or not tool:
                continue
            if tool not in tools:
                tools.append(tool)
            legs[(row, tool)].append(f)
    return legs, tools


def cell(obs):
    out = []
    for f in obs:
        sha = f.get("sha", "n/a")
        rc = f.get("rc", "")
        bad = sha in ("MISMATCH", "NO-REFERENCE") or (
            rc and rc not in RC_OK.get(f.get("tool", ""), {"0"})
        )
        if bad:
            out.append(f"FAIL({sha if sha != 'n/a' else 'rc=' + rc})")
        else:
            out.append(f"{float(f.get('wall', 0)):.2f}")
    body = " / ".join(out)
    cpu = [f.get("cpu", "") for f in obs if f.get("cpu") not in (None, "", "0")]
    rss = [f.get("rss_mb", "0") for f in obs]
    extra = []
    if cpu:
        extra.append("CPU " + "-".join(sorted({c.split(".")[0] for c in cpu})))
    if any(r not in ("0", "") for r in rss):
        extra.append("RSS " + max(rss, key=lambda r: int(r or 0)) + " MB")
    return body + (" (" + ", ".join(extra) + ")" if extra else "")


def main():
    args = [a for a in sys.argv[1:]]
    md = "--markdown" in args
    if md:
        args.remove("--markdown")
    if not args:
        sys.exit(__doc__)
    legs, tools = parse(args)
    rows = [r for r in ROW_ORDER if any((r, t) in legs for t in tools)]
    rows += sorted({r for (r, _t) in legs} - set(rows))

    if md:
        print("| row | " + " | ".join(tools) + " |")
        print("|---" * (len(tools) + 1) + "|")
        for r in rows:
            cells = [cell(legs[(r, t)]) if (r, t) in legs else "-" for t in tools]
            print(f"| {r} | " + " | ".join(cells) + " |")
        return
    w = max(len(t) for t in tools) + 2
    print(f"{'row':<10}" + "".join(f"{t:<{max(w, 28)}}" for t in tools))
    for r in rows:
        cells = [cell(legs[(r, t)]) if (r, t) in legs else "-" for t in tools]
        print(f"{r:<10}" + "".join(f"{c:<{max(w, 28)}}" for c in cells))


if __name__ == "__main__":
    main()
