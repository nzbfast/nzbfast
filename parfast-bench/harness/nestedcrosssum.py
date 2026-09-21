#!/usr/bin/env python3
"""Reduce nestedcross.sh LEG lines to the section 6.6 markdown table.

A READER, not a writer: it emits no LEG line of its own, which is why
`tools/harness-rig-gate.py` does not ask it for a stamp (its SCOPE note lists
`tools/` and `bench/component/` readers for the same reason). The stamp it
reports belongs to the DRIVER, read back out of the log it is handed.

    nestedcrosssum.py <round.log> [--payload BYTES] [--input BYTES]

`x payload` is `dpeak` against the payload the job produces (1,073,741,824 B
on the `gran` fixture), which is the column section 6.2 uses; `consume` is
the inner input divided by the chase worker's own elapsed ms, and it is the
quantity section 6.3 says a quiet box moves and a loaded one cannot supply.
"""
import re, sys, argparse

PAYLOAD = 1_073_741_824
INNER = 589_182_122

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--payload", type=int, default=PAYLOAD)
    ap.add_argument("--input", type=int, default=INNER)
    a = ap.parse_args()

    text = open(a.log, encoding="utf-8", errors="replace").read()
    rig = re.search(r"^HARNESS-RIG (.+)$", text, re.M)
    print(f"driver: {rig.group(1) if rig else '(unstamped)'}\n")

    rows = []
    for line in text.splitlines():
        # harness-rig-gate: a READER. This literal is the needle it PARSES
        # out of a log another driver banked; it writes no log of its own,
        # and the stamp it reports is that driver's, read back above.
        if not line.startswith("LEG "):
            continue
        f = dict(
            p.split("=", 1) for p in line[4:].split(" env=")[0].split() if "=" in p
        )
        rows.append(f)
    if not rows:
        print("no LEG lines", file=sys.stderr)
        return 2

    hdr = ("| leg | line MB/s | holds peak | released | peak RSS | dpeak KB "
           "| x payload | consume MB/s | passes | wall | load1 | load15 |")
    print(hdr)
    print("|" + "---|" * 12)
    for f in rows:
        def num(k, cast=float, d=None):
            try:
                return cast(re.sub(r"[A-Za-z]+$", "", f.get(k, "")))
            except (TypeError, ValueError):
                return d
        dpeak = num("dpeak", int)
        ms = num("chasems", int)
        xp = f"{dpeak * 1024 / a.payload:.2f}x" if dpeak else "?"
        cons = f"{a.input / 1e6 / (ms / 1000):.0f}" if ms else "?"
        line = f.get("line", "?")
        print(f"| {f.get('tag','?')} | {'unthrottled' if line=='0' else line} "
              f"| {f.get('holdspk','?')} | {f.get('trimmed','?')} "
              f"| {f.get('rss','?')} | {dpeak if dpeak else '?':,} | {xp} "
              f"| {cons} | {f.get('passes','?')} | {f.get('wall','?')} "
              f"| {f.get('load1','?')} | {f.get('load15','?')} |")

    bad = [f for f in rows if f.get("sha") != "yes" or f.get("rc") != "0"]
    print(f"\n{len(rows)} leg(s); "
          + ("ALL rc=0 and byte-exact" if not bad
             else f"**{len(bad)} leg(s) NOT clean**: "
                  + ", ".join(f"{f.get('tag')}(rc={f.get('rc')},sha={f.get('sha')})"
                              for f in bad)))
    return 0

if __name__ == "__main__":
    sys.exit(main())
