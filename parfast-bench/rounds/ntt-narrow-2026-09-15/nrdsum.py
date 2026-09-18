#!/usr/bin/env python3
"""nrdsum.py - reduce the NEON narrowing A/B (nrd.py legs) to one table.

    nrdsum.py DIR      DIR holds fold.jsonl, force.jsonl, new.jsonl, base.jsonl

Written 15 Sep 2026 for lane parfast-ntt-narrow-admits-unpriced-stripe-14sep
(an internal note, section 8).
The legs are harness/memladder.py records, four arms interleaved per
rung and rep at `-t4 -m128`: `fold` and `force` on the base binary, `auto` on
the change (new.jsonl) and `auto` on the base (base.jsonl). Every cell is the
MINIMUM whole-process CPU over reps; a leg whose SHA gate failed is refused.
`new/best` is the change's CPU over min(fold, forced W = 512), the brief's
acceptance ratio; `base/new` is what the change bought (> 1 = cheaper now).
"""
import json
import os
import sys


def load(path):
    rows = [json.loads(l) for l in open(path)]
    for r in rows:
        if not r["ok"] or r["rc"] != 0:
            sys.exit("REFUSED: leg did not restore: %s m=%s rep=%s" % (path, r["m"], r["rep"]))
    return rows


def best(rows):
    out = {}
    for r in rows:
        if r["m"] not in out or r["cpu"] < out[r["m"]]["cpu"]:
            out[r["m"]] = r
    return out


def decision(r):
    if r["path"] == "fold":
        return "fold"
    return "W %s, %d win" % ("/".join(str(w) for w in r["ntt_w"]), r["ntt_windows"])


def main(d):
    arms = {a: best(load(os.path.join(d, a + ".jsonl"))) for a in ("fold", "force", "new", "base")}
    reps = {a: len(load(os.path.join(d, a + ".jsonl"))) for a in arms}
    print("legs per arm: %s" % reps)
    print("| m | fold | force | auto (change) | decision | auto (base) | decision | new / best | base / new |")
    print("|---:|---:|---:|---:|---|---:|---|---:|---:|")
    for m in sorted(arms["new"]):
        fo, fc, nw, bs = (arms[a][m] for a in ("fold", "force", "new", "base"))
        bestc = min(fo["cpu"], fc["cpu"])
        print("| %d | %.2f | %.2f | %.2f | %s | %.2f | %s | %.2f | %.2f |" % (
            m, fo["cpu"], fc["cpu"], nw["cpu"], decision(nw), bs["cpu"], decision(bs),
            nw["cpu"] / bestc, bs["cpu"] / nw["cpu"]))
    diff = [m for m in sorted(arms["new"]) if decision(arms["new"][m]).split(",")[0] != decision(arms["base"][m]).split(",")[0]]
    print("\nrungs where the two dispatchers decided differently: %s" % (diff or "none"))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
