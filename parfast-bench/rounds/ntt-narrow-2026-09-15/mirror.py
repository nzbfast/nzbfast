#!/usr/bin/env python3
"""mirror.py - replay ntt_admit_within's stripe narrowing over banked x86 legs.

    rounds/ntt-narrow-2026-09-15/mirror.py

Written 15 Sep 2026 for lane parfast-ntt-narrow-admits-unpriced-stripe-14sep
(an internal note, section 8).
Neither x86 rig was reachable that day, so the question "which step chose
each narrowed width, and what would the new rule decide?" is answered by
replaying the rule's arithmetic over the legs section 6 banked, and the replay
earns its keep only by reproducing every decision those legs RECORDED first.

What it mirrors, at `-t4` under a 128 MiB budget with `needed = m`:
  - FlatPlan::scratch_bytes (par2ntt.rs): (17*257 + 5*min(n,4369) +
    3*min(n,21845) + n) * w * 2, plus the paired kernel's arena
    max(257*w*2, 257*512*2) where it is enabled (nibble x86, NEON; NOT on
    GFNI), plus the additive kernel's 2^K * w * 2 with K = 9;
  - ntt_stripe_geometry_capped: workers = min(4, stripes);
  - ntt_window_row_gate behind the 320-source sanity floor;
  - step 3 (halve while arenas > budget - arenas), then step 4 OLD (narrow
    after any refusal) or NEW (narrow only while the window is too small for
    any row count).
The block size is each leg's recorded slab width. `auto` legs ran k = 312 and
`autoalt` legs k = 702, both on the OLD rule.

Exits 1 if any recorded decision is not reproduced. It is a mirror, not the
code: when the rule or scratch_bytes moves, re-derive it or retire it.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROUND = os.path.join(HERE, "..", "wcomb-x86-2026-09-14")
BUDGET = 128 << 20
LOGS = {  # log -> (class, row gate, paired arena on)
    "coreultra9-gfni-validate-ab.log": ("GFNI-256 x86", 320, False),
    "i5-nibble-validate-ab.log": ("nibble x86", 256, True),
}


def scratch(n, w, paired):
    base = (17 * 257 + 5 * min(n, 4369) + 3 * min(n, 21845) + n) * w * 2
    return base + (max(257 * w * 2, 257 * 512 * 2) if paired else 0) + (1 << 9) * w * 2


def arenas(bs, n, w, paired):
    words = bs // 2
    w = min(w, max(words, 16))
    return scratch(n, w, paired) * min(4, -(-words // w))


def ask(bs, corpus, gate, k):
    s = corpus // bs
    if s < 320 or s <= k:
        return None
    return gate + gate * k // (s - k)


def decide(m, bs, gate, k, paired, new_rule):
    """The width admitted at (512 = the default), or None for the fold."""
    corpus = lambda w: BUDGET - arenas(bs, m, w, paired)
    w = 512
    while w > 32 and arenas(bs, m, w, paired) > corpus(w):
        w //= 2
    while True:
        a = ask(bs, corpus(w), gate, k)
        if a is not None and m >= a:
            return w
        if w <= 32 or (new_rule and a is not None):
            return None
        w //= 2


def main():
    bad = 0
    for log, (cls, gate, paired) in LOGS.items():
        print("== %s (%s)" % (cls, log))
        seen = {}
        for line in open(os.path.join(ROUND, log), encoding="utf-8", errors="replace"):
            if not line.startswith("LEG "):
                continue
            kv = dict(t.split("=", 1) for t in line.split() if "=" in t)
            if kv["budget"] != "128" or kv["arm"] not in ("auto", "autoalt"):
                continue
            key = (int(kv["m"]), kv["arm"])
            got = None if kv["path"] == "fold" else int(kv["ntt_w"])
            seen.setdefault(key, (int(kv["slab_width"]), got))
        for m in sorted({k[0] for k in seen}):
            row = []
            for arm, k in (("auto", 312), ("autoalt", 702)):
                bs, rec = seen[(m, arm)]
                mir = decide(m, bs, gate, k, paired, new_rule=False)
                ok = mir == rec
                bad += not ok
                row.append("%s k=%d recorded %s mirror %s%s" % (arm, k, rec, mir, "" if ok else "  MISMATCH"))
            bs = seen[(m, "auto")][0]
            row.append("NEW rule k=312 -> %s" % decide(m, bs, gate, 312, paired, new_rule=True))
            print("  m=%-5d %s" % (m, " | ".join(row)))
    print("\n== the band: rows the OLD rule narrowed a row-refused window for (no slab, 64 KiB)")
    for cls, gate, paired, k in (("GFNI-256 x86", 320, False, 312), ("nibble x86", 256, True, 312), ("NEON", 192, True, 163)):
        band = [(m, decide(m, 65536, gate, k, paired, False)) for m in range(gate, 1024)
                if decide(m, 65536, gate, k, paired, True) is None and decide(m, 65536, gate, k, paired, False)]
        if band:
            print("  %-13s m = %d..%d, widths %s" % (cls, band[0][0], band[-1][0], sorted({w for _, w in band}, reverse=True)))
    print("\n%d recorded decision(s) not reproduced" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
