# plan_solve replica with the ARM predicate: in place (1 buffer) only when the joint
# Forney arm runs, i.e. m >= backsub_min_missing (704 NEON; 1,280 x86 GFNI classes).
# Dense below the gate pays 4*m^2 off the top (dense_matrix_bytes) under both settings.
import math
def ru_even(n): return n + (n & 1)
def plan_slabs(m, bs, budget, buffers, gate):
    if m == 0 or bs == 0: return (1, max(bs, 2))
    fixed = 0 if m >= gate else 4*m*m
    sp = max(budget - fixed, 0)
    widest = max(min(sp // max(buffers*m, 1), bs) & ~1, 2)
    slabs = max(math.ceil(bs / widest), 1)
    while True:
        w = ru_even(math.ceil(bs / slabs))
        if w*buffers*m <= sp or w <= 2: break
        slabs += 1
    return (math.ceil(bs / w), w)
def plan_solve(m, bs, budget, buffers, gate):
    whole = plan_slabs(m, bs, budget, buffers, gate)
    if whole[0] == 1: return whole, "Whole"
    left = budget - m*bs
    if left > 0:
        a = plan_slabs(m, bs, left, buffers, gate)
        if a[0] <= whole[0]: return a, "Assembled"
    return whole, "Spill"
MiB = 1 << 20
for gate, cls in ((704, "NEON (joint default on)"), (1280, "x86 GFNI-256 / AVX-512 GFNI (joint default on)")):
    for bs, label, ms in ((65536, "64 KiB", (512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 16384)),
                          (1 << 20, "1 MiB", (128, 256, 512, 704, 1024, 1280, 2048))):
        print(f"\n### {cls}, {label} blocks, 128 MiB budget")
        print("| m | arm | whole: slabs / width / staging | in place: slabs / width / staging | sweeps saved |")
        print("|---:|---|---|---|---:|")
        for m in ms:
            b1 = 1 if m >= gate else 2
            (s2, w2), st2 = plan_solve(m, bs, 128*MiB, 2, gate)
            (s1, w1), st1 = plan_solve(m, bs, 128*MiB, b1, gate)
            arm = "joint" if m >= gate else "dense"
            print(f"| {m:,} | {arm} | {s2} / {w2:,} / {st2} | {s1} / {w1:,} / {st1} | {s2-s1} |")
