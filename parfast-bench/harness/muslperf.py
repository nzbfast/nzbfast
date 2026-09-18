#!/usr/bin/env python3
"""muslperf.py <perf.jsonl> <cell> - claim parfast-musl-allocator-speed-15sep. - bucket the three arms' profiles for one cell
by the symbol names the binaries actually carry, and weight each bucket by that
leg's own CPU-seconds so the arms are comparable in absolute terms.

musl static: allocator is `c.malloc.*` (mallocng), memset/memcpy are
`compiler_rt.*`. glibc: allocator and mem ops are unnamed offsets inside
`libc.so.6` (stripped system library), so that whole DSO is one bucket.
mimalloc: `mi_*` / `_mi_*`, with the same compiler_rt mem ops as musl.
"""
import json, os, re, sys
from collections import defaultdict

PERF, CELL = sys.argv[1], sys.argv[2]
D = os.path.dirname(os.path.abspath(PERF))
cpu = {}
for line in open(PERF):
    r = json.loads(line)
    if r["cell"] == CELL:
        cpu[r["arm"]] = (r["cpu"], r["utime"], r["stime"], r["minflt"], r["wall"])

ALLOC = re.compile(r"^(c\.malloc\.|mi_|_mi_|malloc|free|calloc|realloc|__rust_(a|de|re)alloc)")
MEMOPS = re.compile(r"^(compiler_rt\.(memset|memcpy|memmove|memcmp)|__?mem(set|cpy|move|cmp))")
KFAULT = re.compile(r"(clear_page|page_fault|handle_mm_fault|__alloc_pages|get_page_from_freelist|"
                    r"folio|rmqueue|free_unref|zap_|unmap_|vma_|madvise|lru_|memcg|page_counter|"
                    r"tlb|pte_|mmap|munmap|mt_find|down_read|up_read|rwsem)")


def buckets(path, arm):
    b = defaultdict(float)
    top = defaultdict(list)
    for line in open(path, errors="replace"):
        m = re.match(r"\s*([\d.]+)%\s+(\S+)\s+\[([.k])\]\s+(.*)$", line)
        if not m:
            continue
        pct, dso, kind, sym = float(m.group(1)), m.group(2), m.group(3), m.group(4).strip()
        if kind == "k":
            key = "kfault" if KFAULT.search(sym) else "kother"
        elif dso == "libc.so.6":
            key = "libc(glibc malloc+memops)"
        elif ALLOC.match(sym):
            key = "alloc"
        elif MEMOPS.match(sym):
            key = "memops"
        elif "gf16" in sym or "par2ntt" in sym or "par2repair" in sym or "md5" in sym or "crc32" in sym:
            key = "engine"
        else:
            key = "other"
        b[key] += pct
        top[key].append((pct, sym))
    return b, top


print("cell %s: bucket shares as %% of each profile, and x that leg's own CPU-seconds" % CELL)
print("%-10s %7s %-28s %-9s %-9s %-9s %-9s %-9s %-9s" % ("arm", "cpu_s", "engine", "alloc", "libc", "memops", "kfault", "kother", "other"))
abs_ = {}
for arm in ("musl_dbg", "glibc_dbg", "mim_dbg"):
    p = os.path.join(D, "perf", "%s-%s.perf.data.txt" % (CELL, arm))
    if not os.path.exists(p):
        continue
    b, top = buckets(p, arm)
    c = cpu.get(arm, (float("nan"),) * 5)[0]
    keys = ("engine", "alloc", "libc(glibc malloc+memops)", "memops", "kfault", "kother", "other")
    abs_[arm] = {k: b[k] / 100.0 * c for k in keys}
    print("%-10s %7.2f " % (arm, c) + " ".join("%5.1f%%/%4.1fs" % (b[k], abs_[arm][k]) for k in keys))
print("\nminor faults: " + ", ".join("%s %d" % (a, cpu[a][3]) for a in cpu))
print("cpu split u/s: " + ", ".join("%s %.1f/%.1f" % (a, cpu[a][1], cpu[a][2]) for a in cpu))
if "musl_dbg" in abs_ and "mim_dbg" in abs_:
    print("\nmusl -> mim, CPU-seconds by bucket (negative = mimalloc cheaper):")
    for k in abs_["musl_dbg"]:
        print("   %-28s %+6.2fs" % (k, abs_["mim_dbg"][k] - abs_["musl_dbg"][k]))
for a in ("musl_dbg", "glibc_dbg", "mim_dbg"):
    p = os.path.join(D, "perf", "%s-%s.perf.data.txt" % (CELL, a))
    if os.path.exists(p):
        b, top = buckets(p, a)
        for k in ("alloc", "libc(glibc malloc+memops)", "memops"):
            if top[k]:
                print("%-10s %-28s %s" % (a, k, ", ".join("%s %.2f" % (s[:34], pc) for pc, s in sorted(top[k], reverse=True)[:4])))
