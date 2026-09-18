#!/usr/bin/env python3
"""reduce.py - ladder.py logs to markdown tables, with the extractor's
rules: medians over timed reps (rep != 0), legs gated on full restoration,
spread = (max-min)/median in %, one argv per tool."""
import sys, re, statistics
def kv(s):
    d = {}
    for m in re.finditer(r"(\w+)=('[^']*'|\S+)", s): d[m.group(1)] = m.group(2).strip("'")
    return d
def load(p):
    r = {"legs": [], "verify": [], "create": [], "cc": [], "box": "", "bins": []}
    for line in open(p, errors="replace"):
        tag, _, rest = line.rstrip("\n").partition(" ")
        if tag == "LEG": r["legs"].append(kv(rest))
        elif tag == "VERIFY": r["verify"].append(kv(rest))
        elif tag == "CREATE": r["create"].append(kv(rest))
        elif tag == "CC": r["cc"].append(kv(rest))
        elif tag == "BOX": r["box"] = rest
        elif tag == "BIN": r["bins"].append(rest)
    return r
def med(xs): return statistics.median(xs) if xs else None
def spread(xs): return (max(xs) - min(xs)) / med(xs) * 100 if len(xs) > 1 and med(xs) else None
def ok(f): 
    a, b = f.split("/"); return a == b
def fmt(v, sp=None):
    if v is None: return "-"
    s = f"{v:.2f}"
    return s + (f" ±{sp:.0f}%" if sp is not None and sp >= 5 else "")
for p in sys.argv[1:]:
    r = load(p); print(f"\n### {p}\n{r['box']}")
    for b in r["bins"]: print("  " + b[:120])
    if r["cc"]:
        arms = []
        for c in r["cc"]:
            if c["arm"] not in arms: arms.append(c["arm"])
        print("\n| size GiB | red % | blocks | " + " | ".join(arms) + " |"); print("|---:|---:|---:|" + "---|" * len(arms))
        keys = []
        for c in r["cc"]:
            k = (int(c["size"]), int(c["red"]), int(c["blocks"]))
            if k not in keys: keys.append(k)
        for (sz, rd, bl) in keys:
            cells = []
            for arm in arms:
                w = [float(c["wall"]) for c in r["cc"] if c["arm"]==arm and int(c["size"])==sz and int(c["red"])==rd and c["rc"]=="0"]
                cells.append(fmt(med(w), spread(w)))
            print(f"| {sz} | {rd} | {bl} | " + " | ".join(cells) + " |")
        continue
    tools = []
    for l in r["legs"]:
        if l["tool"] not in tools: tools.append(l["tool"])
    if r["create"]:
        print("\n| create | " + " | ".join(sorted({c['tool'] for c in r['create']})) + " |"); print("|---|" + "---|" * len({c['tool'] for c in r['create']}))
        print("| wall s | " + " | ".join(fmt(med([float(c['wall']) for c in r['create'] if c['tool']==t and c['rc']=='0'])) for t in sorted({c['tool'] for c in r['create']})) + " |")
    print("\n| verify | " + " | ".join(tools) + " |"); print("|---|" + "---|" * len(tools))
    print("| wall s | " + " | ".join(fmt(med([float(v['wall']) for v in r['verify'] if v['tool']==t and ok(v['intact'])]), spread([float(v['wall']) for v in r['verify'] if v['tool']==t and ok(v['intact'])])) for t in tools) + " |")
    ms = sorted({int(l["m"]) for l in r["legs"]})
    print("\n| blocks lost | " + " | ".join(tools) + " |"); print("|---:|" + "---|" * len(tools))
    for m in ms:
        cells = []
        for t in tools:
            w = [float(l["wall"]) for l in r["legs"] if l["tool"]==t and int(l["m"])==m and l["rep"]!="0" and ok(l["restored"])]
            cells.append(fmt(med(w), spread(w)))
        print(f"| {m} | " + " | ".join(cells) + " |")
    print(f"\nlegs={len(r['legs'])} not_restored={sum(1 for l in r['legs'] if not ok(l['restored']))}")
