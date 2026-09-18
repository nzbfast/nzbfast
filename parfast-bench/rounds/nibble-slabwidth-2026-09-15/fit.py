# fit NTT_s = c1 + c0/n over W=256 NTT cells (no fold), per (m, t); check held-out cells
import json, re, statistics
from collections import defaultdict
rows=[json.loads(l) for l in open("round.jsonl")]
cells=defaultdict(list)
for r in rows:
    err=open("legs/m%d-auto-%s-r%d.err"%(r["m"],r["arm"],r["rep"]),errors="replace").read()
    nt=[(int(n),int(w),float(v)*{"ms":1e-3,"s":1,"µs":1e-6}[u]) for n,w,v,u in re.findall(r"ntt syndromes \(m=\d+, needed=\d+, n=(\d+), W=(\d+), threads=\d+\): ([0-9.]+)(µs|ms|s)",err)]
    if not nt: continue
    full=max(x[0] for x in nt); W=nt[0][1]
    t=1 if r["arm"].endswith("-t1") else 4
    cells[(r["m"],t,r["arm"],r["slab_width"],full,W)].append(sum(x[2] for x in nt))
med={k:statistics.median(v) for k,v in cells.items()}
for m in (2048,4096):
  for t in (4,1):
    pts=[(k[4],v,k) for k,v in med.items() if k[0]==m and k[1]==t and k[5]==256]
    if len(pts)<2: continue
    lo=min(pts); hi=max(pts)
    c0=(lo[1]-hi[1])/(1/lo[0]-1/hi[0]); c1=hi[1]-c0/hi[0]
    print("m=%d t=%d W=256 fit on n=%d,%d: c1=%.2f s  c0=%.0f  (c0/m=%.2f)"%(m,t,lo[0],hi[0],c1,c0,c0/m))
    for k,v in sorted(med.items()):
        if k[0]==m and k[1]==t:
            p=c1+c0/k[4]
            print("   %-22s width %5d n %5d W %3d  NTT %6.2f  model(W256) %6.2f  %+5.0f%%"%(k[2],k[3],k[4],k[5],v,p,100*(v/p-1)))
