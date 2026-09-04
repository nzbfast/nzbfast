#!/bin/zsh
# smallart.sh - the small-article / many-member regime rig.
#
# Every download rig in this tree before 3 Sep 2026 used ~700 KB
# articles over a handful of large members, which hides both the
# per-ARTICLE and the per-MEMBER cost of the one-pass path. This drives
# `nzbfast get` over a loopback nzbserve at several article sizes and
# several member counts on the SAME bytes, so the two costs separate.
# The findings it produced, and what the numbers mean, are in
# research/RAR-PERF-AUDIT-2026-09-02.md "Round 23".
#
# Shapes are built by hand beside it (all stored RAR5, all 1 GiB):
#   onebig     one 1 GiB member, -m0 -v50m
#   manysmall  2,048 x 512 KB members, -m0 -v20m
#   ms2m       512 x 2 MB      "
#   ms128k     8,192 x 128 KB  "
# A member payload is `split -b <size> -a 4 -d rand.bin f` into its own
# directory; the shape is `rar a -m0 -v20m -ep -idq <shape>/m.rar .`
# from inside it.
#
# Layout expected under $R:  shapes/<name>/*.rar   (work/ is created)
#
#   R=<rigdir> NZBIN=<nzbfast> NZBSERVE=<nzbserve> [ARTS=..] [SHAPES=..]
#   [REPS=3] [PORT=24391] [TAG=run] ./smallart.sh
#
# ARTICLE SIZE IS PART OF THE LAYOUT: nzbserve's `build` and `serve`
# are both given --article-size, or the ids in the NZB name articles
# the server never made.
#
# A/B by invoking it once per arm per pair, alternating - never all of
# one arm then all of the other. On a loaded box only `instr` is worth
# reading; `real` is that box's load and not the product's.
set -u
R=${R:-$(cd $(dirname $0) && pwd)}
NZBIN=${NZBIN:?set NZBIN}
NZBSERVE=${NZBSERVE:?set NZBSERVE}
PORT=${PORT:-24391}
REPS=${REPS:-3}
ARTS=${ARTS:-"700000 100000"}
SHAPES=${SHAPES:-"onebig manysmall"}
TAG=${TAG:-run}
mkdir -p $R/work
echo '{"servers":[{"host":"127.0.0.1","port":'$PORT',"tls":false,"connections":16}]}' > $R/work/cfg.json
for shape in ${=SHAPES}; do
  for art in ${=ARTS}; do
    L=$R/work/leg-$shape-$art
    # Legs are kept between invocations: rebuilding one costs a copy of
    # the whole shape and the NZB is deterministic anyway.
    if [ ! -f $L/build.log ]; then
      rm -rf $L; mkdir -p $L/post
      cp -c $R/shapes/$shape/* $L/post/ 2>/dev/null || cp $R/shapes/$shape/* $L/post/
      $NZBSERVE build $L --article-size $art > $L/build.log 2>&1 || { echo "BUILD FAIL $shape $art"; tail -3 $L/build.log; continue; }
    fi
    nzb=$(ls $L/*.nzb | head -1)
    # By port, never by pattern (CLAUDE.md invariant 2).
    p=$(lsof -ti :$PORT -sTCP:LISTEN); [ -n "$p" ] && { kill $p; sleep 0.7; }
    $NZBSERVE serve $L --port $PORT --article-size $art > $L/serve.log 2>&1 & SRV=$!
    sleep 2
    nart=$(awk '{for(i=1;i<=NF;i++) if($i=="articles") print $(i-1)}' $L/build.log | head -1)
    for r in $(seq 1 $REPS); do
      rm -rf $R/work/out; mkdir -p $R/work/out
      NZBFAST_NO_ENRICH=1 NZBFAST_LINE_CAP=0 /usr/bin/time -l $NZBIN get $nzb \
        --config $R/work/cfg.json --out $R/work/out \
        --connections 16 --window 4 --decoders 8 > $R/work/get.log 2>&1
      line=$(grep -E "^ *[0-9.]+ real" $R/work/get.log | tail -1)
      real=$(echo $line | awk '{print $1}')
      usr=$(echo $line | awk '{print $3}')
      sys=$(echo $line | awk '{print $5}')
      ins=$(grep "instructions retired" $R/work/get.log | awk '{print $1}')
      cyc=$(grep "cycles elapsed" $R/work/get.log | awk '{print $1}')
      rss=$(grep "peak memory footprint" $R/work/get.log | awk '{print $1}')
      nf=$(find $R/work/out -type f | wc -l | tr -d " ")
      kb=$(du -sk $R/work/out | awk '{print $1}')
      echo "LEG $TAG $shape art=$art n=$nart r$r real=$real user=$usr sys=$sys instr=$ins cycles=$cyc rss=$rss out=${nf}f/${kb}k"
    done
    kill $SRV 2>/dev/null; sleep 0.7
  done
done
rm -rf $R/work/out
echo "RIG-DONE $TAG"
