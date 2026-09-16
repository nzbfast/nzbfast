#!/bin/zsh
# shape-ladder.sh - the MEMBER-COUNT ladder, round-robin across shapes.
#
# Written 16 Sep 2026 for the per-member residue chip
# (research/MANYSMALL-PER-MEMBER-RESIDUE-2026-09-16.md). Its parent,
# research/PENDING-R-RESIDUE-2026-09-16.md, closed `pending_r` as the
# cause of the many-member penalty and left the penalty itself unpriced:
# a 1 GiB stored set cut into 2,048 members costs 3.45x the instructions
# per byte of the same 1 GiB as one member, and nobody had separated the
# PER-MEMBER constant from anything superlinear.
#
# That separation is a ladder over member count at FIXED bytes and FIXED
# article size - onebig(1) / ms2m(512) / manysmall(2048) / ms128k(8192),
# all 1 GiB - so a straight line through it reads off as instructions
# per member, and curvature reads as a term that is not per-member.
#
# WHY THIS EXISTS BESIDE ab-binaries.sh RATHER THAN INSIDE IT.
# ab-binaries.sh round-robins ARMS over ONE leg: one shape, one server,
# several binaries. This round-robins SHAPES over ONE binary, which is
# the other axis and needs every shape's server up at once. smallart.sh
# covers the same shapes but BLOCKS - all reps of one shape, then the
# next - and on this fleet load drifts by more than the effect between
# two rungs, so a block design charges the drift to whichever rung ran
# during it. Measured 16 Sep: the one-minute load average spanned 100 to
# 240 on 18 cores inside a single ladder run.
#
#   R=<rigdir> NZBIN=<nzbfast> NZBSERVE=<nzbserve>
#   [SHAPES="onebig ms2m manysmall ms128k"] [ART=700000] [ROUNDS=4]
#   [PORT0=24400] [TAG=lad] [WARM=25] ./shape-ladder.sh
#
# ONE SERVER PER SHAPE, ON ITS OWN PORT, ALL UP FOR THE WHOLE RUN. A
# restart between rungs would put a 2 s sleep and a cold accept path
# inside the interleave, and the rungs are already only ~1 minute apart.
# Ports are PORT0, PORT0+1, ... in $SHAPES order, and every kill here is
# BY PORT, never by pattern (CLAUDE.md invariant 2 - a `pkill nzbserve`
# takes another lane's rig with it and a PreToolUse hook refuses it).
#
# The legs must already exist; smallart.sh builds them, and it must be
# run at the SAME ART or the NZB names articles the server never made.
#
# WAIT FOR EVERY SERVER TO PRINT `NNTP ready`, AND DO NOT REPLACE THAT
# WAIT WITH A SLEEP. smallart.sh's `sleep 2` is enough for the one
# server it starts; four at once, each indexing a 1 GiB leg, are not -
# and at 100 KB articles a leg is 10,753 articles to index, not 1,537.
# A leg whose server is not listening yet does not fail: the pool logs
# `connect failed: Connection refused`, retries, and the run completes
# with a perfectly good-looking instruction count that includes a
# startup stall. That is the absent-fault shape exactly (memory topic
# nzbfast-absent-fault-passes-every-outcome-check) - it cost this rig
# its first 100 KB rung on 16 Sep 2026, and the only reason it was
# caught is that the leg's own log was read rather than its number.
# WARM is the ceiling on that wait in seconds, not the wait itself.
#
# Only `instr` is a product number on a loaded box. The file count is
# printed on every line and is the artefact pin: a rung that fails to
# reproduce (wrong member count) measures nothing while passing every
# end-state check - see memory topic
# nzbfast-absent-fault-passes-every-outcome-check.
set -u
R=${R:?}; NZBIN=${NZBIN:?}; NZBSERVE=${NZBSERVE:?}
SHAPES=${SHAPES:-"onebig ms2m manysmall ms128k"}
ART=${ART:-700000}; ROUNDS=${ROUNDS:-4}; PORT0=${PORT0:-24400}; TAG=${TAG:-lad}
WARM=${WARM:-25}
typeset -A PORTOF
i=0
for shape in ${=SHAPES}; do
  L=$R/work/leg-$shape-$ART
  [ -d $L ] || { echo "no leg at $L - run smallart.sh first"; exit 2; }
  port=$((PORT0 + i)); PORTOF[$shape]=$port; i=$((i + 1))
  p=$(lsof -ti :$port -sTCP:LISTEN); [ -n "$p" ] && { kill $p; sleep 0.5; }
  $NZBSERVE serve $L --port $port --article-size $ART > $L/serve-lad.log 2>&1 &
  echo '{"servers":[{"host":"127.0.0.1","port":'$port',"tls":false,"connections":16}]}' > $R/work/cfg-$shape.json
done
# Readiness, not a sleep - see the header.
for shape in ${=SHAPES}; do
  ok=0
  for i in $(seq 1 $((WARM * 4))); do
    grep -q "NNTP ready" $R/work/leg-$shape-$ART/serve-lad.log 2>/dev/null && { ok=1; break; }
    sleep 0.25
  done
  [ $ok -eq 1 ] || { echo "SERVER NOT READY for $shape after ${WARM}s - refusing to measure"; exit 3; }
done
for r in $(seq 1 $ROUNDS); do
  for shape in ${=SHAPES}; do
    L=$R/work/leg-$shape-$ART
    nzb=$(ls $L/*.nzb | head -1)
    rm -rf $R/work/out-lad; mkdir -p $R/work/out-lad
    NZBFAST_NO_ENRICH=1 NZBFAST_LINE_CAP=0 /usr/bin/time -l $NZBIN get $nzb \
      --config $R/work/cfg-$shape.json --out $R/work/out-lad \
      --connections 16 --window 4 --decoders 8 > $R/work/lad.log 2>&1
    ins=$(grep "instructions retired" $R/work/lad.log | awk '{print $1}')
    real=$(grep -E "^ *[0-9.]+ real" $R/work/lad.log | tail -1 | awk '{print $1}')
    nf=$(find $R/work/out-lad -type f | wc -l | tr -d ' ')
    kb=$(du -sk $R/work/out-lad | awk '{print $1}')
    ld=$(uptime | sed 's/.*averages*: //' | awk '{print $1}')
    echo "LAD $TAG $shape art=$ART r$r instr=$ins real=$real out=${nf}f/${kb}k load=$ld"
  done
done
for shape in ${=SHAPES}; do
  p=$(lsof -ti :${PORTOF[$shape]} -sTCP:LISTEN); [ -n "$p" ] && kill $p
done
sleep 0.5; rm -rf $R/work/out-lad
