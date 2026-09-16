#!/bin/zsh
# ab-binaries.sh - interleaved A/B/... over ONE smallart leg, one
# binary per arm, reporting instructions retired.
#
# Written 16 Sep 2026 for the pending_r residue chip
# (research/PENDING-R-RESIDUE-2026-09-16.md), which needed to price a
# constant on a box at 5 to 10x oversubscription. Instructions retired
# are near-immune to that load (round 23 of
# research/RAR-PERF-AUDIT-2026-09-02.md ran at load 36 to 238 and
# reported only this column); wall from the same box is that box's load
# and is not a product number.
#
# ROUND-ROBIN, NEVER ALL OF ONE ARM THEN THE OTHER. Load on this fleet
# drifts by more than most effects being measured, so a block design
# charges the drift to whichever arm ran during it.
#
#   R=<rigdir> NZBSERVE=<nzbserve> ARMS="A B C" BINDIR=<dir>
#   [SHAPE=manysmall] [ART=700000] [ROUNDS=5] [PORT=24391] ./ab-binaries.sh
#
# Expects $BINDIR/nzbfast-<arm> per arm and a leg smallart.sh has built.
# Take MEDIANS of at least 5 rounds and report each arm's spread beside
# the difference: an effect smaller than one arm's own spread has not
# been measured, it has been guessed at. ALWAYS run a null-control leg
# (a shape the change cannot reach) through the same arms - 16 Sep, the
# onebig control correctly showed no ordering at all between three arms
# that differed by 57% on manysmall.
set -u
R=${R:?}; NZBSERVE=${NZBSERVE:?}; BINDIR=${BINDIR:?}
ARMS=${ARMS:-"A B"}
PORT=${PORT:-24391}; ART=${ART:-700000}; SHAPE=${SHAPE:-manysmall}; ROUNDS=${ROUNDS:-5}
L=$R/work/leg-$SHAPE-$ART
[ -d $L ] || { echo "no leg at $L - run smallart.sh first"; exit 2; }
nzb=$(ls $L/*.nzb | head -1)
p=$(lsof -ti :$PORT -sTCP:LISTEN); [ -n "$p" ] && { kill $p; sleep 0.7; }
$NZBSERVE serve $L --port $PORT --article-size $ART > $L/serve.log 2>&1 & SRV=$!
sleep 2
for i in $(seq 1 $ROUNDS); do
  for arm in ${=ARMS}; do
    bin=$BINDIR/nzbfast-$arm
    [ -x $bin ] || { echo "no binary for arm $arm at $bin"; continue; }
    rm -rf $R/work/out-ab; mkdir -p $R/work/out-ab
    NZBFAST_NO_ENRICH=1 NZBFAST_LINE_CAP=0 /usr/bin/time -l $bin get $nzb \
      --config $R/work/cfg.json --out $R/work/out-ab \
      --connections 16 --window 4 --decoders 8 > $R/work/ab.log 2>&1
    ins=$(grep "instructions retired" $R/work/ab.log | awk '{print $1}')
    nf=$(find $R/work/out-ab -type f | wc -l | tr -d ' ')
    echo "AB $SHAPE art=$ART r$i $arm $ins ${nf}f"
  done
done
kill $SRV 2>/dev/null; sleep 0.5; rm -rf $R/work/out-ab
