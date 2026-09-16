#!/bin/zsh
# sample-decode.sh - one smallart leg run under `sample`, so the decode
# threads' own wait profile can be read.
#
# Written 16 Sep 2026 for the pending_r residue chip
# (research/PENDING-R-RESIDUE-2026-09-16.md). smallart.sh reports
# instructions and wall; this reports WHERE the decode threads sit.
#
# TWO TRAPS, both paid for once already:
#
# 1. `/usr/bin/time -l` FORKS AND EXECS. `$!` is the time shim, not
#    nzbfast, and sampling it yields one thread and no engine frames at
#    all - a sample that looks valid and says nothing. This resolves the
#    child by ppid and samples THAT.
# 2. The release profile sets `strip = "symbols"`, so a stock release
#    binary symbolicates to `???` for every engine frame and atos cannot
#    help (302 symbols in the binary). Build the arm with
#    `CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=1`.
#    Measured 16 Sep: that build's instruction counts match the stripped
#    binary's within 1.6% on all four legs, so it is safe to use for the
#    instruction arms too.
#
#   R=<rigdir> NZBIN=<nzbfast> NZBSERVE=<nzbserve> [SHAPE=manysmall]
#   [ART=700000] [TAG=s] [DUR=30] [IVAL=1] [PORT=24391] ./sample-decode.sh
#
# The leg must already exist (smallart.sh builds it). Raw sample lands
# at $R/samples/sample-<TAG>.txt; read it with decode-sample-attr.py.
#
# IT WRITES ITS OWN `cfg.json` NOW, AND REFUSES A LEG THAT FETCHED
# NOTHING. Until 16 Sep 2026 it read `$R/work/cfg.json` and assumed
# smallart.sh had written it. A rig whose legs were built some other way
# (`nzbserve build` by hand, or shape-ladder.sh, which writes
# `cfg-<shape>.json`) therefore had no such file - and `nzbfast get`
# with no `--config` target falls back to THE OPERATOR'S REAL
# CONFIG. Four legs on 16 Sep went to the real upstream provider that
# config names, failed to log in, and reported 0.68 G instructions and
# one output file in 7 seconds. Every one of those numbers is well-formed
# and all four are pure fiction; only the `out=` count on the report
# line gave it away. The guard below is the cheap half (write the file,
# then check the run actually produced the shape's member count), and
# it is worth more than it looks: this is the absent-fault class
# (memory topic nzbfast-absent-fault-passes-every-outcome-check) with a
# live account on the other end of it.
#
# ALWAYS RUN A `onebig` LEG AS A CONTROL. A decode thread that is merely
# waiting for the next article is blocked in a mutex too, and on a loaded
# box that is most of the profile: measured 16 Sep, onebig - which parks
# no article and never enters flush_pending_r - still showed 85 to 87% of
# decode samples in __psynch_mutexwait. Without that control the same
# number reads as contention on whatever you happen to be looking at.
set -u
R=${R:?}; NZBIN=${NZBIN:?}; NZBSERVE=${NZBSERVE:?}
PORT=${PORT:-24391}; ART=${ART:-700000}; SHAPE=${SHAPE:-manysmall}; TAG=${TAG:-s}
DUR=${DUR:-30}; IVAL=${IVAL:-1}
OUT=${OUT:-$R/samples}; mkdir -p $OUT
L=$R/work/leg-$SHAPE-$ART
[ -d $L ] || { echo "no leg at $L - run smallart.sh first"; exit 2; }
# OUR OWN config, never an assumed one - see the header.
mkdir -p $R/work
echo '{"servers":[{"host":"127.0.0.1","port":'$PORT',"tls":false,"connections":16}]}' > $R/work/cfg-sample-$TAG.json
CFG=$R/work/cfg-sample-$TAG.json
# What this shape MUST produce, so a leg that fetched nothing is caught.
case $SHAPE in
  onebig) WANT=1 ;; ms2m) WANT=512 ;; manysmall) WANT=2048 ;; ms128k) WANT=8192 ;;
  *) WANT=0 ;;
esac
nzb=$(ls $L/*.nzb | head -1)
# By port, never by pattern (CLAUDE.md invariant 2).
p=$(lsof -ti :$PORT -sTCP:LISTEN); [ -n "$p" ] && { kill $p; sleep 0.7; }
$NZBSERVE serve $L --port $PORT --article-size $ART > $L/serve.log 2>&1 & SRV=$!
sleep 2
rm -rf $R/work/out-$TAG; mkdir -p $R/work/out-$TAG
NZBFAST_NO_ENRICH=1 NZBFAST_LINE_CAP=0 /usr/bin/time -l $NZBIN get $nzb \
  --config $CFG --out $R/work/out-$TAG \
  --connections 16 --window 4 --decoders 8 > $OUT/get-$TAG.log 2>&1 & GP=$!
KID=""
for i in $(seq 1 60); do
  KID=$(ps -A -o pid=,ppid= | awk -v p=$GP '$2==p {print $1; exit}')
  [ -n "$KID" ] && break
  sleep 0.05
done
[ -z "$KID" ] && { echo "WARN: could not resolve the exec'd child; sampling the time shim"; KID=$GP; }
sample $KID $DUR $IVAL -f $OUT/sample-$TAG.txt > /dev/null 2>&1
wait $GP
kill $SRV 2>/dev/null; sleep 0.5
GOT=$(find $R/work/out-$TAG -type f 2>/dev/null | wc -l | tr -d ' ')
echo "SAMPLED $TAG shape=$SHAPE art=$ART instr=$(grep 'instructions retired' $OUT/get-$TAG.log | awk '{print $1}') out=${GOT}f/want=${WANT} load=$(uptime | sed 's/.*averages: //')"
rm -rf $R/work/out-$TAG $CFG
if [ $WANT -ne 0 ] && [ "$GOT" != "$WANT" ]; then
  echo "REFUSING THIS SAMPLE: $SHAPE produced $GOT files, not $WANT - the leg did not run. See $OUT/get-$TAG.log"
  exit 4
fi
