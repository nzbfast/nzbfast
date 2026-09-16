#!/bin/zsh
# ab-env.sh - interleaved A/B over ONE smallart leg and ONE binary,
# where the arms differ by an ENVIRONMENT VARIABLE rather than by build.
#
# The sibling of ab-binaries.sh, and the right tool whenever an arm can
# be expressed as a runtime flag. Written 16 Sep 2026 for the per-member
# residue round (research/MANYSMALL-PER-MEMBER-RESIDUE-2026-09-16.md),
# which had to price one walk inside `Extractor::map_output_range` and
# did not want to pay two 12-minute release builds to do it.
#
# ONE BINARY IS A FEATURE, NOT A SHORTCUT: two builds of "the same" tree
# differ by inlining and layout, and on this fleet that has been worth
# more than the effect being measured. One binary removes that axis
# entirely. The cost is that the arm's branch is compiled INTO the hot
# path, so it must be a single predictable test - and the flag must be
# read ONCE (a `OnceLock`, not an `env::var` per call), or the getenv
# lands on the arm you are calling the baseline.
#
#   R=<rigdir> NZBIN=<nzbfast> NZBSERVE=<nzbserve> VAR=<NAME>
#   [SHAPE=manysmall] [ART=700000] [ROUNDS=5] [PORT=24391] ./ab-env.sh
#
# Arm A is VAR unset, arm B is VAR=1. Round-robin within each round,
# never a block of one arm then the other - load on this fleet drifts by
# more than most effects, and a block design charges the drift to
# whichever arm ran during it.
#
# Take MEDIANS of at least 5 rounds and print each arm's own spread: an
# effect smaller than that spread has not been measured. And ALWAYS run
# the same pair over a NULL-CONTROL shape the flag cannot reach
# (`onebig` for anything per-member) - without it a difference reads as
# real whether or not the harness invented it.
#
# The `out=` count is the artefact pin (see sample-decode.sh's header for
# what a leg that quietly fetched nothing looks like), and this writes
# its OWN config for the same reason.
set -u
R=${R:?}; NZBIN=${NZBIN:?}; NZBSERVE=${NZBSERVE:?}; VAR=${VAR:?}
PORT=${PORT:-24391}; ART=${ART:-700000}; SHAPE=${SHAPE:-manysmall}; ROUNDS=${ROUNDS:-5}
L=$R/work/leg-$SHAPE-$ART
[ -d $L ] || { echo "no leg at $L - run smallart.sh first"; exit 2; }
nzb=$(ls $L/*.nzb | head -1)
mkdir -p $R/work
echo '{"servers":[{"host":"127.0.0.1","port":'$PORT',"tls":false,"connections":16}]}' > $R/work/cfg-abenv.json
case $SHAPE in
  onebig) WANT=1 ;; ms2m) WANT=512 ;; manysmall) WANT=2048 ;; ms128k) WANT=8192 ;; *) WANT=0 ;;
esac
# By port, never by pattern (CLAUDE.md invariant 2).
p=$(lsof -ti :$PORT -sTCP:LISTEN); [ -n "$p" ] && { kill $p; sleep 0.7; }
$NZBSERVE serve $L --port $PORT --article-size $ART > $L/serve-abenv.log 2>&1 & SRV=$!
for i in $(seq 1 120); do grep -q "NNTP ready" $L/serve-abenv.log 2>/dev/null && break; sleep 0.25; done
grep -q "NNTP ready" $L/serve-abenv.log || { echo "server never came up - refusing to measure"; kill $SRV; exit 3; }
for i in $(seq 1 $ROUNDS); do
  for arm in A B; do
    rm -rf $R/work/out-abenv; mkdir -p $R/work/out-abenv
    if [ $arm = A ]; then unset $VAR; else export $VAR=1; fi
    NZBFAST_NO_ENRICH=1 NZBFAST_LINE_CAP=0 /usr/bin/time -l $NZBIN get $nzb \
      --config $R/work/cfg-abenv.json --out $R/work/out-abenv \
      --connections 16 --window 4 --decoders 8 > $R/work/abenv.log 2>&1
    ins=$(grep "instructions retired" $R/work/abenv.log | awk '{print $1}')
    nf=$(find $R/work/out-abenv -type f | wc -l | tr -d ' ')
    ld=$(uptime | sed 's/.*averages*: //' | awk '{print $1}')
    echo "ABENV $SHAPE art=$ART r$i $arm instr=$ins out=${nf}f/want=$WANT load=$ld"
    [ $WANT -ne 0 ] && [ "$nf" != "$WANT" ] && echo "  ^^ REFUSE: that leg did not run"
  done
done
unset $VAR
kill $SRV 2>/dev/null; sleep 0.5; rm -rf $R/work/out-abenv $R/work/cfg-abenv.json
