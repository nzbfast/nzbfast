#!/bin/zsh
# par2verify.sh - the shape that reaches the LIVE PAR2 VERIFIER, and the
# A/B that prices its block hashing.
#
# WHY THIS EXISTS. Every download rig in this tree posts BARE STORED RAR5
# VOLUMES WITH NO PAR2 SET (`smallart.sh` and the shapes under
# `~/smallart/mkshapes.sh`), so `LiveVerifier` never activates a recovery
# set and its block-checksum path is never entered. Round 26 was chipped
# with "the verifier re-CRCs every PAR2 block the pcrc32 already vouched
# for" as one of three suspects and had to report it UNTESTED for exactly
# that reason. This rig is the missing shape: the same stored RAR5
# volumes WITH a real PAR2 set posted beside them.
#
# PROVE THE PATH BEFORE READING A NUMBER. A leg is only a measurement if
# the run's `[verify]` line reports blocks verified in-stream AND the
# `[crc-geometry]` line exists at all (it is silent on a job that mapped
# no spans). This script refuses a leg that produces neither, because a
# rig that misses the path publishes numbers about nothing - which is how
# this item survived a whole lane once already.
#
# Shape recipe (any box with `rar` and `par2`), 1 GiB stored + 5% recovery:
#
#   mkdir -p $R/shapes/par1g && cd $R/shapes/par1g
#   rar a -m0 -v50m -ep -idq m.rar /path/to/rand.bin        # 21 volumes
#   par2 create -q -s768000 -r5 -n8 m.par2 m.part*.rar      # 9 par2 files
#
# The block size and the article size are chosen INDEPENDENTLY here on
# purpose - that is how real posts are made, and the straddle geometry is
# what the reuse has to cope with. Aligning them would flatter the arm.
#
# Layout expected under $R:  shapes/<name>/*   (work/ is created)
#
#   R=<rigdir> NZBIN=<nzbfast> NZBSERVE=<nzbserve> [ARTS=..] [SHAPES=..]
#   [REPS=3] [PORT=24393] [TAG=run] ./par2verify.sh
#
# ARTICLE SIZE IS PART OF THE LAYOUT: `build` and `serve` are both given
# --article-size, or the ids in the NZB name articles the server never
# made (same trap as smallart.sh).
#
# The arms are ONE binary: `NZBFAST_NO_CRC_REUSE=1` is the pre-2 Sep
# behaviour (every needed piece hashed from the bytes) and unset is the
# shipped reuse. Legs alternate arm by arm, never all of one then all of
# the other. On a loaded box read `instr` only; `real` is the box's load.
set -u
R=${R:-$(cd $(dirname $0) && pwd)}
NZBIN=${NZBIN:?set NZBIN}
NZBSERVE=${NZBSERVE:?set NZBSERVE}
PORT=${PORT:-24393}
REPS=${REPS:-3}
ARTS=${ARTS:-"700000"}
SHAPES=${SHAPES:-"par1g"}
TAG=${TAG:-run}
mkdir -p $R/work
CFG=$R/work/cfg.json
echo '{"servers":[{"host":"127.0.0.1","port":'$PORT',"tls":false,"connections":16}]}' > $CFG
# Round 27's rig defect: a silently-failed redirect leaves --config
# naming a file that does not exist, and Config::load then adopts
# SABnzbd's server list and dials a REAL provider. Refuse to run.
[ -s $CFG ] || { echo "FATAL: config not written"; exit 1; }

for shape in ${=SHAPES}; do
  for art in ${=ARTS}; do
    L=$R/work/leg-$shape-$art
    if [ ! -f $L/build.log ]; then
      rm -rf $L; mkdir -p $L/post
      cp -c $R/shapes/$shape/* $L/post/ 2>/dev/null || cp $R/shapes/$shape/* $L/post/
      $NZBSERVE build $L --article-size $art > $L/build.log 2>&1 || {
        echo "BUILD FAIL $shape $art"; tail -3 $L/build.log; continue; }
    fi
    nzb=$(ls $L/*.nzb | head -1)
    # By port, never by pattern (CLAUDE.md invariant 2).
    p=$(lsof -ti :$PORT -sTCP:LISTEN); [ -n "$p" ] && { kill $p; sleep 0.7; }
    $NZBSERVE serve $L --port $PORT --article-size $art > $L/serve.log 2>&1 & SRV=$!
    sleep 2
    nart=$(awk '{for(i=1;i<=NF;i++) if($i=="articles") print $(i-1)}' $L/build.log | head -1)
    for r in $(seq 1 $REPS); do
      for arm in reuse noreuse; do
        rm -rf $R/work/out; mkdir -p $R/work/out
        [ $arm = noreuse ] && export NZBFAST_NO_CRC_REUSE=1 || unset NZBFAST_NO_CRC_REUSE
        NZBFAST_NO_ENRICH=1 NZBFAST_LINE_CAP=0 /usr/bin/time -l $NZBIN get $nzb \
          --config $CFG --out $R/work/out \
          --connections 16 --window 4 --decoders 8 > $R/work/get.log 2>&1
        # THE PATH GATE. `[verify] verified N file(s): B blocks in-stream`
        # is the verifier saying it activated a set and claimed blocks
        # live; `[crc-geometry]` only prints for a job that mapped spans.
        vline=$(grep -h "verified .* file(s)" $R/work/get.log | tail -1)
        gline=$(grep -h "crc-geometry\|spared" $R/work/get.log | tail -1)
        blocks=$(echo $vline | sed -n 's/.*: \([0-9][0-9]*\) blocks in-stream.*/\1/p')
        if [ -z "${blocks:-}" ] || [ "${blocks:-0}" -eq 0 ] || [ -z "$gline" ]; then
          echo "RIG-FAIL $shape art=$art $arm - verifier PAR2 path not reached"
          echo "  verify: ${vline:-<none>}"
          echo "  geom:   ${gline:-<none>}"
          cp $R/work/get.log $L/fail-$arm.log
          kill $SRV 2>/dev/null; exit 2
        fi
        line=$(grep -E "^ *[0-9.]+ real" $R/work/get.log | tail -1)
        real=$(echo $line | awk '{print $1}')
        usr=$(echo $line | awk '{print $3}')
        sys=$(echo $line | awk '{print $5}')
        ins=$(grep "instructions retired" $R/work/get.log | awk '{print $1}')
        cyc=$(grep "cycles elapsed" $R/work/get.log | awk '{print $1}')
        rss=$(grep "peak memory footprint" $R/work/get.log | awk '{print $1}')
        nf=$(find $R/work/out -type f | wc -l | tr -d " ")
        kb=$(du -sk $R/work/out | awk '{print $1}')
        spared=$(echo $gline | sed -n 's/.*spared \([0-9.]*\) GB.*/\1/p')
        echo "LEG $TAG $shape art=$art n=$nart $arm r$r real=$real user=$usr sys=$sys instr=$ins cycles=$cyc rss=$rss blocks=$blocks spared=${spared:-0}GB out=${nf}f/${kb}k"
      done
    done
    kill $SRV 2>/dev/null; sleep 0.7
  done
done
unset NZBFAST_NO_CRC_REUSE
rm -rf $R/work/out
echo "RIG-DONE $TAG"
