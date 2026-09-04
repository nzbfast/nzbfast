#!/usr/bin/env bash
# par2-create-round.sh - what a PAR2 CREATE costs the rest of the box.
#
# Written 4 Sep 2026 for claim `par2-create-drop-at-settle`, the create
# twin of par2-cache-round.sh (which does the same job for verify and
# repair). The two share resident.c and the same method; they are
# separate scripts because a create needs a create driver, a second
# payload for the `chain` phase and a quiesce loop the verify round has
# no use for.
#
# THE POINT, and it is the same point the verify round makes: every PAR2
# leg in research/PAR2-PERF-AUDIT-2026-09-02.md timed the PAR2 process
# and none of them timed the machine around it. A 23 GB create pulls its
# whole payload through the page cache twice and leaves it there.
#
# WHAT THIS ROUND ALREADY ANSWERED, so a later lane does not re-run it
# expecting a different verdict: a give-back at the END of a create does
# NOT reduce the eviction the create inflicts. The reclaim happens while
# the create runs and the hook is later than the damage; measured 3/3,
# working-set survival identical to within 0.3%, and the arm cost 10.1%
# of the create's wall. The write-up is the create section of
# research/PAR2-TWO-LANES-COMPARED-2026-09-03.md. The round is kept
# because the SHAPE is reusable - it is how you measure any change to
# what a create leaves behind - not because the arm is open.
#
# ARMS ARE ONE BINARY. `NZBFAST_PAR2GEN_SETTLE` selected the policy at
# run time in the round above, so it could not fall into the trap that
# cost three separate lanes a day on 3 Sep 2026 - a "candidate" that was
# secretly the baseline (research/PAR2-RIGS-2026-09-02.md). MAIN CARRIES
# NO SUCH KNOB, because the arm was dropped, so `--arms 0` (the default)
# is the only arm a tree built from main has. Asking for another one is
# REFUSED rather than run, because an arm the binary does not understand
# reads as "no effect" and prints a column identical to the baseline,
# which is the exact shape of a false negative.
#
# Usage:
#   par2-create-round.sh --bin DIR --rig DIR [--rig2 DIR] [--ws FILE]
#                        [--out DIR] [--reps N] [--phase P[,P...]]
#                        [--arms "0 1 bg"] [--pct N] [--bs BYTES]
#
#   --bin    directory holding par2_create_bench
#            (cargo build --release -p nzbkit --example par2_create_bench)
#   --rig    directory holding the member(s); everything not *.par2 is one
#   --rig2   a DIFFERENT payload, for --phase chain
#   --ws     the unrelated working set file, for --phase evict
#   --arms   default "0", the shipped creator. Any other arm needs a
#            binary that carries NZBFAST_PAR2GEN_SETTLE, which main does
#            not - see the header.
#
# Phases:
#   solo   nothing else resident. The create's own wall, and how much of
#          the payload is left in the page cache when it ends.
#   evict  an 8 GiB unrelated working set is made resident FIRST, so the
#          headline is how many of ITS pages survive the create. THE
#          WORKING SET MUST BE BIG ENOUGH THAT PAYLOAD + SET EXCEEDS
#          USABLE PAGE CACHE, or the baseline arm simply fits and the
#          round measures nothing: on a 31 GB box a 23.4 GB member with
#          its 10% set is 25.7 GB of demand, so 8 GiB takes it to 33.7
#          and the baseline HAS to give some back.
#   chain  create, then create over --rig2. Arm 0 starts the second job
#          against a cache full of the first job's dead payload; a
#          give-back arm starts against a free one.
#   post   create, then read the payload back sequentially, timed.
#          `nzbfast post` builds the recovery set and then UPLOADS the
#          payload, so this is the cost side of any give-back and it is
#          not a hypothetical consumer.
#
# Dropping the cache needs root and Linux; without it this refuses
# rather than reporting a number it did not measure. ARM ORDER ROTATES
# between reps and the position is on every row. Record the load with
# every number: a leg taken above ~5 on 8 vCPU that is not the leg's own
# work is not a score.
#
# Output: CSV on stdout, the binary digest and refusals on stderr.
set -u

BIN=; RIG=; RIG2=; WS=; OUT=; REPS=3; PHASES=solo; ARMS="0"; PCT=10; BS=2097152
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN=$2; shift 2;;
    --rig) RIG=$2; shift 2;;
    --rig2) RIG2=$2; shift 2;;
    --ws) WS=$2; shift 2;;
    --out) OUT=$2; shift 2;;
    --reps) REPS=$2; shift 2;;
    --phase) PHASES=$(echo "$2" | tr ',' ' '); shift 2;;
    --arms) ARMS=$2; shift 2;;
    --pct) PCT=$2; shift 2;;
    --bs) BS=$2; shift 2;;
    -h|--help) sed -n '2,72p' "$0"; exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
[ -n "$BIN" ] && [ -n "$RIG" ] || { echo "need --bin and --rig" >&2; exit 2; }
for p in $PHASES; do
  case "$p" in
    solo) ;;
    evict) [ -n "$WS" ] || { echo "--phase evict needs --ws" >&2; exit 2; };;
    chain) [ -n "$RIG2" ] || { echo "--phase chain needs --rig2" >&2; exit 2; };;
    post) ;;
    *) echo "unknown --phase $p" >&2; exit 2;;
  esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
RES=$HERE/resident
if [ ! -x "$RES" ]; then
  cc -O2 -o "$RES" "$HERE/resident.c" || { echo "cannot build resident" >&2; exit 2; }
fi
CREATE=$BIN/par2_create_bench
[ -x "$CREATE" ] || { echo "no par2_create_bench in $BIN" >&2; exit 2; }
# The knob gate, and it is deliberately NOT unconditional. The shipped
# tree carries no give-back arm - it was measured and dropped, see the
# header - so a binary built from main today has no such string in it,
# and refusing on that would make this driver unrunnable on the very
# tree it lives in. What the gate must catch is the false negative: an
# arm the binary does not understand reads as "no effect" and prints a
# column identical to the baseline. So: arm 0 alone always runs, and any
# OTHER arm is refused unless the binary can actually take it.
if ! strings "$CREATE" 2>/dev/null | grep -q NZBFAST_PAR2GEN_SETTLE; then
  for a in $ARMS; do
    [ "$a" = 0 ] && continue
    echo "REFUSING: $CREATE carries no NZBFAST_PAR2GEN_SETTLE, so arm '$a' would silently \
run as arm 0. Use --arms 0 to measure what a create leaves behind, or build a tree that \
carries the arm." >&2
    exit 3
  done
  echo "# note: no NZBFAST_PAR2GEN_SETTLE in this binary; arm 0 is the only arm it has" >&2
fi
[ -w /proc/sys/vm/drop_caches ] || {
  echo "REFUSING: cannot drop the page cache here (needs root on Linux)" >&2; exit 3; }
OUT=${OUT:-$RIG/.createround-out}
mkdir -p "$OUT"
# The member the payload counts are taken over: the largest non-.par2
# file in the rig, which is the one the size floor admits. GNU `find
# -printf`, which is fine because everything below the /proc gate above
# is Linux-only by construction - this script cannot reach here on a
# machine that could not drop its own page cache.
MEMBER=$(find "$RIG" -maxdepth 1 -type f ! -name '*.par2' -printf '%s %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
[ -n "$MEMBER" ] || { echo "no member in $RIG" >&2; exit 2; }
echo "# binary $( (sha256sum "$CREATE" 2>/dev/null || shasum -a 256 "$CREATE") | cut -c1-16)" >&2
echo "# member $MEMBER" >&2

cached_kb() { awk '/^Cached:/{print $2; exit}' /proc/meminfo; }
loadnow()   { cut -d' ' -f1-3 /proc/loadavg | tr ' ' '/'; }
n1()        { "$RES" "$@" 2>/dev/null | awk '{r+=$1; t+=$2} END{printf "%d,%d", r+0, t+0}'; }

# A background arm is still freeing when create_into returns, which is
# the whole point of it. Wait for the count to stop moving before
# recording it, or the row measures the race and not the arm.
quiesce() {
  local a b i=0
  a=$(n1 "$MEMBER")
  while [ $i -lt 40 ]; do
    sleep 1
    b=$(n1 "$MEMBER")
    [ "$a" = "$b" ] && { echo "$a $i"; return; }
    a=$b; i=$((i + 1))
  done
  echo "$a $i"
}

echo "rep,pos,arm,phase,create_s,rc,quiesce_s,ws_res_before,ws_res_after,ws_tot,pay_res_after,pay_tot,vol_res_after,vol_tot,follow_s,follow_rc,cached_kb_before,cached_kb_after,setdigest,load"

leg() { # rep pos arm phase
  local rep=$1 pos=$2 arm=$3 ph=$4
  rm -f "$OUT"/*.par2
  [ -n "$RIG2" ] && rm -f "$RIG2"/.createround-out/*.par2 2>/dev/null
  sync; echo 3 > /proc/sys/vm/drop_caches
  local wsb=0 wsa=0 wst=0 w
  if [ "$ph" = evict ]; then
    # The working set goes in AFTER the drop and the payload stays out,
    # so the only thing that can evict these pages is the create.
    cat "$WS" > /dev/null
    w=$(n1 "$WS"); wsb=${w%,*}; wst=${w#*,}
  fi
  local cb t0 t1 rc
  cb=$(cached_kb)
  t0=$(date +%s.%N)
  env NZBFAST_PAR2GEN_SETTLE="$arm" "$CREATE" "$RIG" "$OUT" "$PCT" "$BS" > /dev/null 2>&1
  rc=$?
  t1=$(date +%s.%N)
  local q p qs
  q=$(quiesce); p=${q% *}; qs=${q##* }
  [ "$ph" = evict ] && { w=$(n1 "$WS"); wsa=${w%,*}; }
  local v; v=$(n1 "$OUT"/*.par2)
  local fs=NA frc=0 f0 f1
  if [ "$ph" = chain ] || [ "$ph" = post ]; then
    f0=$(date +%s.%N)
    if [ "$ph" = chain ]; then
      mkdir -p "$RIG2/.createround-out"
      env NZBFAST_PAR2GEN_SETTLE="$arm" "$CREATE" "$RIG2" "$RIG2/.createround-out" "$PCT" "$BS" \
        > /dev/null 2>&1
      frc=$?
    else
      cat "$MEMBER" > /dev/null; frc=$?
    fi
    f1=$(date +%s.%N)
    fs=$(awk -v a="$f0" -v b="$f1" 'BEGIN{printf "%.2f", b-a}')
  fi
  local wall dg
  wall=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
  # Identity gate LAST: hashing the set pulls its pages in, so it must
  # not run before any of the counts above.
  dg=$(cat "$OUT"/*.par2 2>/dev/null | (sha256sum 2>/dev/null || shasum -a 256) | cut -c1-16)
  echo "$rep,$pos,$arm,$ph,$wall,$rc,$qs,$wsb,$wsa,$wst,${p%,*},${p#*,},${v%,*},${v#*,},$fs,$frc,$cb,$(cached_kb),$dg,$(loadnow)"
}

for ph in $PHASES; do
  r=1
  while [ "$r" -le "$REPS" ]; do
    # Rotate the arm order every rep so no arm keeps a position.
    set -- $ARMS
    n=$#; k=$(((r - 1) % n)); i=0
    while [ $i -lt $k ]; do a=$1; shift; set -- "$@" "$a"; i=$((i + 1)); done
    pos=1
    for a in "$@"; do leg "$r" "$pos" "$a" "$ph"; pos=$((pos + 1)); done
    r=$((r + 1))
  done
done
