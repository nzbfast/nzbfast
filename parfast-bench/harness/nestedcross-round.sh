#!/bin/sh
# nestedcross-round.sh - the WHOLE line-rate crossover ladder, with the load
# rule enforced rather than remembered. Claim
# `nested-stage2-line-rate-crossover-quiet-21sep`.
#
#   nestedcross-round.sh [first-port]
#
# WHY A WRAPPER AT ALL, when `nestedcross.sh` already takes a leg. Because
# the measurement this round exists for is the one a loaded box CANNOT
# supply (an internal note section 6.3), and the
# rule that protects it is a judgement a human or an agent makes between
# legs and forgets under time pressure. Here it is a gate:
#
#   * `NXC_MAXLOAD` (default 40 on a 32-core box) is a ceiling on load1;
#   * and load1 must be BELOW load15, which is CLAUDE.md's armv7 rule -
#     load1 >> load15 is a RISING queue, the case that looks safe and is
#     not, and load1 << load15 is a DRAINED one, which is the window.
#
# A leg whose gate fails is SKIPPED and says so, and the round goes on to
# poll again rather than ending: a window that closes mid-ladder should cost
# the legs it closed over, not the round.
#
# THE LADDER. The margin is held FIXED at the rung 6.2 found most sensitive
# (64M, 30-32 passes) and the LINE RATE is walked, because the crossover is
# a property of the line/decode ratio and 6.2 already walked the margin. The
# off-arm controls are taken at the ends and the middle, not at every rung:
# the arm-off leg does not depend on the margin at all, so its only job is
# to give each rung its `dpeak` and `holdspk` baseline, and three of them
# bracket the axis.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
PORT0=${1:-11940}
MAXLOAD=${NXC_MAXLOAD:-40}
MARGIN=${NXC_MARGIN:-64M}
RATES=${NXC_RATES:-"0 400 200 100 50 20"}
OFFRATES=${NXC_OFFRATES:-"0 100 20"}
POLL=${NXC_POLL:-120}
TRIES=${NXC_TRIES:-30}

HLIB=${HLIB:-$HERE/hlib.sh}
if [ -f "$HLIB" ]; then . "$HLIB"; harness_lines "$0" "$HLIB" "$HERE/nestedcross.sh"
else echo "HARNESS-UNAVAILABLE $HLIB"; fi

echo "ROUND nestedcross margin=$MARGIN rates='$RATES' offrates='$OFFRATES' maxload=$MAXLOAD"

load1()  { uptime | sed -n 's/.*load averages*:[ ]*\([0-9.]*\) .*/\1/p'; }
load15() { uptime | sed -n 's/.*load averages*:[ ]*[0-9.]* [0-9.]* \([0-9.]*\).*/\1/p'; }

# Returns 0 when the box is DRAINED by both tests. Polls rather than spins -
# the window on this box has been hours away, and a busy-wait is itself load.
wait_quiet() {
  _i=0
  while [ "$_i" -lt "$TRIES" ]; do
    _l1=$(load1); _l15=$(load15)
    if [ "$(python3 -c "print(1 if $_l1 <= $MAXLOAD and $_l1 < $_l15 else 0)")" = "1" ]; then
      echo "WINDOW-OPEN load1=$_l1 load15=$_l15"; return 0
    fi
    echo "WINDOW-WAIT load1=$_l1 load15=$_l15 (need load1<=$MAXLOAD and load1<load15) try=$_i"
    sleep "$POLL"; _i=$((_i + 1))
  done
  echo "WINDOW-NEVER-CAME load1=$_l1 load15=$_l15"; return 1
}

P=$PORT0
for r in $OFFRATES; do
  wait_quiet || { echo "ROUND-ABANDONED before off-$r"; exit 1; }
  sh "$HERE/nestedcross.sh" "X-off-$r" "$P" "$r" \
     NZBFAST_CHASE_STAT=1 NZBFAST_NO_ENRICH=1
  P=$((P + 1))
done

for r in $RATES; do
  wait_quiet || { echo "ROUND-ABANDONED before on-$r"; exit 1; }
  sh "$HERE/nestedcross.sh" "X-on$MARGIN-$r" "$P" "$r" \
     NZBFAST_CHASE_STAT=1 NZBFAST_NO_ENRICH=1 \
     NZBFAST_CHASE_PROGRESS_TRIM=1 NZBFAST_CHASE_TRIM_MARGIN="$MARGIN"
  P=$((P + 1))
done

echo "ROUND-DONE"
