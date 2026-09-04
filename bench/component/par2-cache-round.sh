#!/usr/bin/env bash
# par2-cache-round.sh - does a PAR2 pass evict the rest of the box?
#
# Written 3 Sep 2026 for the read-side page-cache policy
# (crates/nzbkit-base/src/disk/readpolicy.rs).
#
# THE METRIC IS PARTLY OUTSIDE THE PROCESS. Every PAR2 leg recorded in
# research/PAR2-PERF-AUDIT-2026-09-02.md timed the PAR2 process; none of
# them timed the machine around it. A 23 GB verify pulls its whole
# payload through the page cache and evicts whatever else was resident -
# on a build box that is other lanes' object files, on a user's machine
# it is their working set. Two phases measure the two halves:
#
#   evict  the payload is COLD and an unrelated working set is RESIDENT.
#          Headline number: how many of that working set's pages survive
#          the PAR2 leg, counted by ./resident (mincore), not timed. The
#          leg's own wall in this phase is the COLD wall.
#   warm   the payload is RESIDENT and there is no working set. This is
#          the keep rule's "no slower warm" arm and nothing else.
#
# ARMS ARE ONE BINARY. NZBFAST_READ_HINTS=0/1 selects the policy at run
# time, so this round cannot fall into the trap that cost three separate
# lanes a day on 3 Sep 2026 - a "candidate" that was secretly the
# baseline (research/PAR2-RIGS-2026-09-02.md). Nothing here builds two
# trees, so nothing here can ship the wrong one. The binary is still
# gated below on actually carrying the knob, because an arm the binary
# does not understand reads as "no effect", which is the exact shape of
# a false negative.
#
# Usage:
#   par2-cache-round.sh --bin DIR --rig DIR [--ws FILE] [--reps N]
#                       [--phase evict|warm] [--floor-mb N]
#
#   --bin       directory holding par2_repair_dir (cargo build --release
#               -p nzbkit --example par2_repair_dir)
#   --rig       directory holding the member(s) and their .par2 set
#   --ws        the unrelated working set file; required for --phase evict
#   --reps      paired repetitions, default 3
#   --floor-mb  force NZBFAST_READ_HINT_MIN_MB, for a threshold sweep
#
# Dropping the cache needs root and Linux; without it the evict phase
# refuses rather than reporting a number it did not measure.
#
# ARM ORDER ALTERNATES between reps and the position is recorded on every
# row: interleaving removes drift, not thermal or contention drift, and
# this round's own coordination rules say to record the position.
#
# Output: CSV on stdout.
#   rep,pos,arm,phase,wall_s,rc,ws_res_before,ws_res_after,ws_total,
#   cached_kb_before,cached_kb_after,load
set -u

BIN=; RIG=; WS=; REPS=3; PHASE=evict; FLOOR=
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN=$2; shift 2;;
    --rig) RIG=$2; shift 2;;
    --ws) WS=$2; shift 2;;
    --reps) REPS=$2; shift 2;;
    --phase) PHASE=$2; shift 2;;
    --floor-mb) FLOOR=$2; shift 2;;
    -h|--help) sed -n '2,50p' "$0"; exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
[ -n "$BIN" ] && [ -n "$RIG" ] || { echo "need --bin and --rig" >&2; exit 2; }
case "$PHASE" in
  evict) [ -n "$WS" ] || { echo "--phase evict needs --ws" >&2; exit 2; };;
  warm) ;;
  *) echo "unknown --phase $PHASE" >&2; exit 2;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
RES=$HERE/resident
if [ ! -x "$RES" ]; then
  cc -O2 -o "$RES" "$HERE/resident.c" || { echo "cannot build resident" >&2; exit 2; }
fi
VERIFY=$BIN/par2_repair_dir
[ -x "$VERIFY" ] || { echo "no par2_repair_dir in $BIN" >&2; exit 2; }
if ! strings "$VERIFY" 2>/dev/null | grep -q NZBFAST_READ_HINTS; then
  echo "REFUSING: $VERIFY carries no NZBFAST_READ_HINTS, so both arms are one policy" >&2
  exit 3
fi
echo "# binary $( (sha256sum "$VERIFY" 2>/dev/null || shasum -a 256 "$VERIFY") | cut -c1-16)" >&2
if [ "$PHASE" = evict ] && [ ! -w /proc/sys/vm/drop_caches ]; then
  echo "REFUSING: --phase evict cannot drop the page cache here (needs root on Linux)" >&2
  exit 3
fi

drop_caches() { sync; echo 3 > /proc/sys/vm/drop_caches; }
cached_kb()  { awk '/^Cached:/{print $2; exit}' /proc/meminfo 2>/dev/null || echo 0; }
loadnow()    { cut -d' ' -f1-3 /proc/loadavg 2>/dev/null | tr ' ' '/' || echo NA; }
warm_all()   { for m in "$RIG"/*; do [ -f "$m" ] && cat "$m" > /dev/null; done; }

echo "rep,pos,arm,phase,wall_s,rc,ws_res_before,ws_res_after,ws_total,cached_kb_before,cached_kb_after,load"

leg() { # rep pos arm
  local rep=$1 pos=$2 arm=$3 rb=0 ra=0 tot=0 cb ca t0 t1 wall rc
  drop_caches
  if [ "$PHASE" = evict ]; then
    # The working set goes in AFTER the drop and the payload stays out,
    # so the only thing that can evict these pages is the PAR2 leg.
    cat "$WS" > /dev/null
    set -- $("$RES" "$WS"); rb=$1; tot=$2
  else
    warm_all
  fi
  cb=$(cached_kb)
  t0=$(date +%s.%N)
  env NZBFAST_READ_HINTS="$arm" ${FLOOR:+NZBFAST_READ_HINT_MIN_MB="$FLOOR"} \
      "$VERIFY" "$RIG" > /dev/null 2>&1
  rc=$?
  t1=$(date +%s.%N)
  wall=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
  if [ "$PHASE" = evict ]; then set -- $("$RES" "$WS"); ra=$1; fi
  ca=$(cached_kb)
  echo "$rep,$pos,$arm,$PHASE,$wall,$rc,$rb,$ra,$tot,$cb,$ca,$(loadnow)"
}

r=1
while [ "$r" -le "$REPS" ]; do
  if [ $((r % 2)) -eq 1 ]; then leg "$r" 1 0; leg "$r" 2 1
  else                          leg "$r" 1 1; leg "$r" 2 0; fi
  r=$((r + 1))
done
