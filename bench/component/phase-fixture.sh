#!/bin/bash
# Build a PAR2 phase-profile fixture: N random members of one size, one
# recovery set written by parfast at a given slice size and redundancy,
# and a SHA-256 manifest of the pristine members that every repair leg
# is gated on (research/PARFAST-REPAIR-PHASE-PROFILE-2026-09-10.md).
#
#   phase-fixture.sh <root> <members> <member_bytes> <slice_bytes> <pct> <parfast>
#
# Leaves <root>/pristine/{m01.bin..mNN.bin, set.par2, set.volNN+NN.par2}
# and <root>/pristine.sha (members only). The members are generated in
# parallel from /dev/urandom, which is the slow step on a Mac (~0.4 GB/s
# per stream); the set is created ONCE, with NZBFAST_REPAIR_TIMING kept
# OFF, and its wall is printed so a create regression is visible too.
#
# A slice size below the legal floor is RAISED, not honoured: PAR2 caps a
# set at 32,768 source blocks (par2gen::MAX_INPUT_SLICES), so `-s65536`
# over a 10 GiB payload silently became 393,216 B / 27,310 blocks on
# 10 Sep 2026 and the "163,840-block" fixture it was meant to be cannot
# exist. Read the CREATE line's slice count back, and reach the high-m
# regime with `-b32768` plus a high redundancy instead (phase-ladder.sh
# takes the parfast `-b` spelling through PARFAST_CREATE_ARGS).
set -euo pipefail
ROOT=${1:?root}; N=${2:?members}; MB=${3:?member bytes}; SL=${4:?slice bytes}
PCT=${5:?redundancy pct}; PF=${6:?parfast binary}
P=$ROOT/pristine
mkdir -p "$P"
if [ ! -f "$ROOT/pristine.sha" ]; then
  for i in $(seq -f %02g 1 "$N"); do
    [ -s "$P/m$i.bin" ] || head -c "$MB" /dev/urandom > "$P/m$i.bin" &
  done
  wait
  ( cd "$P" && shasum -a 256 m*.bin > "$ROOT/pristine.sha" )
fi
rm -f "$P"/*.par2
t0=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
# PARFAST_CREATE_ARGS replaces the -s/-r pair when set (e.g. "-b32768 -r100").
( cd "$P" && "$PF" c -q ${PARFAST_CREATE_ARGS:--s"$SL" -r"$PCT"} set.par2 m*.bin )
rc=$?
t1=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
blocks=$("$PF" v -q "$P/set.par2" 2>/dev/null | head -0; ls "$P"/*.vol*.par2 | sed -E 's/.*vol([0-9]+)\+([0-9]+).*/\1 \2/' | awk '{if ($1+$2>m) m=$1+$2} END{print m+0}')
echo "CREATE members=$N member_bytes=$MB slice_asked=$SL args=${PARFAST_CREATE_ARGS:-none} pct=$PCT wall=$(echo "$t1 - $t0" | bc) rc=$rc recovery_blocks=$blocks parity_bytes=$(cat "$P"/*.vol*.par2 | wc -c | tr -d ' ')"
