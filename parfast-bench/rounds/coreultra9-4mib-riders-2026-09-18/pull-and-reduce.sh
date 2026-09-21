#!/bin/sh
# pull-and-reduce.sh - bring this sitting's logs back and reduce them.
#
# Run from the repo root AFTER the round posts DONE. It pulls, checks the
# encoding, banks UTF-8 copies under logs/, and reduces every cell.
#
# IT CHECKS THE LEG COUNTS FIRST AND REFUSES ON A ZERO. That is not ceremony:
# the lane that held this box before this one posted a completion NOTE - in
# wording its driver generates automatically - over a sitting that ran ZERO
# legs, and the identical wording had covered a real round four hours earlier.
# A DONE line proves the ladder loop exited. The leg count is the thing that
# proves it measured. Read the count, not the word.
set -u
BOX=intel-core-ultra-9-386h
REMOTE='C:<rig>/zr18sep/harness/logs'
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
mkdir -p logs

echo "== pulling =="
scp -q "$BOX:$REMOTE/*.log" logs/ || { echo "REFUSING: scp failed"; exit 2; }
scp -q "$BOX:C:<rig>/zr18sep/zrider.log" ./zrider-driver.log || echo "note: driver log not pulled"

echo
echo "== encoding (UTF-16 reads to rowgate.py as 'REFUSED: no legs') =="
for f in logs/*.log ./zrider-driver.log; do
  [ -f "$f" ] || continue
  d=$(file -b "$f")
  case "$d" in
    *UTF-16*) echo "  CONVERTING $f ($d)"; iconv -f UTF-16LE -t UTF-8 "$f" > "$f.u8" && mv "$f.u8" "$f" ;;
    *)        echo "  ok $f ($d)" ;;
  esac
done

echo
echo "== leg counts, and a ZERO is a REFUSAL =="
bad=0
for f in logs/*.log; do
  n=$(grep -ac '^LEG ' "$f" 2>/dev/null || echo 0)
  printf '  %-14s %s\n' "$(basename "$f" .log)" "$n"
  [ "$n" -eq 0 ] && bad=$((bad+1))
done
if [ "$bad" -gt 0 ]; then
  echo "REFUSING: $bad ladder log(s) carry ZERO legs. A DONE line proves the loop exited, not that it measured."
  exit 2
fi

echo
echo "== rc and restored: every leg must be rc=0 =="
echo "  non-rc=0 legs: $(grep -ah '^LEG ' logs/*.log | grep -vc 'rc=0 ')"
echo "  legs not restored=16/16 or match=1: $(grep -ah '^LEG ' logs/*.log | grep -vcE 'restored=16/16|match=1')"

echo
echo "== affinity readback on the pinned ladders =="
grep -a 'AFFINITY-AUDIT\|ZRIDER-' ./zrider-driver.log 2>/dev/null | sed 's/^[^ ]* /  /'

echo
echo "== (D) solo vs interleaved, and the drift control =="
for t in zsolo zint zdrift; do
  [ -f "logs/$t.log" ] && { echo "--- $t"; python3 ../../harness/rowgate.py read "logs/$t.log"; }
done

echo
echo "== (A) the knee: wide pool with no siblings, its control, and the mixed arm =="
python3 ../../harness/kneeratio.py logs/zp3e8.log logs/zp3e4.log $([ -f logs/zp3pe8.log ] && echo logs/zp3pe8.log)

echo
echo "== (B) the e8 band top, and (C) the p4 third rep =="
for t in ze8top zp4rep; do
  [ -f "logs/$t.log" ] && { echo "--- $t"; python3 ../../harness/rowgate.py read "logs/$t.log"; }
done

echo
echo "NEXT: screen with crpin4m-2026-09-18/bracket-firmness.py and, FROM THE REPO ROOT,"
echo "      pinaff4m-2026-09-16/ladder-monotonicity-audit.py, before believing a crossover."
