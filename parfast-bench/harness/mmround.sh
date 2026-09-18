#!/bin/bash
# Round 2: the candidate after the three fixes round 1's primitive bench
# found. Claim memops-memmove-overlap-regression-16sep.
set -u
R=/root/mmov-16sep
cd "$R" || exit 1
export LEGS=${LEGS:-15} MIN_S=${MIN_S:-0.002} ROUNDS=1

echo "=== PHASE 1: correctness through the exported symbol ==="
for arm in base cand aa; do echo "-- check $arm"; ./membench-$arm check | tail -2; done

echo "=== PHASE 2: x86_64 MUTATION suite through the same harness ==="
for m in mut2-*; do
  [ -e "$m" ] || continue
  out=$(./"$m" check | tail -1)
  if [ "$out" = "ALL-OK" ]; then echo "$m  PASSED (HOLE)"; else echo "$m  FAILED (caught)"; fi
done

echo "=== PHASE 3: membench, overlapping shapes ==="
: > "$R/membench2.txt"
ARMS_ORDER=(base cand aa)
for r in $(seq 1 "${ROUNDS_N:-9}"); do
  k=$(( (r - 1) % 3 ))
  order=("${ARMS_ORDER[@]:$k}" "${ARMS_ORDER[@]:0:$k}")
  if [ $((r % 2)) -eq 0 ]; then order=("${order[2]}" "${order[1]}" "${order[0]}"); fi
  for arm in "${order[@]}"; do ARM=$arm nice -n 19 ./membench-$arm bench >> "$R/membench2.txt"; done
  echo "  round $r done: ${order[*]}"
done
echo "PHASE3-DONE lines=$(wc -l < "$R/membench2.txt")"

echo "=== PHASE 4: the tls cell, three arms ==="
cd /root/harness || exit 1
R=$R REPS=${REPS:-7} CELLS=tls OUT=tls2.jsonl \
  ARMS="musl=$R/nzbfast-musl,fast=$R/nzbfast-fast,aa=$R/nzbfast-aa" \
  SERVER=$R/nzbfast-musl FILES=16 python3 dmem.py

echo "=== PHASE 5: the tls profiles ==="
R=$R REPS=1 CELLS=tls OUT=prof2.jsonl PROFILE=1 \
  ARMS="musl=$R/nzbfast-musl,fast=$R/nzbfast-fast,aa=$R/nzbfast-aa" \
  SERVER=$R/nzbfast-musl FILES=16 python3 dmem.py
echo ROUND2-DONE
