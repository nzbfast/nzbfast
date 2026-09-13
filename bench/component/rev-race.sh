#!/bin/bash
# .rev recovery-volume restoration: rebuild missing data volumes from the
# standalone .rev files RAR writes with `rar rv`.
#
# This is the leg Weaver's rarpar CAN run - it implements exactly this and
# nothing else on the recovery side - so it is here to give it a fair fight.
#
#   rev-race.sh <root> <rounds> <ours-bin> <rar> <rarpar>
#
# Protocol matches every other leg: fresh copy of the damaged set, pre-warm
# every byte, time, then gate on the rebuilt volumes being byte-identical to
# the pristine ones.
set -euo pipefail
# Timed-leg discipline: rc captured, stderr kept, success decided per tool.
# shellcheck source=../lib/legrc.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/legrc.sh"

ROOT=${1:?usage: rev-race.sh <root> <rounds> <ours> <rar> <rarpar>}
ROUNDS=${2:-3}
OURS=${3:?ours}
RAR=${4:-rar}
RARPAR=${5:-rarpar}
WORK=$ROOT/work
leg_errdir "${REV_LOGS:-$ROOT/logs-rev}"
obsn=0

run_one() {
  local tool=$1
  rm -rf "$WORK"
  cp -c -R "$ROOT/damaged" "$WORK" 2>/dev/null || cp -R "$ROOT/damaged" "$WORK"
  cat "$WORK"/* > /dev/null 2>&1   # pre-warm
  local label="rev-$tool-$obsn" back=$PWD
  # Timed, with rc and stderr kept: a tool that REFUSES this shape returns
  # fast, and a discarded-stream harness records that as a win. See the
  # README's trap list.
  case $tool in
    ours)   leg_timed "$tool" "$label" "$OURS" "$WORK" ;;
    # RARLab's own reconstruct. It wants the first volume by name.
    rar)    cd "$WORK"
            leg_timed "$tool" "$label" "$RAR" rc "$(ls ./*.part01.rar 2>/dev/null || ls ./*.rar | head -1)"
            cd "$back" ;;
    rarpar) leg_timed "$tool" "$label" "$RARPAR" rar restore-volumes "$WORK"/*.rev ;;
    *) echo "unknown tool $tool" >&2; return 0 ;;
  esac
  # The OUTPUT gate stays, and stays separate from the exit code.
  local bad=0 missing=0
  for f in "$ROOT/pristine"/*.rar; do
    b=$(basename "$f")
    if [[ ! -f "$WORK/$b" ]]; then missing=$((missing+1)); continue; fi
    cmp -s "$f" "$WORK/$b" || bad=$((bad+1))
  done
  local gate=""
  (( missing == 0 && bad == 0 )) || gate="!! NOT-RESTORED (missing=$missing wrong=$bad)"
  printf '  %-8s %8.3fs rc=%-3s%s\n' "$tool" "$LEG_WALL" "$LEG_RC" "$(leg_flag "$LEG_STATUS" "$gate")"
}

echo "=== .rev restore ($ROUNDS rounds, warm protocol) ==="
echo "    per-leg stderr: $LEG_ERRDIR"
for _ in $(seq "$ROUNDS"); do
  obsn=$((obsn + 1))
  for t in ours rar rarpar; do run_one "$t"; done
done
rm -rf "$WORK"
