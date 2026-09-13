#!/bin/bash
# RAR inline recovery-record (`-rr`) repair leg, product path.
#
#   rr-race.sh <root> <rounds> <ours-bin> <rar> [sizes-MB]
#
# Moved in-repo from the scratch rig, where it carried a hardcoded worktree
# path that no longer exists and a /dev/urandom payload that made the corpus
# unreproducible. The payload now comes from a fixed-seed generator argument,
# so a corpus rebuilt on another machine is the same corpus.
#
# WHICH PATH THIS TIMES, because there are two and only one of them ships for
# this damage: `bench_rr_product` drives ArchiveReader ->
# repair_recovery_to_file, which is what the daemon takes whenever headers
# still parse (crates/nzbfast/src/main.rs). `bench_rr_stream` drives the raw
# {RB}-marker scan used ONLY when headers are too damaged to read. Payload
# damage leaves headers intact, so timing the stream driver here measures a
# path no user reaches on this input - an earlier round did exactly that.
#
# Build the driver with `--features parallel`, which is what crates/nzbfast
# enables; without it the decode runs serial and reads about 50% slow.
#
# Damage recipe, unchanged so the numbers stay comparable: three 3,000-byte
# runs of 0x5a at 20%, 50% and 80% of the archive. The gate is byte-identity
# against the pristine archive AND against `rar r`'s own repaired output, so
# a tool that "succeeds" without actually reconstructing is caught.
set -euo pipefail
# Timed-leg discipline: rc captured, stderr kept, success decided per tool.
# shellcheck source=../lib/legrc.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/legrc.sh"

ROOT=${1:?usage: rr-race.sh <root> <rounds> <ours-bin> <rar> [sizes]}
ROUNDS=${2:-3}
OURS=${3:?ours binary}
RAR=${4:-rar}
SIZES=${5:-16 32 128 512 2048}

W=$ROOT
mkdir -p "$W"
cd "$W"
leg_errdir "${RR_LOGS:-$ROOT/logs-rr}"

damage() { # damage <name>
  local name=$1
  cp "$name.pristine.rar" "$name.dmg.rar"
  python3 - "$name.dmg.rar" <<'PY'
import os, sys
p = sys.argv[1]
size = os.path.getsize(p)
with open(p, 'r+b') as fh:
    for frac in (0.20, 0.50, 0.80):
        fh.seek(int(size * frac))
        fh.write(b'\x5a' * 3000)
PY
}

printf '%-8s %8s %8s  %s\n' archive ours rar-r gate
for mb in $SIZES; do
  name=a$mb
  if [[ ! -f $name.pristine.rar ]]; then
    echo "$name.pristine.rar missing - build it with rr-build.sh" >&2
    continue
  fi
  best_ours=999; best_rar=999; gate=OK; obsn=0
  for _ in $(seq "$ROUNDS"); do
    obsn=$((obsn + 1))
    damage "$name"
    rm -f "$name.ours.rar"
    # rc AND stderr, both kept. A repair that REFUSES returns fast, and a
    # `>/dev/null 2>&1 || true` leg publishes that as the best time of the
    # round. See the component README's trap list.
    leg_timed ours "$name-ours-$obsn" "$OURS" "$W/$name.dmg.rar" "$W/$name.ours.rar"
    o=$LEG_WALL; [[ $LEG_STATUS == OK ]] || gate="OURS_FAIL(rc=$LEG_RC)"
    # Only when the exit code was fine: an rc failure EXPLAINS the diff, so
    # it must not be overwritten by the diff it caused.
    [[ $gate != OK ]] || cmp -s "$name.ours.rar" "$name.pristine.rar" || gate=OURS_DIFF

    damage "$name"
    rm -f "fixed.$name.dmg.rar"
    leg_timed rar "$name-rar-$obsn" "$RAR" r -idq "$name.dmg.rar"
    t=$LEG_WALL; [[ $LEG_STATUS == OK ]] || gate="RAR_FAIL(rc=$LEG_RC)"
    [[ $gate != OK ]] || cmp -s "fixed.$name.dmg.rar" "$name.pristine.rar" || gate=RAR_DIFF

    # Only a leg that PASSED both gates is eligible for the best-of: a
    # failure is fast, so folding it into a `min` is how a refusal becomes
    # the published number.
    [[ $gate == OK ]] || continue
    best_ours=$(python3 -c "print(min($best_ours,$o))")
    best_rar=$(python3 -c "print(min($best_rar,$t))")
  done
  if [[ $gate != OK || $best_ours == 999 ]]; then
    printf '%-8s %8s %8s  %s (stderr: %s)\n' "${mb}MB" FAILED FAILED "$gate" "$LEG_ERRDIR"
  else
    python3 -c "print('%-8s %8.3f %8.3f  %s (%.1fx)' % ('${mb}MB', $best_ours, $best_rar, '$gate', $best_rar/$best_ours))"
  fi
  rm -f "$name.dmg.rar" "$name.ours.rar" "fixed.$name.dmg.rar"
done
