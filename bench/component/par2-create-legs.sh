#!/bin/bash
# PAR2 CREATE legs, macOS/Linux: our creator against ParPar and
# par2cmdline-turbo over the same payload.
#
# Create is the one leg where ParPar is the reference implementation
# (it only creates). Numbers and method:
# research/PAR2-PERF-AUDIT-2026-09-02.md sections 9, 12, 14.
#
#   par2-create-legs.sh [rounds] [block-size ...]
#
# Env: SRC (payload dir, every regular non-.par2 file in it is a
# member), OURS (par2_create_bench), PARPAR, TURBO, OUT (scratch),
# PCT (redundancy, default 10), TOOLS (default "ours parpar turbo16").
#
# Two traps this script exists to hold:
#  - ParPar wants `-s <N>b` for a byte count; a bare number is a SLICE
#    COUNT and it refuses over 32,768 with a message about input slices.
#  - par2cmdline-turbo refuses files outside its base path: pass -B<dir>
#    and absolute member paths, or it prints "Ignoring out of basepath
#    source file" and then "You must specify a list of files".
set -u
SRC=${SRC:?set SRC to a payload directory}
OURS=${OURS:?set OURS to a par2_create_bench build}
PARPAR=${PARPAR:-}
TURBO=${TURBO:-}
PARFAST=${PARFAST:-$HOME/parshoot3/bin/parfast}
PAR2_120=${PAR2_120:-$HOME/parshoot3/bin/par2}
PAR2_130=${PAR2_130:-$HOME/parshoot3/bin/par2cmdline130}
TURBO140=${TURBO140:-$HOME/parshoot3/bin/par2turbo}
TURBO150=${TURBO150:-$HOME/parshoot3/bin/par2turbo150}
OUT=${OUT:-${TMPDIR:-/tmp}/par2-create-out}
PCT=${PCT:-10}
ROUNDS=${1:-3}; shift || true
if [ $# -eq 0 ]; then SIZES=(1048576 65536); else SIZES=("$@"); fi
IFS=' ' read -r -a TOOLS <<< "${TOOLS:-ours parpar turbo16}"
now() { perl -MTime::HiRes=time -e 'printf "%.4f\n", time'; }
cat "$SRC"/* > /dev/null 2>&1   # pre-warm
members=$(cd "$SRC" && ls | grep -v '\.par2$')
for r in $(seq 1 "$ROUNDS"); do
 for bs in "${SIZES[@]}"; do
  for tool in "${TOOLS[@]}"; do
   rm -rf "$OUT"; mkdir -p "$OUT"
   t0=$(now)
   case $tool in
    ours)    NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$SRC" "$OUT" "$PCT" "$bs" > /dev/null 2> "$OUT/../create.err" ;;
    parpar)  [ -n "$PARPAR" ] || { echo "PARPAR unset"; continue; }
             (cd "$SRC" && $PARPAR -q -s "${bs}b" -r "$PCT%" -o "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
    turbo16) [ -n "$TURBO" ] || { echo "TURBO unset"; continue; }
             # shellcheck disable=SC2086
             (cd "$SRC" && $TURBO c -q -s"$bs" -r"$PCT" -T16 -B"$SRC" "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
    # --- release-table arms, added 4 Sep 2026 -------------------------
    # `parfast` is the SHIPPING BINARY, where `ours` is the
    # par2_create_bench harness. A create table in parfast's README has
    # to come from the tool a reader runs, argument parsing and all.
    # It takes par2cmdline's own spelling, which is the whole point of
    # it, so the invocation is turbo's minus the -T.
    # shellcheck disable=SC2086
    parfast) (cd "$SRC" && "$PARFAST" c -q -s"$bs" -r"$PCT" -B"$SRC" "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
    # shellcheck disable=SC2086
    par2_120) (cd "$SRC" && "$PAR2_120" c -q -s"$bs" -r"$PCT" -B"$SRC" "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
    # shellcheck disable=SC2086
    par2_130) (cd "$SRC" && "$PAR2_130" c -q -s"$bs" -r"$PCT" -B"$SRC" "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
    # turbo at BOTH versions, and each with and without -T16, because
    # the shipped default is what a user gets and -T16 is what its own
    # documentation steers them to.
    # shellcheck disable=SC2086
    turbo140) (cd "$SRC" && "$TURBO140" c -q -s"$bs" -r"$PCT" -B"$SRC" "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
    # shellcheck disable=SC2086
    turbo150) (cd "$SRC" && "$TURBO150" c -q -s"$bs" -r"$PCT" -B"$SRC" "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
    # shellcheck disable=SC2086
    turbo150_16) (cd "$SRC" && "$TURBO150" c -q -s"$bs" -r"$PCT" -T16 -B"$SRC" "$OUT/bench.par2" $members > /dev/null 2>&1) ;;
   esac
   t1=$(now)
   printf "CREATE r=%d bs=%-8d tool=%-7s wall=%.3f files=%s MB=%s\n" \
     "$r" "$bs" "$tool" "$(echo "$t1 - $t0" | bc)" \
     "$(ls "$OUT" | wc -l | tr -d ' ')" "$(du -sm "$OUT" | cut -f1)"
   [ -n "${TIMING:-}" ] && [ -f "$OUT/../create.err" ] && \
     grep repair-timing "$OUT/../create.err" | sed 's/.*repair-timing: /    /'
  done
 done
done
