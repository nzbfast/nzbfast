#!/bin/bash
# readscan-round.sh - the read-side cache policy's round for a box that
# cannot run the engine and cannot drop its cache.
#
# par2-cache-round.sh is the equivalent for a box that can do both: it
# drives the real binary with NZBFAST_READ_HINTS and establishes cold
# arms with `echo 3 > /proc/sys/vm/drop_caches`. Neither is available on
# a NAS-class appliance - no compiler, no root - which is precisely the
# ROTATIONAL device class the policy stands down on. This driver uses
# the three static C tools instead (readscan, resident, uncache), so the
# same two questions can be asked there:
#
#   1. does the sequential declaration matter on this device, and
#   2. does gated drop-behind cost wall, and what does it save the REST
#      of the box.
#
# Question 2's metric is outside the process, exactly as in the engine
# round: a mincore page count of an unrelated working set before and
# after the leg. For it to mean anything the payload plus the working
# set must EXCEED the page cache - otherwise nothing is evicted in
# either arm and the round measures nothing. The script prints the
# demand ratio and refuses below 1.05.
#
# Usage (all paths are read ONLY; nothing here writes, creates or
# unlinks a payload):
#
#   readscan-round.sh mech  --bin DIR --file F [--reps N] [--buf MiB]
#   readscan-round.sh evict --bin DIR --payload F --ws "F1;F2;F3" [--reps N] [--buf MiB]
#
# `--ws` is a SEMICOLON-separated list of working sets, one consumed per
# LEG (cycled if there are fewer entries than legs; each entry may name
# several space-separated files, so a path in one may not contain a
# space). A FRESH set per leg is not a nicety.
# Re-reading one working set across legs promotes its pages to the
# kernel's active list, and from the second leg on it survives the
# BASELINE arm too - the round then reports "nothing was evicted" for
# both arms and reads as a null result. The rotational round of 3 Sep
# 2026 saw exactly that at rep 2 and the first rep is the only one of
# its three that measured anything.
#
# `mech` is the no-memory-pressure pair: every arm warm, then every arm
# cold. Its COLD drop-behind column is NOT a verdict on the policy - a
# bare cold read with the payload fitting in RAM never reclaims, so the
# drop is pure cost there; that trap is recorded at the end of
# research/PAR2-TWO-LANES-COMPARED-2026-09-03.md. What `mech` is for is
# the SEQUENTIAL question and the gate's classification counts.
#
# Every row carries the arm's POSITION in the round and the box's load,
# and every leg is bracketed by the block device's sectors-read counter
# so a leg contaminated by somebody else's I/O can be seen rather than
# averaged in. Arm order rotates between reps.
set -u

BIN=""; REPS=3; BUF=1; FILE=""; PAYLOAD=""; WS=""; DEV=""
MODE="${1:-}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2;;
    --file) FILE="$2"; shift 2;;
    --payload) PAYLOAD="$2"; shift 2;;
    --ws) WS="$2"; shift 2;;
    --reps) REPS="$2"; shift 2;;
    --buf) BUF="$2"; shift 2;;
    --dev) DEV="$2"; shift 2;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
[ -n "$BIN" ] || { echo "--bin DIR (holding readscan, resident, uncache) is required" >&2; exit 2; }
for t in readscan resident uncache; do
  [ -x "$BIN/$t" ] || { echo "$BIN/$t missing or not executable" >&2; exit 2; }
done

# The binaries are the arms here, so their identity is part of the
# round: three separate lanes on 3 Sep 2026 measured a "candidate" that
# was secretly the baseline (research/PAR2-RIGS-2026-09-02.md).
echo "# tools:"
( cd "$BIN" && sha256sum readscan resident uncache 2>/dev/null || md5sum readscan resident uncache ) | sed 's/^/#   /'
echo "# box: $(uname -srm)  cores=$(nproc 2>/dev/null || echo ?)"
echo "# mem: $(awk '/MemTotal/{printf "%.1f GB total", $2/1e6} /^Cached:/{printf ", %.1f GB cached", $2/1e6}' /proc/meminfo)"

load() { cut -d' ' -f1-3 /proc/loadavg; }
sectors() { [ -n "$DEV" ] && awk -v d="$DEV" '$3==d{print $6}' /proc/diskstats || echo 0; }
res_pages() { # total resident pages over the listed files
  # shellcheck disable=SC2086
  "$BIN/resident" $1 | awk '{s+=$1} END{print s+0}'
}
res_total() {
  # shellcheck disable=SC2086
  "$BIN/resident" $1 | awk '{s+=$2} END{print s+0}'
}

# One leg. $1 = label, $2 = readscan flags, rest = file.
leg() {
  local label="$1" flags="$2" f="$3"
  local s0 s1 out
  s0=$(sectors)
  # shellcheck disable=SC2086
  out=$("$BIN/readscan" $flags -b "$BUF" "$f")
  s1=$(sectors)
  echo "$out sectors_read=$(( (s1 - s0) )) load=$(load | tr ' ' '/')"
}

ARMS_NAME=(plain seq seq_drop seq_drop_gated)
ARMS_FLAG=("" "-s" "-s -d 64" "-s -d 64 -g")

if [ "$MODE" = "mech" ]; then
  [ -n "$FILE" ] || { echo "--file is required for mech" >&2; exit 2; }
  sz=$(stat -c %s "$FILE")
  echo "# mech file: $FILE  $(awk -v b="$sz" 'BEGIN{printf "%.2f GB", b/1e9}')  buf=${BUF}MiB reps=$REPS"
  # RE-WARM BEFORE EVERY LEG, and record what the leg actually found.
  # The obvious form - warm once, then run all four arms - does not
  # work: the drop-behind arms evict the payload as they read it, so
  # every arm after the first drop arm runs COLD and the phase silently
  # stops measuring what it says it measures. The first round on the
  # rotational box was written that way and its `sectors_read` column is
  # what caught it. The `pre=` column is its replacement: a warm leg
  # must show `pre` equal to the file's page count.
  echo "# WARM: the file is re-read plain before every leg, so each arm"
  echo '# starts from a resident payload. pre= is the residency the leg found.' 
  for r in $(seq 1 "$REPS"); do
    for i in $(seq 0 3); do
      k=$(( (i + r - 1) % 4 ))
      "$BIN/readscan" -b "$BUF" "$FILE" >/dev/null
      pre=$(res_pages "$FILE")
      printf 'ROW\tmech-warm\trep=%d\tpos=%d\tarm=%s\t%s\tpre=%d/%d\n' \
        "$r" "$i" "${ARMS_NAME[$k]}" "$(leg "${ARMS_NAME[$k]}" "${ARMS_FLAG[$k]}" "$FILE")" \
        "$pre" "$(res_total "$FILE")"
    done
  done
  echo "# COLD: the file is uncached before every leg. Read the drop columns"
  echo "# here as cost only - there is no memory pressure in this phase."
  for r in $(seq 1 "$REPS"); do
    for i in $(seq 0 3); do
      k=$(( (i + r - 1) % 4 ))
      u=$("$BIN/uncache" "$FILE")
      printf 'ROW\tmech-cold\trep=%d\tpos=%d\tarm=%s\t%s\tuncache=%s\n' \
        "$r" "$i" "${ARMS_NAME[$k]}" "$(leg "${ARMS_NAME[$k]}" "${ARMS_FLAG[$k]}" "$FILE")" \
        "$(echo "$u" | awk '{print $1"->"$2"/"$3}')"
    done
  done
  echo "# END mech"
  exit 0
fi

if [ "$MODE" = "evict" ]; then
  [ -n "$PAYLOAD" ] && [ -n "$WS" ] || { echo "--payload and --ws are required for evict" >&2; exit 2; }
  psz=$(stat -c %s "$PAYLOAD")
  echo "# payload: $PAYLOAD $(awk -v b="$psz" 'BEGIN{printf "%.2f GB", b/1e9}')"
  cache=$(awk '/MemTotal/{print $2*1024}' /proc/meminfo)
  # One working set per leg, semicolon separated.
  IFS=';' read -r -a WS_SET <<< "$WS"
  NSETS=${#WS_SET[@]}
  for n in $(seq 0 $(( NSETS - 1 ))); do
    wsz=0; for f in ${WS_SET[$n]}; do wsz=$(( wsz + $(stat -c %s "$f") )); done
    ratio=$(awk -v p="$psz" -v w="$wsz" -v c="$cache" 'BEGIN{printf "%.2f", (p+w)/c}')
    echo "# ws set $n: $(awk -v b="$wsz" 'BEGIN{printf "%.2f GB", b/1e9}') over $(echo "${WS_SET[$n]}" | wc -w) file(s), demand/RAM = $ratio"
    awk -v r="$ratio" 'BEGIN{ if (r+0 < 1.05) exit 1 }' || { echo "REFUSED: working set $n leaves demand ratio $ratio - below 1.05 nothing is evicted in either arm and the round measures nothing" >&2; exit 3; }
  done
  # Two arms only: what a rotational volume ships TODAY (the sequential
  # declaration, no drop-behind) against the candidate.
  E_NAME=(seq seq_drop_gated)
  E_FLAG=("-s" "-s -d 64 -g")
  leg_i=0
  for r in $(seq 1 "$REPS"); do
    for i in 0 1; do
      k=$(( (i + r - 1) % 2 ))
      set_i=$(( leg_i % NSETS ))
      this_ws="${WS_SET[$set_i]}"
      leg_i=$(( leg_i + 1 ))
      "$BIN/uncache" "$PAYLOAD" > /dev/null
      # shellcheck disable=SC2086
      for f in $this_ws; do "$BIN/readscan" -b "$BUF" "$f" >/dev/null; done
      before=$(res_pages "$this_ws"); total=$(res_total "$this_ws")
      row=$(leg "${E_NAME[$k]}" "${E_FLAG[$k]}" "$PAYLOAD")
      after=$(res_pages "$this_ws")
      cached=$(awk '/^Cached:/{printf "%.1f", $2/1e6}' /proc/meminfo)
      printf 'ROW\tevict\trep=%d\tpos=%d\tarm=%s\t%s\tws=%d->%d/%d\tcached_after=%sGB\tws_set=%d\n' \
        "$r" "$i" "${E_NAME[$k]}" "$row" "$before" "$after" "$total" "$cached" "$set_i"
    done
  done
  echo "# END evict"
  exit 0
fi

echo "usage: $0 mech|evict --bin DIR ..." >&2
exit 2
