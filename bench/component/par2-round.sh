#!/bin/bash
# PAR2 component round, macOS/Linux: the repair and verify legs.
#
# Protocol, and every line of it is load-bearing (see
# research/PAR2-PERF-AUDIT-2026-09-02.md section 1): fresh copy of the
# corpus per leg -> PRE-WARM every byte -> time the binary -> gate the
# result on SHA256 identity against the pristine set. Pre-warming is
# what makes macOS and Windows comparable at all: `cp -c` here is an
# APFS clone that leaves the source pages cached, where a Windows copy
# really moves the bytes.
#
#   par2-round.sh <rounds> [leg ...]
#
# Legs: verify, 3, 101, heavy, and m<N> for a crossover sweep set built
# by par2-mkdamage.py. Arms come from TOOLS (default "ours turbo16
# turbo"):
#   ours     - our repair driver as it ships (fast par mode on)
#   fold     - ours with NZBFAST_NTT=0, the streaming fold
#   ntt      - ours with NZBFAST_NTT=force, the transform whatever the gates say
#   dense    - ours with NZBFAST_BACKSUB=dense, the m x m explicit inverse
#   forney   - ours with NZBFAST_BACKSUB=forney, the transform back-substitution
#   sched16  - ours with NZBFAST_GF16_GRANULE=16, the shipped fold schedule
#   sched16b - sched16's byte-identical twin, so a run can be an A/A
#   sched32  - ours with NZBFAST_GF16_GRANULE=32, the wide fold schedule
#   turbo16  - par2cmdline-turbo, -T16
#   turbo    - par2cmdline-turbo as shipped
#
# Env: RIG (corpus root), OURS (our binary), TURBO, WORK (scratch dir),
# TIMING=1 to print the per-phase split from NZBFAST_REPAIR_TIMING.
#
# PROTOCOL knobs, all defaulting to the old shape: LAYOUT=mirror runs the
# round's arm order and then its reverse (A B B A) so both arms hold both
# positions inside ONE round, SETTLE_MS idles between legs OUTSIDE every
# timed region, and REPS repeats the sequence within a round so a round
# yields a median rather than a sample. They exist because two big writes
# back to back with no idle between them latch for a whole run with a
# RANDOM SIGN on the Windows box, so two BYTE-IDENTICAL arms read as a
# clean sweep (audit round 40, research/RAR-PERF-AUDIT-2026-09-02.md).
# The macOS/APFS side has never shown that latch in 480 legs - which is
# exactly why the A/A comes first on any box: TOOLS="sched16 sched16b"
# is one binary against itself and must come out flat before either real
# arm is believed. Arm order rotates by round here whatever LAYOUT says.
#
# The corpus is the published one: a 1 GiB payload in 21 volumes with a
# 10% recovery set at 1 MiB blocks (verify / 3 / 101) and a second at
# 64 KiB blocks (heavy, 1,500 of 16,384 blocks damaged). par2rig-build.sh
# beside this file builds it; RIG needs pristine/, pristine-heavy/ and
# one damaged-* directory per leg, plus pristine.sha (sha256 of every
# payload file, taken inside pristine/).
#
# NOTE for the dense/forney pair: that A/B only means anything on an
# m<N> leg, and the published heavy set is 10% - 1,638 recovery blocks
# for 16,384 input blocks - so N cannot exceed 1,638 on it. That is
# below the shipped gate (forney::BACKSUB_MIN_MISSING = 2048), which is
# fine for measuring the CROSSOVER (both arms are forced) but cannot
# show the shipped default. For legs past the gate, build a deeper set
# first: `par2_create_bench <payload-dir> <payload-dir> 45 65536` gives
# ~7,300 recovery blocks. Audit section 20 has the numbers this arm
# produced and the shapes they were taken at.
set -u
RIG=${RIG:-$HOME/parshoot3/rig}
OURS=${OURS:?set OURS to a par2_repair_dir build}
TURBO=${TURBO:-$HOME/parshoot3/bin/par2turbo}
PARFAST=${PARFAST:-$HOME/parshoot3/bin/parfast}
PAR2_120=${PAR2_120:-$HOME/parshoot3/bin/par2}
PAR2_130=${PAR2_130:-$HOME/parshoot3/bin/par2cmdline130}
TURBO140=${TURBO140:-$HOME/parshoot3/bin/par2turbo}
TURBO150=${TURBO150:-$HOME/parshoot3/bin/par2turbo150}
RARPAR=${RARPAR:-$HOME/parshoot3/bin/rarpar}
WORK=${WORK:-${TMPDIR:-/tmp}/par2-round-work}
ROUNDS=${1:-3}; shift || true
if [ $# -eq 0 ]; then LEGS=(verify 3 101 heavy); else LEGS=("$@"); fi
IFS=' ' read -r -a TOOLS <<< "${TOOLS:-ours turbo16 turbo}"
LAYOUT=${LAYOUT:-rotate}
SETTLE_MS=${SETTLE_MS:-0}
REPS=${REPS:-1}
echo "PROTOCOL rounds=$ROUNDS layout=$LAYOUT settle_ms=$SETTLE_MS reps=$REPS tools=${TOOLS[*]}"
now() { perl -MTime::HiRes=time -e 'printf "%.4f\n", time'; }
sha_ok() {
  if command -v shasum > /dev/null; then (cd "$WORK" && shasum -a 256 -c "$RIG/pristine.sha" 2>/dev/null | grep -c ': OK$')
  else (cd "$WORK" && sha256sum -c "$RIG/pristine.sha" 2>/dev/null | grep -c ': OK$'); fi
}
total=$(grep -c . "$RIG/pristine.sha" 2>/dev/null || echo '?')
for r in $(seq 1 "$ROUNDS"); do
 for leg in "${LEGS[@]}"; do
  case $leg in
   verify) src=pristine;       par=site.par2 ;;
   3)      src=damaged-3;      par=site.par2 ;;
   101)    src=damaged-101;    par=site.par2 ;;
   heavy)  src=damaged-heavy;  par=heavy.par2 ;;
   m*)     src=damaged-$leg;   par=heavy.par2 ;;
   *) echo "unknown leg $leg" >&2; exit 2 ;;
  esac
  # The set's own index name differs between rigs; believe the corpus.
  [ -f "$RIG/$src/$par" ] || par=$(cd "$RIG/$src" && ls ./*.par2 | grep -v vol | head -1 | xargs basename)
  # The round's arm order: rotated by round, mirrored inside the round
  # when asked, repeated REPS times.
  order=()
  n=${#TOOLS[@]}
  base=()
  for ((i = 0; i < n; i++)); do base+=("${TOOLS[$(((i + r - 1) % n))]}"); done
  for ((q = 0; q < REPS; q++)); do
   order+=("${base[@]}")
   if [ "$LAYOUT" = mirror ]; then
    for ((i = n - 1; i >= 0; i--)); do order+=("${base[$i]}"); done
   fi
  done
  pos=0
  for tool in "${order[@]}"; do
   pos=$((pos + 1))
   # Idle OUTSIDE every timed region - that is what breaks the latch.
   [ "$SETTLE_MS" -gt 0 ] && perl -e "select undef, undef, undef, $SETTLE_MS/1000"
   rm -rf "$WORK"
   cp -c -R "$RIG/$src" "$WORK" 2>/dev/null || cp -R "$RIG/$src" "$WORK"
   cat "$WORK"/* > /dev/null 2>&1   # pre-warm
   cd "$WORK" || exit 1
   t0=$(now)
   case $tool in
    ours)    NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$WORK" > /dev/null 2> "$WORK/../last.err" ;;
    fold)    NZBFAST_NTT=0     NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$WORK" > /dev/null 2> "$WORK/../last.err" ;;
    ntt)     NZBFAST_NTT=force NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$WORK" > /dev/null 2> "$WORK/../last.err" ;;
    dense)   NZBFAST_BACKSUB=dense  NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$WORK" > /dev/null 2> "$WORK/../last.err" ;;
    forney)  NZBFAST_BACKSUB=forney NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$WORK" > /dev/null 2> "$WORK/../last.err" ;;
    sched16|sched16b)
             NZBFAST_GF16_GRANULE=16 NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$WORK" > /dev/null 2> "$WORK/../last.err" ;;
    sched32) NZBFAST_GF16_GRANULE=32 NZBFAST_REPAIR_TIMING=${TIMING:-} "$OURS" "$WORK" > /dev/null 2> "$WORK/../last.err" ;;
    turbo16) "$TURBO" r -q -T16 "$par" > /dev/null 2>&1 ;;
    turbo)   "$TURBO" r -q "$par" > /dev/null 2>&1 ;;
    # --- release-table arms, added 4 Sep 2026 -------------------------
    # The arm under test here is the SHIPPING parfast BINARY, not the
    # par2_repair_dir harness the `ours` arm drives. A table published in
    # parfast's own README has to come from the tool a reader will run,
    # including its argument parsing and its output layer, or it is a
    # measurement of something else. Keep both: `ours` stays the engine
    # A/B arm, `parfast` is the product arm.
    parfast)  "$PARFAST" r -q "$par" > /dev/null 2>&1 ;;
    # The rival set widened for the same reason: a reader may still be on
    # classic par2cmdline, and 1.2.0 is what Homebrew serves today while
    # 1.3.0 is the current tag.
    par2_120) "$PAR2_120" r -q "$par" > /dev/null 2>&1 ;;
    par2_130) "$PAR2_130" r -q "$par" > /dev/null 2>&1 ;;
    turbo140) "$TURBO140" r -q "$par" > /dev/null 2>&1 ;;
    turbo150) "$TURBO150" r -q "$par" > /dev/null 2>&1 ;;
    turbo150_16) "$TURBO150" r -q -T16 "$par" > /dev/null 2>&1 ;;
    # rarpar is a repair/extract driver rather than a par2cmdline
    # dialect, so it takes the set by path under its own subcommand. It
    # does not create, which is why it has no arm in par2-create-legs.sh.
    # rarpar resolves its argument itself rather than from the cwd, so a
    # bare "$par" gives it "I/O error: No such file or directory" AND
    # EXIT 0 - an arm that silently does nothing in 13 ms and reports
    # success. It gets the absolute path. (The other half of that first
    # bogus reading was mine: piping its output through `head` SIGPIPEs
    # it mid-repair, so never smoke-test a repair arm through a pager.)
    rarpar)   "$RARPAR" par repair "$WORK" > /dev/null 2>&1 ;;
   esac
   t1=$(now)
   printf "LEG r=%d pos=%d leg=%-6s tool=%-8s wall=%.3f sha_ok=%s/%s\n" \
     "$r" "$pos" "$leg" "$tool" "$(echo "$t1 - $t0" | bc)" "$(sha_ok)" "$total"
   [ -n "${TIMING:-}" ] && [ -f "$WORK/../last.err" ] && \
     grep repair-timing "$WORK/../last.err" | sed 's/.*repair-timing: /    /'
   cd - > /dev/null || exit 1
  done
 done
done
rm -rf "$WORK"
