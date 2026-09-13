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
# THE DAMAGE LADDER, and why the leg KEYS are not the labels.
#
#   leg            label                       damaged   m        rig
#   verify         no damage                        0%   0        RIG
#   3              slight damage                  0.3%   3        RIG
#   101            light damage                   9.9%   101      RIG
#   heavy          some damage                    9.2%   1,500    RIG
#   d25            a lot of damage                 25%   8,192    CEILING
#   d50            extreme damage                  50%   16,384   CEILING
#   d100           the most damage still            100%  32,768  CEILING
#                  recoverable
#   gapped         the recovery set damaged too   12.2%  4,000    CEILING
#   gapped-refuse  the same, past our cap         30.5%  10,000   CEILING
#
# `heavy` WAS THE WHOLE PROBLEM. It named a 9.2% repair - 1,500 of
# 16,384 blocks - and every table that carried the word implied a worst
# case. It is not one: it is `101` again at a smaller block size (9.9%
# of 1,024 blocks), differing in m rather than in how badly the set is
# hurt. Neither could be worse, because RIG's sets carry 10% parity and
# 10% parity cannot repair more than 10% of its inputs. The rungs past
# it therefore need their OWN fixture, `par2rig-ceiling.sh`, which
# carries 100% redundancy at the PAR2 spec ceiling of 32,768 blocks.
#
# THE LADDER IS NOT IN COST ORDER, and a table that presents it as one
# will look wrong. Fold work is `m * (N - m)`: it peaks at m = N/2 and
# is ZERO at m = N, because a set with nothing left has nothing to fold.
# So `extreme damage` is the slowest leg here and `the most damage still
# recoverable` - every block gone, rebuilt from exactly enough parity -
# runs an order of magnitude faster than the rung below it. Say so in
# the write-up rather than letting a reader find it and distrust the
# table.
#
# THE GAPPED LEGS ARE A DIFFERENT AXIS. Everything above damages DATA;
# those two damage the RECOVERY SET, which is what a thin provider fill
# actually produces. With recovery packets missing the exponents are no
# longer consecutive, so there is no Vandermonde factorization and BOTH
# transforms are lost at once: Gauss-Jordan for the inverse, the dense
# product for the solve. `gapped-refuse` is past MAX_REPAIR_DIM and we
# DECLINE it - it is there to measure a leg par2cmdline completes and we
# do not, which is a product gap and not a benchmark result. Read its
# rc, not its wall.
#
# Legs: the ten above, plus m<N> for a crossover sweep set built by
# par2-mkdamage.py. Arms come from TOOLS (default "ours turbo16
# turbo"):
#   ours     - our repair driver as it ships (fast par mode on)
#   fold     - ours with NZBFAST_NTT=0, the streaming fold
#   ntt      - ours with NZBFAST_NTT=force, the transform whatever the gates say
#   dense    - ours with NZBFAST_BACKSUB=dense, the m x m explicit inverse
#   forney   - ours with NZBFAST_BACKSUB=forney, the transform back-substitution
#   sched16  - ours with NZBFAST_GF16_GRANULE=16, the shipped fold schedule
#   sched16b - sched16's byte-identical twin, so a run can be an A/A
#   sched32  - ours with NZBFAST_GF16_GRANULE=32, the wide fold schedule
#   turbo16  - par2cmdline-turbo, -T16 (turbo's files-hashed-in-parallel
#              count, NOT its compute-thread knob - see the README trap)
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
# A change to verification, retained blocks or retention admission MUST
# include the CLEAN verify leg on every host being used to justify it.
# Retention is paid before damage is known; repair-only timings miss its
# cost on a clean set. Run an A/A first (TOOLS="ours ours"), then compare
# one pinned binary with NZBFAST_REPAIR_RETAIN unset, =0, and an explicit
# budget sufficient for the whole corpus. At 4/10 GiB, unset already
# disables retention: unset-vs-0 alone cannot price retaining that size.
# Include 1/2/4/10 GiB corpora and report actual input-block bytes, not
# just payload bytes: per-member padding can put a nominal 2 GiB set
# above the gate. Keep every SHA/exit-status gate and check NoDamage for
# the clean arm (the example can print an error status with exit 0).
# Read deltas against each host/size's A/A floor; a sub-floor delta is
# inconclusive. Archive every cell, binary/driver digest, load and order.
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
# The ceiling rig (par2rig-ceiling.sh) holds the d25/d50/d100 and gapped
# legs. It defaults to RIG so an invocation that names none of them is
# unchanged; a run that does name one and has no ceiling rig fails at
# the copy, loudly, rather than silently measuring the wrong corpus.
CEILING=${CEILING:-$RIG}
OURS=${OURS:?set OURS to a par2_repair_dir build}
TURBO=${TURBO:-$HOME/parshoot3/bin/par2turbo}
PARFAST=${PARFAST:-$HOME/parshoot3/bin/parfast}
PAR2_120=${PAR2_120:-$HOME/parshoot3/bin/par2}
PAR2_130=${PAR2_130:-$HOME/parshoot3/bin/par2cmdline130}
TURBO140=${TURBO140:-$HOME/parshoot3/bin/par2turbo}
TURBO150=${TURBO150:-$HOME/parshoot3/bin/par2turbo150}
RARPAR=${RARPAR:-$HOME/parshoot3/bin/rarpar}
# --- rival-survey arms, added 5 Sep 2026 ------------------------------
# Every other PAR2 implementation the survey could get to run
# (research/PAR2-RIVAL-SURVEY-2026-09-05.md has the roster and why each
# is or is not here). par2tbb is par2cmdline 0.4 + Intel TBB 2.2 (2010,
# MMX kernel) and only links against a TBB from before the 2021 oneTBB
# API break, so TBBLIB names that library's directory for its
# LD_LIBRARY_PATH; gopar is akalin's Go implementation (`r` repairs, `v`
# verifies, no -q); par2rs is a 30-line CLI over the rust-par2 crate,
# which ships as a library only and claims 1.1x turbo on repair;
# turbo120 is nzbgetcom's par2cmdline-turbo fork (turbo 1.2.0 + Unicode
# fixes), the binary NZBGet ships, included to show it IS turbo.
PAR2TBB=${PAR2TBB:-$HOME/parshoot3/bin/par2tbb}
TBBLIB=${TBBLIB:-}
GOPAR=${GOPAR:-$HOME/parshoot3/bin/gopar}
PAR2RS=${PAR2RS:-$HOME/parshoot3/bin/par2rs-cli}
TURBO120=${TURBO120:-$HOME/parshoot3/bin/par2turbo120utf8}
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
  if command -v shasum > /dev/null; then (cd "$WORK" && shasum -a 256 -c "$rig/pristine.sha" 2>/dev/null | grep -c ': OK$')
  else (cd "$WORK" && sha256sum -c "$rig/pristine.sha" 2>/dev/null | grep -c ': OK$'); fi
}
for r in $(seq 1 "$ROUNDS"); do
 for leg in "${LEGS[@]}"; do
  # rig / src / par, and the two facts a published table has to carry:
  # `label`, the plain-English rung, and `dmg`, the share of the set's
  # INPUT BLOCKS that is damaged. `dmg` is why the ladder needed a
  # second fixture at all - see LABELS in the header.
  rig=$RIG
  case $leg in
   verify) src=pristine;       par=site.par2;    label=no-damage;         dmg=0% ;;
   3)      src=damaged-3;      par=site.par2;    label=slight-damage;     dmg=0.3% ;;
   101)    src=damaged-101;    par=site.par2;    label=light-damage;      dmg=9.9% ;;
   heavy)  src=damaged-heavy;  par=heavy.par2;   label=some-damage;       dmg=9.2% ;;
   # The ceiling rig (par2rig-ceiling.sh): N = 32,768 blocks of 64 KiB
   # at 100% redundancy, so the damage rungs are not capped by parity.
   d25)    src=damaged-d25;    par='';           label=a-lot-of-damage;   dmg=25%;  rig=$CEILING ;;
   d50)    src=damaged-d50;    par='';           label=extreme-damage;    dmg=50%;  rig=$CEILING ;;
   d100)   src=damaged-d100;   par='';           label=most-recoverable;  dmg=100%; rig=$CEILING ;;
   # A DIFFERENT AXIS: the recovery set is damaged, not the data. No
   # Vandermonde factorization, so Gauss-Jordan and the dense product.
   gapped) src=damaged-gapped; par='';           label=gapped-recovery;   dmg=12.2%; rig=$CEILING ;;
   gapped-refuse)
           src=damaged-gapped-refuse; par='';    label=gapped-over-cap;   dmg=30.5%; rig=$CEILING ;;
   m*)     src=damaged-$leg;   par=heavy.par2;   label=sweep;             dmg="n/a" ;;
   *) echo "unknown leg $leg" >&2; exit 2 ;;
  esac
  # The set's own index name differs between rigs; believe the corpus.
  [ -f "$rig/$src/$par" ] || par=$(cd "$rig/$src" && ls ./*.par2 | grep -v vol | head -1 | xargs basename)
  total=$(grep -c . "$rig/pristine.sha" 2>/dev/null || echo '?')
  # Which solve OUR engine chose for this leg, asked once per leg and
  # OUTSIDE
  # every timed cell. The same published leg does not run the same arm
  # on every part - the gate is 896 on aarch64, 1,280 on the x86 nibble
  # arms and 2,048 elsewhere - so a table that names a leg without
  # naming its arm is describing two different algorithms with one word.
  # The engine already reports it; this only reads it back. It is a
  # property of the LEG, not of the tool, so it is spelled `our_arm` and
  # is printed on the rival rows too - those rows say which solve OUR
  # engine would take on the set the rival is being timed over.
  arm=unasked
  if [ "${ARMPROBE:-1}" = 1 ] && [ "$leg" != verify ]; then
   rm -rf "$WORK"
   cp -c -R "$rig/$src" "$WORK" 2>/dev/null || cp -R "$rig/$src" "$WORK"
   arm=$( (cd "$WORK" && NZBFAST_REPAIR_TIMING=1 "$OURS" "$WORK" 2>&1 > /dev/null) \
          | sed -n 's/.*back-substitution setup ([0-9x]*, \([a-z-]*\)).*/\1/p' | head -1)
   [ -n "$arm" ] || arm=none
  fi
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
   cp -c -R "$rig/$src" "$WORK" 2>/dev/null || cp -R "$rig/$src" "$WORK"
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
    # --- rival-survey arms (see the env block above) ---------------------
    tbb)      LD_LIBRARY_PATH=$TBBLIB "$PAR2TBB" r -q "$par" > /dev/null 2> "$WORK/../last.err" ;;
    gopar)    "$GOPAR" r "$par" > /dev/null 2> "$WORK/../last.err" ;;
    par2rs)   "$PAR2RS" r "$par" > /dev/null 2> "$WORK/../last.err" ;;
    turbo120) "$TURBO120" r -q "$par" > /dev/null 2>&1 ;;
    turbo120_16) "$TURBO120" r -q -T16 "$par" > /dev/null 2>&1 ;;
    *) echo "unknown tool $tool" >&2; false ;;
   esac
   rc=$?
   t1=$(now)
   # rc is on the line because a rival that cannot READ the set exits
   # non-zero in milliseconds, and sha_ok alone then reads as a verify
   # pass on the verify leg (the payload was never touched).
   # `label` and `dmg` are on the line because the leg KEY has proved a
   # bad label twice: `heavy` named a 9.2% repair for months, and the
   # same key runs a different solve arm on different parts. Keys stay
   # stable (five boxes hold `damaged-heavy` directories and every
   # historical log names them); the line now carries what the key means.
   # Every field is space-free so a kv reader can split on whitespace.
   printf "LEG r=%d pos=%d leg=%-13s label=%-17s dmg=%-6s our_arm=%-12s tool=%-8s wall=%.3f sha_ok=%s/%s rc=%d\n" \
     "$r" "$pos" "$leg" "$label" "$dmg" "$arm" "$tool" "$(echo "$t1 - $t0" | bc)" "$(sha_ok)" "$total" "$rc"
   [ -n "${TIMING:-}" ] && [ -f "$WORK/../last.err" ] && \
     grep repair-timing "$WORK/../last.err" | sed 's/.*repair-timing: /    /'
   cd - > /dev/null || exit 1
  done
 done
done
rm -rf "$WORK"
