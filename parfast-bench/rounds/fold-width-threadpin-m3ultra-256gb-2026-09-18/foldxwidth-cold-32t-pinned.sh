#!/bin/zsh
# The fold-team WIDTH sweep at the clamp-floor window with the POOL PINNED, on
# apple-m3-ultra, behind TODO 1 of
# an internal note and claim
# `fold-width-threadcount-pin-apple-m3-ultra-18sep` (gen da2bcff7).
#
# SIBLING of `foldxwidth-cold-32t.sh`, which is itself a sibling of the 20t
# one. NOT AN EDIT OF EITHER, which is section 10.2's precedent and stated in
# the handoff's own "how to run it": editing a landed script in place silently
# re-labels its landed logs.
#
# THE QUESTION. apple-m1-ultra-64gb is 20 threads AND an M1 Ultra; apple-m3-ultra is 32
# threads AND an M3 Ultra. At the `repair_cap()` clamp floor (a 2.67 MiB
# window) they disagree about the fold-team width constant: section 13.5's cold
# sweep here reads 1.000 / 0.976 / 0.972 / 0.996 / 1.215 at widths 1/2/3/4/8,
# where section 12.5 on 20 threads read 1.000 / 1.019 / 1.200 / 1.146 / 1.215 -
# two rungs WIN here and none wins there. Thread count and microarchitecture
# are confounded in every cell of both rounds and 13.13 has ruled out the cheap
# bytes-per-member re-frame. Pinning THIS pool to 20 separates them on ONE box.
#
# WHY RAYON_NUM_THREADS IS THE RIGHT KNOB HERE. It sizes the WHOLE process
# pool. At the floor window the widths under test are 1 to 8, far under either
# thread count, so `stripe_len_for_budget`'s `(window / 4 MiB).clamp(1,
# threads)` term is irrelevant at every rung and this arm moves the POOL WIDTH
# rather than the clamp. That is exactly the axis the confound needs.
#
# WHAT CHANGES FROM THE 32t SCRIPT, and nothing else does:
#   1. `arm()` carries RAYON_NUM_THREADS=$PIN, so it lands on BOTH arms of
#      every cell - never on one, which would make every cell a pin A/B.
#   2. P0 is new: the two proofs the pin owes before a rung is read off it.
#   3. P1 is X4's sweep run at a given pin; P2 interleaves the two pins rung by
#      rung so a foreign burst is common-mode across the comparison that
#      matters.
#
# THE TWO PROOFS P0 OWES, and they are different claims:
#   (a) POSITIVE CONTROL. Pinned to the box's own 32, the sweep must reproduce
#       section 13.5's banked cold row within its error bar. If pinning to 32
#       changes the answer, the knob is the experiment and nothing after it
#       means anything. The handoff says do not skip this and the
#       neon-create-width-thread-count round of 16 Sep is the precedent.
#   (b) NOT-INERT. A pin that is silently ignored ALSO reproduces the banked
#       row, so (a) alone cannot tell a working knob from a dead one. P0b puts
#       the two pins head to head at the CAP window at width 64 (2 MiB a
#       piece), where the work is pool-bound and 20 threads against 32 must
#       NOT read 1.00.
#
# Box: apple-m3-ultra (M3 Ultra, 32 threads, 256 GB, macOS 27.0). Claimed in
# ~/bench-out/COORDINATION-apple-m3-ultra.txt AND under ~/.parfast-rig.lock naming
# a LIVE pid (bench-suite item 0e). NOTHING IS BUILT HERE: one
# aarch64-apple-darwin test binary built on the session box with
#   cargo test --release -p nzbfast-unpack --lib --features fold-team-probe --no-run
# copied in as ./unpack-test, sha256 checked at both ends. revscan-ab.py
# imports coldcache.py - BOTH are copied in.
#
# NO CONSTANT MOVES off this round. All three knobs already exist:
# NZBFAST_REV_FOLD_WINDOW_KIB is PRODUCTION (rarfix.rs:784),
# RARS_STRIPED_FOLD_TEAM_WIDTH and RARS_STRIPED_FOLD_MIN_WINDOW are the
# non-default `fold-team-probe` knobs. `vendor/rars/src/recovery/rar5.rs` is a
# CLEAN-ROOM file and is not opened by this lane at all.
set -e
cd "$(dirname "$0")"

ON=0
BUDGET=2048
RUNS=${RUNS:-32}
PIN=${PIN:-32}

W_CAP=524288      # KiB, 512 MiB: the shipped repair cap
W_FLOOR=8192      # KiB, 8 MiB: repair_cap()'s clamp floor, and REV_FOLD_WINDOW

TEAM="RARS_STRIPED_FOLD_MIN_WINDOW=$ON"

# THE PIN LANDS HERE, so it is on both arms of every cell by construction.
arm() {  # arm <window KiB> <width> [pin]
  echo "$TEAM,NZBFAST_REV_FOLD_WINDOW_KIB=$1,RARS_STRIPED_FOLD_TEAM_WIDTH=$2,RAYON_NUM_THREADS=${3:-$PIN}"
}

prep() {
  pmset displaysleepnow || true
  for spec in ${PREP_SETS:-4x128}; do
    [[ -d $PWD/set-$spec ]] && { echo "have set-$spec"; continue; }
    REVSCAN_SET=$PWD/set-$spec REVSCAN_SIZES=$spec REVSCAN_REV=2 \
      ./unpack-test --ignored --exact --nocapture \
      rarfix::rarfix_rev_recovery_tests::revscan_build_set
  done
  touch .metadata_never_index
  du -sh set-* | sed 's/^/  /'
  echo "fixture root guarded: $(ls -la .metadata_never_index)"
}

# ab <label> <set> <cache> <base env> <new env> [runs]
ab() {
  local label=$1 set=$2 cache=$3 benv=$4 nenv=$5 runs=${6:-$RUNS}
  echo "=== $label   set=$set cache=$cache runs=$runs   box_before: $(uptime | sed 's/.*averages://')   foreign_1core: $(ps -Ao pcpu,comm | sort -rn | head -1 | tr -s ' ')"
  python3 revscan-ab.py --base ./unpack-test --new ./unpack-test \
    --set $set --drop 2 --runs $runs --label "$label" --cache $cache \
    --base-env REVSCAN_BUDGET_MIB=$BUDGET,$benv \
    --new-env  REVSCAN_BUDGET_MIB=$BUDGET,$nenv
  echo "    box_after: $(uptime | sed 's/.*averages://')"
  echo
}

# P0a: THE POSITIVE CONTROL. X4's sweep with the pin set to the box's own 32.
# Every rung must land on section 13.5's banked cold row within its error bar.
rounds_p0a_positive_control_32() {
  PIN=32
  for w in 2 3 4 8; do
    ab "P0a-128m-cold-PIN32-floor-w1-vs-w$w" set-4x128 cold \
      "$(arm $W_FLOOR 1 32)" "$(arm $W_FLOOR $w 32)"
  done
  ab "P0a-128m-cold-PIN32-AA-floor-w1" set-4x128 cold "$(arm $W_FLOOR 1 32)" "$(arm $W_FLOOR 1 32)"
  pmset displaysleepnow || true
}

# P0b: THE NOT-INERT PROOF. Same width, same window, ONLY the pin moves, at a
# place where the work is pool-bound: the cap window (128 MiB) at width 64, so
# 64 pieces are handed to a pool of 32 against a pool of 20. This is the ONE
# cell in the round that is deliberately a pin A/B, and it must NOT read 1.00.
# The A/A beside it is the control that says so.
rounds_p0b_not_inert() {
  ab "P0b-128m-cold-cap-w64-PIN32-vs-PIN20" set-4x128 cold \
    "$(arm $W_CAP 64 32)" "$(arm $W_CAP 64 20)"
  ab "P0b-128m-cold-cap-w64-AA-PIN32"       set-4x128 cold \
    "$(arm $W_CAP 64 32)" "$(arm $W_CAP 64 32)"
  pmset displaysleepnow || true
}

# P0c: THE SECOND NOT-INERT CELL, and it is here because the first one answered
# in the CPU column alone. P0b's cap-window w64 cell reads wall 1.000 with
# process CPU 405.5 against 310.2 ms - a 23.5% move against a CPU A/A of 0.6%,
# which proves the pin reaches the pool and ALSO says that cell is not
# wall-pool-bound. This one is: the floor window at width 8 is the rung section
# 13.5 priced at +381% CPU, so 8 pieces over a pool of 20 against 32 is where a
# pool size should show in WALL as well.
rounds_p0c_not_inert_floor_w8() {
  ab "P0c-128m-cold-floor-w8-PIN32-vs-PIN20" set-4x128 cold \
    "$(arm $W_FLOOR 8 32)" "$(arm $W_FLOOR 8 20)"
  ab "P0c-128m-cold-floor-w8-AA-PIN32"       set-4x128 cold \
    "$(arm $W_FLOOR 8 32)" "$(arm $W_FLOOR 8 32)"
  pmset displaysleepnow || true
}

# P1: the sweep at ONE pin, both cache modes. `PIN=20 ... rounds_p1_sweep`.
rounds_p1_sweep() {
  for c in ${=MODES:-cold}; do   # ${=} deliberately: zsh does NOT word-split an unquoted parameter
    for w in 2 3 4 8; do
      ab "P1-128m-$c-PIN$PIN-floor-w1-vs-w$w" set-4x128 $c \
        "$(arm $W_FLOOR 1)" "$(arm $W_FLOOR $w)"
    done
    ab "P1-128m-$c-PIN$PIN-AA-floor-w1" set-4x128 $c "$(arm $W_FLOOR 1)" "$(arm $W_FLOOR 1)"
    pmset displaysleepnow || true
  done
}

# P2: THE ROUND THAT ANSWERS THE QUESTION. The two pins INTERLEAVED rung by
# rung rather than as two blocks, so a foreign burst spanning a cell moves the
# 20- and 32-thread readings of the SAME rung together and cancels in the
# comparison that matters. Both A/As are taken at the ends.
#
# Every cell is `w1 against w<n>` AT ONE PIN - the pin is on both arms, so what
# each cell reports is that pin's own bowl, and the two bowls are then read
# against each other. That is deliberately NOT a pin A/B: a pin A/B at a single
# width would confound the bowl's shape with the pool's raw speed.
rounds_p2_interleaved() {
  for c in ${=MODES:-cold}; do   # ${=} deliberately: zsh does NOT word-split an unquoted parameter
    ab "P2-128m-$c-PIN32-AA-floor-w1-head" set-4x128 $c "$(arm $W_FLOOR 1 32)" "$(arm $W_FLOOR 1 32)"
    ab "P2-128m-$c-PIN20-AA-floor-w1-head" set-4x128 $c "$(arm $W_FLOOR 1 20)" "$(arm $W_FLOOR 1 20)"
    for w in 2 3 4 8; do
      ab "P2-128m-$c-PIN32-floor-w1-vs-w$w" set-4x128 $c \
        "$(arm $W_FLOOR 1 32)" "$(arm $W_FLOOR $w 32)"
      ab "P2-128m-$c-PIN20-floor-w1-vs-w$w" set-4x128 $c \
        "$(arm $W_FLOOR 1 20)" "$(arm $W_FLOOR $w 20)"
    done
    ab "P2-128m-$c-PIN20-AA-floor-w1-tail" set-4x128 $c "$(arm $W_FLOOR 1 20)" "$(arm $W_FLOOR 1 20)"
    ab "P2-128m-$c-PIN32-AA-floor-w1-tail" set-4x128 $c "$(arm $W_FLOOR 1 32)" "$(arm $W_FLOOR 1 32)"
    pmset displaysleepnow || true
  done
}

# P3: THE PIN LADDER AT THE RUNG THAT DISAGREES MOST, which asks the one
# question P2 leaves open: is 20 a SPECIAL point, or is the pool size simply a
# weak monotone term here? P2 finds the M3's w3 win getting slightly DEEPER as
# the pool shrinks (0.973 at 32, 0.967 at 20), which is the wrong sign for
# explaining apple-m1-ultra-64gb's 1.200. If that trend continues to 12 and 8 the term is
# monotone and small; if it turns over at some pool size, 20 was special after
# all and P2's reading needs qualifying. Each cell is w1-against-w3 AT ONE PIN,
# so the pin is on both arms exactly as in P2.
rounds_p3_pin_ladder_at_w3() {
  ab "P3-128m-cold-PIN32-AA-floor-w1-head" set-4x128 cold "$(arm $W_FLOOR 1 32)" "$(arm $W_FLOOR 1 32)"
  for p in 32 20 12 8 4; do
    ab "P3-128m-cold-PIN$p-floor-w1-vs-w3" set-4x128 cold \
      "$(arm $W_FLOOR 1 $p)" "$(arm $W_FLOOR 3 $p)"
  done
  ab "P3-128m-cold-PIN32-AA-floor-w1-tail" set-4x128 cold "$(arm $W_FLOOR 1 32)" "$(arm $W_FLOOR 1 32)"
  pmset displaysleepnow || true
}

"$@"
