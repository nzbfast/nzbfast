#!/bin/bash
# Build the PAR2 CEILING rig: the damage rungs the published shootout
# corpus physically cannot reach.
#
#   par2rig-ceiling.sh <root> <payload-file> <creator> <turbo>
#
# WHY A SECOND RIG EXISTS. `par2rig-build.sh` makes two sets at 10%
# redundancy, and 10% parity cannot repair more than 10% of its inputs.
# So every leg that rig can hold tops out around 9-10% damaged, however
# it is labelled: `101` is 9.9% of a 1,024-block set and the leg we
# called "heavy" is 9.2% of a 16,384-block one. They differ in BLOCK
# SIZE, and so in m, not in how badly the set is hurt. To ask what a
# badly damaged set costs, the fixture has to carry the parity for it.
#
# THE SHAPE. One set at the PAR2 spec ceiling, with the block size and
# the input count HELD CONSTANT so the only thing the rungs vary is the
# damage:
#
#   N = 32,768 input blocks of 64 KiB  = 2 GiB payload
#   R = 32,768 recovery blocks         = 2 GiB parity (100% redundancy)
#
# 32,768 is not a round number picked for effect: PAR2 addresses input
# slices with the naturals below 65,535 coprime to it (65,535 = 3*5*17*257),
# and there are exactly 32,768 of them. Recovery slices are capped at the
# same count. So N = R = 32,768 with every input block missing is THE
# HEAVIEST REPAIR THAT CAN EXIST in the format - one recovery block
# short of it and the set is simply unrecoverable.
#
# THE RUNGS, and note that they are NOT in cost order:
#
#   d25   8,192 blocks   25%   a lot of damage
#   d50  16,384 blocks   50%   extreme damage - THE SLOWEST, see below
#   d100 32,768 blocks  100%   the most damage still recoverable
#
# A repair's fold work is `m * (N - m)` block folds: every surviving
# block folded into every syndrome. That product PEAKS AT m = N/2 and is
# ZERO at m = N, because a set with nothing left has nothing to fold -
# the whole repair collapses to the solve. So d50 is roughly 268M block
# folds and d100 is under 8M, and the ladder's last rung is FASTER than
# the one before it. That is arithmetic, not a measurement error, and a
# table that hides it will read as one.
#
# THE TWO GAPPED RUNGS ARE A DIFFERENT AXIS ENTIRELY. Everything above
# damages DATA. These damage the RECOVERY SET, which is what a bad
# provider fill actually produces, and it is the worst case in this
# whole file:
#
#   gapped        m = 4,000, recovery volumes deleted at random
#   gapped-refuse m = 10,000, same
#
# When recovery packets are themselves missing the surviving exponents
# are no longer consecutive. `A` becomes a generalized Vandermonde with
# no factorization, so BOTH transforms are lost at once: no Forney (the
# solve falls back to the dense product) and no `invert_vandermonde`
# (the inverse falls back to Gauss-Jordan, `O(m^3)` scalar). And because
# the dense arm is capped at `MAX_REPAIR_DIM` = 8,192, the second rung
# is REFUSED outright by us - `gapped-refuse` exists to measure a leg we
# decline and par2cmdline completes, which is a product gap and not a
# benchmark result. Delete the volumes AT RANDOM: the engine relabels an
# arithmetic progression of exponents back into a consecutive one
# (`progression_parameters`, `NZBFAST_RS_PROGRESSIONS`), so deleting
# every other volume would quietly stay on the fast path and measure
# nothing.
#
# THE SET IS CREATED BY OUR OWN CREATOR AND THEN GATED ON A RIVAL. At
# 100% redundancy the create is 32,768 x 32,768 block folds, which
# par2cmdline-turbo takes tens of minutes to do and ours takes about
# half a minute. Creating it with ours would be a fair repair fixture
# only if the set is genuinely spec-conformant, so the build REFUSES
# unless par2cmdline-turbo verifies it clean first. A set only our own
# reader accepts is not a benchmark, it is a mirror.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)

ROOT=${1:?usage: par2rig-ceiling.sh <root> <payload> <creator> <turbo>}
PAYLOAD=${2:?need a payload file}
CREATOR=${3:?need a par2_create_bench build}
TURBO=${4:?need a par2cmdline-turbo, to gate the set}

# The published shape. Overridable ONLY so the selftest below can drive
# the same code over a set small enough to build in seconds - a round
# that reports these legs must use the defaults, because the whole point
# of the rung names is that they mean one fixed thing.
BS=${CEILING_BS:-65536}
NBLOCKS=${CEILING_NBLOCKS:-32768}
WANT=$((BS * NBLOCKS))          # 2 GiB exactly at the defaults
SCALE=$((NBLOCKS * 100 / 32768))   # percent of the published size, for the damage counts
# 16 files of 2,048 blocks at the published size: enough members that a
# damage map spreads the way a thinned fill does, few enough that the
# per-file verify overhead is not what the round measures.
NVOL=${CEILING_NVOL:-16}
BLOCKS_PER_VOL=$((NBLOCKS / NVOL))
[ $((BLOCKS_PER_VOL * NVOL)) = "$NBLOCKS" ] || {
  echo "NBLOCKS ($NBLOCKS) must divide by NVOL ($NVOL)" >&2; exit 2; }

sz=$(wc -c < "$PAYLOAD" | tr -d ' ')
[ "$sz" -ge "$WANT" ] || { echo "payload is $sz bytes, need >= $WANT" >&2; exit 2; }

rm -rf "$ROOT"
mkdir -p "$ROOT/pristine"

echo "== payload: $NVOL files of exactly $((BLOCKS_PER_VOL)) blocks"
# PLAIN SPLIT FILES, NOT RAR VOLUMES, and that is the one place this rig
# deliberately departs from par2rig-build.sh. The rung this fixture
# exists for is N = 32,768 EXACTLY - the PAR2 input-slice ceiling - and a
# RAR container adds its own header bytes, so a payload sized to
# `bs * 32,768` comes back as a 32,769-block archive. Measured in this
# script's own selftest: 512 requested blocks produced 513. One block
# over the ceiling is not a slower set, it is an INVALID one that no
# reader may accept. Sizing files to a whole multiple of the block size
# makes the count exact by construction instead of by luck.
#
# Nothing about the repair cares: PAR2 sees files and blocks, and the
# damage maps below address blocks. The payload must still be genuinely
# random for the reason par2rig-build.sh gives - periodicity inflates
# par2cmdline-turbo's sliding scan and flatters us.
for ((v = 0; v < NVOL; v++)); do
  dd if="$PAYLOAD" of="$ROOT/pristine/$(printf 'set.%03d.bin' "$v")" \
     bs="$BS" skip=$((v * BLOCKS_PER_VOL)) count="$BLOCKS_PER_VOL" \
     status=none
done
echo "   files: $(ls "$ROOT"/pristine/*.bin | wc -l | tr -d ' ')"
inputs=$(python3 -c "
import os,sys,glob
bs=int(sys.argv[1]); d=sys.argv[2]
print(sum(-(-os.path.getsize(f)//bs) for f in glob.glob(os.path.join(d,'*.bin'))))
" "$BS" "$ROOT/pristine")
echo "   input blocks: $inputs (want $NBLOCKS)"
[ "$inputs" = "$NBLOCKS" ] || {
  echo "REFUSED: the payload is $inputs blocks, not $NBLOCKS." >&2
  exit 2
}

echo "== ceiling PAR2 ($((BS / 1024)) KiB blocks, 100% redundancy, $NBLOCKS recovery blocks)"
# Create into a SEPARATE directory and move the packets in afterwards.
# The creator takes every regular file in its source directory as a
# member, so creating in place would feed it its own output on any
# re-run and silently build a set over the parity as well as the data.
mkdir -p "$ROOT/parout"
"$CREATOR" "$ROOT/pristine" "$ROOT/parout" 100 "$BS"
ls "$ROOT/parout"/*.par2 > /dev/null 2>&1 || { echo "creator wrote no par2 files" >&2; exit 2; }
mv "$ROOT/parout"/*.par2 "$ROOT/pristine/"
rmdir "$ROOT/parout"

# The recovery count is the whole premise of the d100 rung, so assert it
# rather than assume it: `set.volAAA+BB.par2` names BB recovery blocks,
# and the sum has to be exactly NBLOCKS. One short and d100 is
# unrepairable (which is a different leg); one over and the set is past
# the PAR2 recovery-slice ceiling and no reader should accept it.
recov=$(ls "$ROOT/pristine"/*.par2 \
  | sed -n 's/.*vol[0-9][0-9]*+0*\([0-9][0-9]*\)\.par2$/\1/p' \
  | awk '{s += $1} END {print s + 0}')
echo "   recovery blocks: $recov (want $inputs, one per input block)"
[ "$recov" = "$inputs" ] || {
  echo "REFUSED: the set carries $recov recovery blocks for $inputs input blocks." >&2
  echo "  d100 needs exactly one recovery block per input block." >&2
  exit 2
}

echo "== rival gate: par2cmdline-turbo must verify the set clean"
if ! ( cd "$ROOT/pristine" && "$TURBO" v -q ./*.par2 > "$ROOT/turbo-verify.log" 2>&1 ); then
  echo "REFUSED: par2cmdline-turbo will not verify the set we created." >&2
  echo "  see $ROOT/turbo-verify.log - do not benchmark a set only we can read." >&2
  exit 2
fi
echo "   turbo verifies it clean"

( cd "$ROOT/pristine" && shasum -a 256 ./*.bin > "$ROOT/pristine.sha" )

# --- data damage: flip one byte in the middle of N evenly spaced blocks
damage() { # damage <dst> <nblocks>
  local dst=$1 n=$2
  rm -rf "$dst"; cp -R "$ROOT/pristine" "$dst"
  python3 - "$dst" "$BS" "$n" <<'PY'
import os, sys
d, bs, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
vols = sorted(f for f in os.listdir(d) if f.endswith('.bin'))
sizes = [os.path.getsize(os.path.join(d, v)) for v in vols]
blocks = [s // bs for s in sizes]
total = sum(blocks)
if n > total:
    raise SystemExit(f"asked for {n} damaged blocks, the set holds {total}")
# Spread proportionally over every volume, evenly spaced inside each, so
# the damage is a uniform thinning of the set rather than a burst. A
# burst and a spread cost the same to REPAIR (m is m), but a spread is
# what a thinned provider fill looks like and it keeps every volume in
# play for the verify pass.
hit = 0
for vi, v in enumerate(vols):
    want = n * blocks[vi] // total
    if vi == len(vols) - 1:
        want = n - hit
    if want <= 0:
        continue
    p = os.path.join(d, v)
    with open(p, 'r+b') as f:
        for k in range(want):
            b = (k * blocks[vi]) // want
            off = b * bs + bs // 2
            if off + 1 > sizes[vi]:
                continue
            f.seek(off)
            byte = f.read(1)
            f.seek(off)
            f.write(bytes([byte[0] ^ 0xFF]))
            hit += 1
print(f"   damaged {hit} blocks across {len(vols)} volumes")
PY
}

echo "== damage maps"
damage "$ROOT/damaged-d25" $((NBLOCKS / 4))
damage "$ROOT/damaged-d50" $((NBLOCKS / 2))

echo "== d100: every data file deleted (the most damage still recoverable)"
rm -rf "$ROOT/damaged-d100"; cp -R "$ROOT/pristine" "$ROOT/damaged-d100"
rm -f "$ROOT/damaged-d100"/*.bin

# --- recovery damage: gap the recovery EXPONENTS at slice granularity
gapped() { # gapped <dst> <ndamaged-data-blocks> <max-run> <seed>
  local dst=$1 n=$2 maxrun=$3 seed=$4
  damage "$dst" "$n"
  python3 "$HERE/par2-gap-recovery.py" "$dst" --max-run "$maxrun" --seed "$seed"
}

echo "== gapped recovery sets (the recovery set damaged too)"
# `--max-run` is set to HALF the leg's m, so the repair cannot find a
# consecutive run of m and must take the unstructured path. Deleting
# whole recovery volumes does NOT achieve this and the first version of
# this script was wrong about it - see par2-gap-recovery.py's header,
# which records what its own selftest disproved.
gapped "$ROOT/damaged-gapped"        $((4000 * SCALE / 100))  $((2000 * SCALE / 100))  20260908
gapped "$ROOT/damaged-gapped-refuse" $((10000 * SCALE / 100)) $((5000 * SCALE / 100))  20260908

echo "== done"
du -sh "$ROOT"/*/ 2>/dev/null
