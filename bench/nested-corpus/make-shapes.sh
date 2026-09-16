#!/bin/zsh
# make-shapes.sh - build the stored-RAR shapes smallart.sh drives.
#
# smallart.sh's header said the shapes were "built by hand beside it".
# That sentence cost the 16 Sep 2026 lane most of a session and had
# already cost the serial-bound survey the whole item: its entry 7
# recorded the pending_r residue as unmeasurable because "reproducing
# the shape needs a posted many-small-member RAR set ... and that is a
# chip of its own", when in fact round 23's rig was already in the tree
# and only the 1 GiB binaries were missing (they are gitignored, and
# rightly). Shapes are deterministic given the payload, so there is no
# reason for the next lane to re-derive the rar(1) lines from prose.
#
#   R=<rigdir> [SIZE=1024] [SHAPES="onebig manysmall ms2m ms128k"] ./make-shapes.sh
#
# Writes $R/payload/rand.bin (SIZE MiB, made once and reused), the
# member trees under $R/src-<shape>/, and the volumes at
# $R/shapes/<shape>/*.rar, which is the layout smallart.sh expects.
#
# All four are STORED (-m0): the point of these shapes is the
# per-ARTICLE and per-MEMBER cost of the one-pass path, so compression
# would only add a term that has nothing to do with what they measure.
#
# Needs rar(1) (`brew install rar`). Roughly 2x SIZE of disk per shape
# (the split member tree plus the volumes), and the payload again.
set -u
R=${R:?set R to the rig directory}
SIZE=${SIZE:-1024}
SHAPES=${SHAPES:-"onebig manysmall"}
mkdir -p $R/payload $R/shapes
if [ ! -f $R/payload/rand.bin ]; then
  dd if=/dev/urandom of=$R/payload/rand.bin bs=1m count=$SIZE 2>&1 | tail -1
fi
for shape in ${=SHAPES}; do
  # member size in bytes, and the volume size rar is given. onebig is
  # the per-ARTICLE axis (one member, nothing to park); the other three
  # are the per-MEMBER ladder.
  case $shape in
    onebig)    msize=0       vol=50m ;;
    ms2m)      msize=2097152 vol=20m ;;
    manysmall) msize=524288  vol=20m ;;
    ms128k)    msize=131072  vol=20m ;;
    *) echo "unknown shape $shape"; exit 2 ;;
  esac
  d=$R/src-$shape
  mkdir -p $d $R/shapes/$shape
  if [ -z "$(ls -A $R/shapes/$shape 2>/dev/null)" ]; then
    if [ $msize -eq 0 ]; then
      [ -f $d/rand.bin ] || cp -c $R/payload/rand.bin $d/rand.bin 2>/dev/null || cp $R/payload/rand.bin $d/rand.bin
    else
      # -a 4 keeps the names four digits wide, so 8,192 members still
      # sort and the NZB subject ordering matches the on-disk one.
      [ "$(ls $d | wc -l | tr -d ' ')" -ge 1 ] || split -b $msize -a 4 -d $R/payload/rand.bin $d/f
    fi
    ( cd $d && rar a -m0 -v$vol -ep -idq $R/shapes/$shape/m.rar . )
  fi
  echo "SHAPE $shape members=$(ls $d | wc -l | tr -d ' ') vols=$(ls $R/shapes/$shape | wc -l | tr -d ' ')"
done
