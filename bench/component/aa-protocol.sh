#!/bin/sh
# A/A protocol probe (macOS/Unix half). Races ONE binary against a
# BYTE-IDENTICAL COPY of itself over the short stored shapes, under each
# candidate harness protocol in turn, so the answer to "is a two-arm race on
# this box separable at all" is measured rather than assumed.
#
# Written 3 Sep 2026 for the shootout-position-bias lane. Read
# bench/component/aa-position.py's docstring for what the output means and
# what "flat" is; the Windows twin is aa-protocol.ps1 and must stay in step.
#
#   SR=~/shapes-round BIN=$SR/bin/prodrar-base OUT=$SR/log ./aa-protocol.sh
#
# Every arm is the same six rounds over the same three shapes. Only the
# protocol changes, so a difference between arms is the protocol.
set -eu
SR=${SR:-$HOME/shapes-round}
BIN=${BIN:-$SR/bin/prodrar-base}
OUT=${OUT:-$SR/log}
SHOOT=${SHOOT:-$SR/bin/shootout}
SHAPES=${SHAPES:-storev,encstore,encstorep}
ROUNDS=${ROUNDS:-6}
SETTLE=${SETTLE:-3000}
TAG=${TAG:-aa}

mkdir -p "$OUT" "$SR/work/aa"
# The two arms are the same bytes. Copy rather than symlink: a symlink can be
# resolved to one path by the OS page cache and turn the A/A into a control
# against itself in a way that hides exactly what this probe measures.
cp -f "$BIN" "$SR/bin/${TAG}-arm1"
cp -f "$BIN" "$SR/bin/${TAG}-arm2"
cmp "$SR/bin/${TAG}-arm1" "$SR/bin/${TAG}-arm2" || { echo "arms differ"; exit 1; }

run() {
  name=$1; shift
  echo "=== $name: $* ==="
  "$SHOOT" race --shapes "$SR/shapes" --work "$SR/work/aa" \
    --manifest "$SR/manifest.txt" --rounds "$ROUNDS" \
    --tools ours-${TAG}1,ours-${TAG}2 --only "$SHAPES" \
    --tool-bin ours-${TAG}1="$SR/bin/${TAG}-arm1" \
    --tool-bin ours-${TAG}2="$SR/bin/${TAG}-arm2" \
    "$@" > "$OUT/$TAG-$name.log" 2>&1
  tail -1 "$OUT/$TAG-$name.log"
}

# One THROWAWAY round first. A freshly written executable is scanned on its
# first execution (Defender on Windows, and the same argument holds for any
# first-touch cost here), and that scan lands entirely on whichever arm runs
# first - which is the bias this probe exists to measure.
echo "=== warmup (discarded) ==="
"$SHOOT" race --shapes "$SR/shapes" --work "$SR/work/aa" \
  --manifest "$SR/manifest.txt" --rounds 1 \
  --tools ours-${TAG}1,ours-${TAG}2 --only "$SHAPES" \
  --tool-bin ours-${TAG}1="$SR/bin/${TAG}-arm1" \
  --tool-bin ours-${TAG}2="$SR/bin/${TAG}-arm2" \
  > "$OUT/$TAG-warmup-discarded.log" 2>&1

run p0-rotate
run p1-mirror --layout mirror
run p2-rotate-settle --settle-ms "$SETTLE"
run p3-mirror-settle --layout mirror --settle-ms "$SETTLE"
echo "logs in $OUT/$TAG-p*.log"
