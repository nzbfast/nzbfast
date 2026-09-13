#!/bin/bash
# Build the ten SCENARIO fixtures - the shapes the published PAR2 numbers are
# measured on, each one a download a reader would recognise rather than a block
# count.
#
#   par2-scenarios-build.sh <root> [rar] [par2-creator] [corpusgen]
#
# Every payload is a prefix of the ONE fixed-seed stream `corpusgen` writes
# (`corpusgen rand <file> <bytes>`, seed 0xC0FFEE01), so the fixtures are
# byte-identical on every machine and rand.bin is their common head. The
# payload must be truly random: a payload with short periodicity inflates
# par2cmdline-turbo's sliding-scan work and has flattered us by ~7% on the
# heavy leg.
#
# THE SETS ARE CREATED BY THE RIVAL, par2cmdline-turbo, on purpose. A shootout
# whose fixtures came out of our own creator invites the obvious question about
# whose block layout the repair arm is tuned for, and answering it later costs
# more than the build time does now. Pass a different creator as $3 if you want
# to check that the answer does not move (it should not; PAR2 is a wire format
# and every set here verifies under all three tools).
#
# Sizes and redundancies are the census modes measured 6 Sep 2026 over 189
# random PAR2-bearing releases (research/PARFAST-PUBLIC-SCENARIOS-2026-09-06.md):
# 10-15% redundancy is the largest bucket, 0.5-1.5 MiB the largest slice
# bucket, 2k-10k data blocks where two thirds of sets sit. Row 8's 5% / 512 KiB
# and row 10's 2% / 1.2 MB are the small-post and bare-media tails of the same
# survey; row 5's 100/110% has NO measured wild population and is kept as the
# transform-bound extreme, which the results page must say out loud.
#
# Damage is applied separately, in ARTICLE units, by `apply-damage.py` reading
# the `amap-*.txt` maps beside this script. Nothing here damages anything: a
# fixture that ships pre-damaged cannot be re-cut when a map changes.
set -euo pipefail

ROOT=${1:?usage: par2-scenarios-build.sh <root> [rar] [par2-creator] [corpusgen]}
RAR=${2:-rar}
# Two knobs for a rig that is not this Mac:
#   NORAR=1        no `rar` on the box - split the payload into equal members
#                  named like the volumes instead. Store-mode RAR volumes are
#                  a thin header over the payload, and PAR2 does not care, so
#                  the shape (member count, sizes, block counts) is preserved.
#                  The BYTES are not the M3's, so a number from such a box is
#                  read within its own box only - which the README already
#                  requires of the three rigs.
#   SKIP_DAMAGED=1 build only the pristine fixtures. `round2.sh` cuts each
#                  row's damage into its work copy from the map instead, which
#                  is what a box without cheap clones wants: the eight damaged
#                  trees are free on APFS and are eight real copies on NTFS.
NORAR=${NORAR:-0}
SKIP_DAMAGED=${SKIP_DAMAGED:-0}
PAR2=${3:-par2turbo150}
CORPUSGEN=${4:-$ROOT/bin/corpusgen}
HERE=$(cd "$(dirname "$0")" && pwd)

# The yEnc article payload size the maps are cut in. 768000 B = 750 KiB is the
# modern posting default; an article is 700-800 KB on the posts the census read.
ART=768000

mkdir -p "$ROOT" "$ROOT/payload"

if [ ! -x "$CORPUSGEN" ]; then
  mkdir -p "$(dirname "$CORPUSGEN")"
  echo "== building corpusgen"
  rustc -O --edition 2021 -o "$CORPUSGEN" "$HERE/corpusgen.rs"
fi

gen() { # gen <file> <bytes>
  [ -f "$1" ] && [ "$(wc -c < "$1")" = "$2" ] && return 0
  "$CORPUSGEN" rand "$1" "$2"
}

volumes() { # volumes <payload> <outdir> <stem> <count> <vol-size>
  local payload=$1 out=$2 stem=$3 count=$4 vsize=$5
  mkdir -p "$out"
  if [ "$NORAR" = "0" ]; then
    ( cd "$(dirname "$payload")" && "$RAR" a -idq -ep -m0 -tsm- -tsc- -tsa- \
        -v"$vsize" "$out/$stem.rar" "$(basename "$payload")" )
    return 0
  fi
  # Split fallback: the same volume LAYOUT rar would have written - full
  # members of <vol-size> and a short last one - under the same names, minus
  # the ~50 bytes of RAR header per volume.
  python3 - "$payload" "$out" "$stem" "$vsize" <<'SPLIT'
import os, sys
payload, out, stem, vsize = sys.argv[1:5]
n = int(vsize[:-1]) * (1024 * 1024 if vsize[-1] in "mM" else 1)
with open(payload, "rb") as src:
    i = 0
    while True:
        chunk = src.read(n)
        if not chunk:
            break
        i += 1
        with open(os.path.join(out, "%s.part%02d.rar" % (stem, i)), "wb") as dst:
            dst.write(chunk)
print("   %d split member(s), no rar on this box" % i)
SPLIT
}

# par2cmdline-turbo refuses a member outside its base path and then says
# "You must specify a list of files", which reads like an argument mistake
# and is not one: pass an ABSOLUTE -B and absolute member paths.
create_set() { # create_set <dir> <set-name> <slice> <pct> <member-glob>
  local dir=$1 name=$2 slice=$3 pct=$4 glob=$5
  # shellcheck disable=SC2086
  ( cd "$dir" && "$PAR2" c -q -s"$slice" -r"$pct" -B"$dir" "$dir/$name" $(ls $glob | sed "s|^|$dir/|") )
}

# ---------------------------------------------------------------------------
# Row 1: a TV episode. 1.5 GiB in 21 RAR volumes, 10% at 1 MiB.
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/tv" ]; then
  echo "== row 1: TV episode, 1.5 GiB / 21 volumes"
  gen "$ROOT/payload/tv.bin" $((1536 * 1024 * 1024))
  mkdir -p "$ROOT/tv"
  volumes "$ROOT/payload/tv.bin" "$ROOT/tv" episode 21 75m
  create_set "$ROOT/tv" episode.par2 1048576 10 '*.rar'
fi

# ---------------------------------------------------------------------------
# Rows 2, 3, 4 and 6: ONE movie fixture, four damage shapes over it.
# 10 GiB in 21 RAR volumes, 10% at 1 MiB.
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/movie" ]; then
  echo "== rows 2-4, 6: movie, 10 GiB / 21 volumes"
  gen "$ROOT/payload/movie.bin" $((10240 * 1024 * 1024))
  mkdir -p "$ROOT/movie"
  volumes "$ROOT/payload/movie.bin" "$ROOT/movie" feature 21 500m
  create_set "$ROOT/movie" feature.par2 1048576 10 '*.rar'
fi

# ---------------------------------------------------------------------------
# Row 5: the pars ARE the download. Two shapes, both at 100% and 110%, both
# damaged by deleting every data file.
#
#   pars-single  a 1 GiB single member, the "one mkv" shape
#   pars-multi   the SAME 21 movie volumes, a second set at full redundancy
#
# The multi set reuses the movie's volumes rather than building a third 10 GiB
# payload: it is the same download, posted the other way.
# ---------------------------------------------------------------------------
for pct in 100 110; do
  if [ ! -d "$ROOT/pars-single-$pct" ]; then
    echo "== row 5: pars-only single member, ${pct}%"
    gen "$ROOT/payload/feature.mkv" $((1024 * 1024 * 1024))
    mkdir -p "$ROOT/pars-single-$pct"
    cp -c "$ROOT/payload/feature.mkv" "$ROOT/pars-single-$pct/" 2>/dev/null ||
      cp "$ROOT/payload/feature.mkv" "$ROOT/pars-single-$pct/"
    create_set "$ROOT/pars-single-$pct" feature.par2 1048576 "$pct" 'feature.mkv'
  fi
done
for pct in 100 110; do
  if [ ! -d "$ROOT/pars-multi-$pct" ]; then
    echo "== row 5: pars-only 21 members, ${pct}% (slow: 10k x 10k rows)"
    mkdir -p "$ROOT/pars-multi-$pct"
    for f in "$ROOT/movie"/*.rar; do
      cp -c "$f" "$ROOT/pars-multi-$pct/" 2>/dev/null || cp "$f" "$ROOT/pars-multi-$pct/"
    done
    create_set "$ROOT/pars-multi-$pct" feature.par2 1048576 "$pct" '*.rar'
  fi
done

# ---------------------------------------------------------------------------
# Row 7: the poster's side. 10 x 1 GiB members, created at 1 MiB and 4 MiB.
# No PAR2 set is built here - creating one IS the leg.
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/create" ]; then
  echo "== row 7: create corpus, 10 x 1 GiB"
  mkdir -p "$ROOT/create"
  for i in $(seq -f '%02g' 1 10); do
    gen "$ROOT/create/part$i.bin" $((1024 * 1024 * 1024))
  done
fi

# ---------------------------------------------------------------------------
# Row 8: an album or audiobook. One 600 MiB RAR, 5% at 512 KiB.
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/album" ]; then
  echo "== row 8: album, 600 MiB single RAR"
  gen "$ROOT/payload/album.bin" $((600 * 1024 * 1024))
  mkdir -p "$ROOT/album"
  if [ "$NORAR" = "0" ]; then
    ( cd "$ROOT/payload" && "$RAR" a -idq -ep -m0 -tsm- -tsc- -tsa- "$ROOT/album/album.rar" album.bin )
  else
    cp "$ROOT/payload/album.bin" "$ROOT/album/album.rar"
  fi
  create_set "$ROOT/album" album.par2 524288 5 'album.rar'
fi

# ---------------------------------------------------------------------------
# Row 9: the heavy leg, 1 GiB in 21 volumes at 64 KiB blocks. Kept from the
# original rig unchanged so the published heavy number stays comparable; only
# its TITLE changes. 16k data blocks is the far tail of the census's
# block-count distribution, and the results page says so.
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/heavy" ]; then
  echo "== row 9: heavy, 1 GiB / 21 volumes at 64 KiB"
  gen "$ROOT/payload/rand.bin" $((1024 * 1024 * 1024))
  mkdir -p "$ROOT/heavy"
  volumes "$ROOT/payload/rand.bin" "$ROOT/heavy" set 21 50m
  create_set "$ROOT/heavy" heavy.par2 65536 10 '*.rar'
fi

# ---------------------------------------------------------------------------
# Row 10: a sports broadcast. ONE obfuscated mp4 under a 32-character random
# name, NO RAR, and a small release-named PAR2 set with par2cmdline's
# `.vol-NN.par2` volume naming - the shape 57% of motorsport posts take, and
# exactly the geometry of the 6 Sep sample: 2,000 data blocks of 1,202,100
# bytes and ~40 recovery blocks, i.e. 2.0%.
#
# The `.vol-NN` names are applied by renaming after creation: no current
# creator writes them, and the classifier that reads them
# (`nzb::par2_vol_suffix`) is why they are on the rig at all. Renaming is safe
# because a PAR2 volume is found by its CONTENT; every arm here loads them.
# ---------------------------------------------------------------------------
OBF=8f3c1a90d47b62e5c0193ae7bd48f215
REL=Motorsport.2026.Round12.UNCUT.HDTV.H264-RIG
if [ ! -d "$ROOT/sports" ]; then
  echo "== row 10: sports broadcast, one obfuscated 2.4 GB mp4"
  mkdir -p "$ROOT/sports"
  gen "$ROOT/sports/$OBF.mp4" $((2000 * 1202100))
  create_set "$ROOT/sports" "$REL.par2" 1202100 2 "$OBF.mp4"
  ( cd "$ROOT/sports" && n=0
    for v in $(ls "$REL".vol*.par2 2>/dev/null | sort); do
      mv "$v" "$(printf '%s.vol-%02d.par2' "$REL" "$n")"; n=$((n + 1))
    done
    echo "   $n volume(s) renamed to .vol-NN.par2" )
fi

# ---------------------------------------------------------------------------
# The damage maps. Every scenario copy is made from a map beside this script,
# so a re-cut map re-cuts every rig identically.
# ---------------------------------------------------------------------------
if [ "$SKIP_DAMAGED" = "1" ]; then
  echo "== damage SKIPPED (round2.sh cuts each row's map into its work copy)"
else
echo "== damage"
dmg() { # dmg <src> <dst> <map> <block-size>
  python3 "$HERE/apply-damage.py" "$ROOT/$1" "$ROOT/$2" "$HERE/$3" --block-size "$4"
}
dmg tv    row1-tv-2articles      amap-row1-tv.txt         1048576
dmg movie row2-movie-12articles  amap-row2-movie.txt      1048576
dmg movie row3-movie-gap         amap-row3-movie-gap.txt  1048576
dmg movie row3-movie-volgone     amap-row3-movie-most.txt 1048576
dmg movie row4-movie-deleted     amap-row4-movie.txt      1048576
dmg album row8-album-1article    amap-row8-album.txt       524288
dmg sports row10-sports-1article amap-row10-sports.txt    1202100
for pct in 100 110; do
  dmg "pars-single-$pct" "row5-single-$pct" amap-row5-single.txt 1048576
  dmg "pars-multi-$pct"  "row5-multi-$pct"  amap-row5-multi.txt  1048576
done
dmg heavy row9-heavy-1500blocks map-heavy-1500.txt 65536
fi

echo "== sha references"
( cd "$ROOT/tv"     && shasum -a 256 ./*.rar > "$ROOT/tv.sha" )
( cd "$ROOT/movie"  && shasum -a 256 ./*.rar > "$ROOT/movie.sha" )
( cd "$ROOT/album"  && shasum -a 256 ./*.rar > "$ROOT/album.sha" )
( cd "$ROOT/heavy"  && shasum -a 256 ./*.rar > "$ROOT/heavy.sha" )
( cd "$ROOT/sports" && shasum -a 256 ./*.mp4 > "$ROOT/sports.sha" )
( cd "$ROOT/pars-single-100" && shasum -a 256 ./*.mkv > "$ROOT/pars-single.sha" )
( cd "$ROOT/pars-multi-100"  && shasum -a 256 ./*.rar > "$ROOT/pars-multi.sha" )

echo "== done"
du -sh "$ROOT"/*/ 2>/dev/null
