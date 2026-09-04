#!/bin/bash
# Build the 7 extraction shapes, ~1 GiB of payload each.
#
#   shapes-build.sh <srcdir> <shapesdir> [rar-binary]
#
# Every archive uses -ep (store bare names, no paths): an earlier corpus
# stored absolute paths on some shapes only, so extractors recreated deep
# directory chains on those legs alone and `store` looked like a loss.
# -tsm-/-tsc-/-tsa- drop file timestamps and -mt4 pins the compressor to four
# threads, which together make the archives byte-identical on every machine
# that runs this script - rar's block split otherwise follows the host core
# count, so a 32-core box and a 20-core box produce different bytes.
set -euo pipefail

SRC=${1:?usage: shapes-build.sh <srcdir> <shapesdir> [rar]}
OUT=${2:?need a shapes dir}
RAR=${3:-rar}
PW=benchpw

mkdir -p "$OUT"

b() { # b <name> <input> <flags...>
  local name=$1 input=$2; shift 2
  local dir="$OUT/$name"
  rm -rf "$dir"; mkdir -p "$dir"
  echo "== $name  ($*)"
  ( cd "$SRC" && "$RAR" a -idq -ep -mt4 -tsm- -tsc- -tsa- "$@" "$dir/$name.rar" "$input" ) </dev/null
}

b store  rand.bin  -m0
b small  small/    -m3
b solid  small/    -m3 -s
b rep    rep.bin   -m3
b big    mixed.bin -m3 -v125m
b enc    mixed.bin -m3 "-hp$PW"
b r7dict mixed.bin -m3 -md128m
# Usenet-shaped legs (2 Sep 2026): the census shapes, 50 MB volumes.
b storev    rand.bin  -m0 -v50m
b encstore  rand.bin  -m0 -v50m "-hp$PW"
b encstorep rand.bin  -m0 -v50m "-p$PW"
b bigv      mixed.bin -m3 -v50m

echo
echo "== corpus"
for d in "$OUT"/*/; do
  n=$(basename "$d")
  sz=$(cat "$d"/*.rar | wc -c | tr -d ' ')
  printf '%-8s %14s bytes  %s\n' "$n" "$sz" "$(ls "$d" | tr '\n' ' ')"
done
