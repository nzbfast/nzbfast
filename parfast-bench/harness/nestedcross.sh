#!/bin/sh
# nestedcross.sh - ONE LEG of the nested-chase progress-trim LINE-RATE
# CROSSOVER ladder. Claim `nested-stage2-line-rate-crossover-quiet-21sep`,
# 21 Sep 2026, answering an internal note section
# 6.3's closing sentence.
#
#   nestedcross.sh <tag> <port> <line-mbps|0> [VAR=value ...]
#
# WHAT IT MEASURES, AND WHY IT IS NOT A RE-RUN OF 6.2. Section 6.2's ladder
# walked the MARGIN at two line rates and found the trade unfavourable at
# both. Section 6.3 then said the one quantity a loaded box could not supply
# is the DECODE RATE, which is what sets where the line-rate axis crosses
# over - the line speed below which the margin binds at all. So this driver
# holds the margin FIXED and walks the LINE RATE, and the column it exists
# to produce is `holdspk`: at a line rate above the crossover every rung
# holds the whole input and the arm is a pure loss (6.2's unthrottled legs);
# below it, `holdspk` falls. The crossover is where that column leaves the
# input size, and its position is a property of the box, which is why this
# driver refuses nothing about load and the ROUND wrapper must pick the
# window instead.
#
# WHY IT IS IN THE REPO AND `leg-gran-stage2.sh` WAS NOT. Its ancestor lived
# only in `~/nzbfast-nested-holds/` and hard-wired `REPO` to a worktree
# (`relaxed-banach-0c05d1`). A worktree is deleted when its lane closes, so
# that driver was one cleanup away from unrunnable while being the only
# record of how the round ran. Everything box-shaped here is an env override
# with a default, and the round log carries the resolved values.
#
# DO NOT PASS `NZBFAST_HOLDS_CAP=64M`. Section 7's quoted recipe carries it
# and that recipe is STAGE 1's: at 64M the inner chase demotes
# (`stream=demoted reason="held-bytes cap: chase memory"`) and the leg
# measures the disk control instead of the subject. Stage 2's whole subject
# is the UNDER-cap regime, so the cap stays at the box's own default.
# Measured here 21 Sep 2026: with the cap the leg reports 1,079 blocking
# reads, without it 37,745 - and both exit 0 with a matching sha256, so the
# oracle does NOT catch this.
#
# READ WITH: section 6.3, and CLAUDE.md's armv7 load rule. A wall figure
# from this driver is publishable ONLY beside its own uptime pair, which is
# why `load1`/`load15` are ON the LEG line rather than in a header - a row
# lifted out of the log carries its own load with it.
set -u

TAG=${1:?tag}; PORT=${2:?port}; LINE=${3:?line-mbps (0 = unthrottled)}
shift 3

# EVERY BOX-SHAPED PATH IS AN OVERRIDE. The defaults are this Mac's, named
# so a reader sees the shape; a second box sets the four variables and needs
# no edit here.
RIG=${NXC_RIG:-$HOME/nzbfast-gran-holds}
# SELF-LOCATING, and that is the fix this driver exists for: the default is
# the checkout this script is IN, two levels up from `harness/`, so
# a driver that travels with the repo builds and measures the same tree. Its
# ancestor named a worktree, and a worktree dies with its lane.
REPO=${NXC_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}
# QUOTED, AND THAT IS NOT STYLE. `tools/scrub-bench-logs.py` collapses a
# `<rig> path to `<rig>` for the published mirror with a character
# class that excludes `/`, whitespace, quotes, `;`, `,` and `)` but NOT
# `}` - so an unquoted default INSIDE a `${...}` loses its closing brace,
# and the published copy stops parsing. `tools/script-parse-gate.py`
# catches it (it parses the mirror too), which is how this was found; the
# quote makes the scrub stop one character early and is the cheaper fix.
VOL=${NXC_VOL:-"<rig>"}
LOGROOT=${NXC_LOGD:-$HOME/nzbfast-nested-holds/legs-cross}
NZB=${NXC_NZB:-$RIG/nzbfast-gran-holds.nzb}
REF=${NXC_REF:-$HOME/nzbfast-nested-holds/ref/SHA256}

# THE HARNESS'S OWN PROVENANCE, at round start - one `HARNESS` line per file
# this leg sources, then the `HARNESS-RIG` token
# `tools/jcross-position-audit.py`'s `driver_label()` reads. A stamp is a
# nicety and must never end a round, so a missing library SAYS so and the
# leg proceeds (plib.ps1's `Get-RigStamp` header names the field round that
# rule was learned on).
HLIB=${HLIB:-$(cd "$(dirname "$0")" && pwd)/hlib.sh}
if [ -f "$HLIB" ]; then . "$HLIB"; harness_lines "$0" "$HLIB"
else echo "HARNESS-UNAVAILABLE $HLIB"; fi

BIN=$REPO/target/release/nzbfast
SRVBIN=$REPO/bench/nested-corpus/nzbserve/target/release/nzbserve
for f in "$BIN" "$SRVBIN" "$NZB"; do
  [ -f "$f" ] || { echo "LEG tag=$TAG rc=missing what=$f"; exit 2; }
done
[ -d "$VOL" ] || { echo "LEG tag=$TAG rc=novol what=$VOL"; exit 2; }

LINEARG=""
[ "$LINE" != "0" ] && LINEARG="--line-mbps $LINE"

# Clear the WHOLE image, not just this tag's directory: `dpeak` is a df
# figure over the volume, so a previous leg left on it inflates this one.
rm -rf "$VOL"/* 2>/dev/null
OUT=$VOL/$TAG; mkdir -p "$OUT"
LOGD=$LOGROOT/$TAG; rm -rf "$LOGD"; mkdir -p "$LOGD"

echo "== $TAG (line=${LINE} MB/s, 0 = unthrottled) =="
echo "RESOLVED rig=$RIG repo=$REPO vol=$VOL bin=$BIN"
# BINSHA IS NOT DECORATION - IT IS THE TRAP THIS ROUND ACTUALLY HIT. The
# stage 2 ladder ran against a binary built BEFORE `ac8246391` inverted the
# gate to opt-IN, so that build trims with `NZBFAST_CHASE_PROGRESS_TRIM`
# UNSET and its "arm off" control is not one. A leg that reports
# `trimmed=` non-zero with no `_TRIM=1` in `env=` is that build; read the
# LEG line's `trimmed`/`passes` against its `env=`, never the tag.
echo "BINSHA $(shasum -a 256 "$BIN" | cut -d' ' -f1)"
echo "ENVARM $*"
UPB=$(uptime)
echo "UPTIME-BEFORE $UPB"

# 5 s, NOT 2: `nzbserve serve` REWRITES the leg's NZB at startup, and a
# client launched too soon reads a truncated file and dies with `NZB
# contains no files`. 2 s raced it once on the stage 1 round.
# shellcheck disable=SC2086
"$SRVBIN" serve "$RIG" --port "$PORT" $LINEARG > "$LOGD/nzbserve.log" 2>&1 &
sleep 5

printf '{"servers":[{"host":"127.0.0.1","port":%s,"tls":false,"connections":32}]}' "$PORT" > "$LOGD/loopback.json"

# dpeak sampler: df over the DEDICATED image only.
( while :; do df -k "$VOL" | tail -1 | awk '{print $3}'; sleep 0.5; done ) > "$LOGD/dfsamples" 2>/dev/null &
DFPID=$!

T0=$(python3 -c 'import time;print(time.time())')
env "$@" /usr/bin/time -l "$BIN" \
    --config "$LOGD/loopback.json" get "$NZB" \
    --out "$OUT" --connections 32 --window 4 --decoders 8 \
    > "$LOGD/run.log" 2> "$LOGD/time.log"
RC=$?
T1=$(python3 -c 'import time;print(time.time())')

kill $DFPID 2>/dev/null
# BY PORT AND `-sTCP:LISTEN` ONLY. A bare `lsof -ti :$PORT` also returns
# CLIENTS of that port, and a pattern kill would reach every other lane's
# nzbserve on this shared box (CLAUDE.md invariants 2 and 2a).
SRV=$(lsof -ti :"$PORT" -sTCP:LISTEN 2>/dev/null)
[ -n "$SRV" ] && kill $SRV
sleep 1

UPA=$(uptime)
echo "UPTIME-AFTER $UPA"

WALL=$(python3 -c "print(round($T1-$T0,2))")
GOT=$(cd "$OUT" && shasum -a 256 movie.bin 2>/dev/null | cut -d' ' -f1)
WANT=$(awk '$2=="movie.bin"{print $1}' "$REF" 2>/dev/null)
if [ -n "$GOT" ] && [ "$GOT" = "$WANT" ]; then SHAOK=yes; else SHAOK=NO; fi
DPEAK=$(sort -n "$LOGD/dfsamples" | tail -1)

MEM=$(grep -m1 'peak RSS' "$LOGD/run.log" 2>/dev/null)
RSS=$(echo "$MEM"    | sed -n 's/.*peak RSS \([0-9.]*\) GB.*/\1/p')
HOLDS=$(echo "$MEM"  | sed -n 's/.*holds peak \([0-9]*\) MB.*/\1/p')
TRIM=$(echo "$MEM"   | sed -n 's/.*chase trimmed \([0-9]*\) MB.*/\1/p')
DROP=$(echo "$MEM"   | sed -n 's/.*chase trimmed [0-9]* MB (\([0-9]*\) dropped).*/\1/p')
PASSES=$(sed -n 's/.*chase progress trim \([0-9]*\) pass(es).*/\1/p' "$LOGD/run.log" | tail -1)
# The chase worker's own elapsed ms. Inner input / this is the CONSUME rate,
# which is the quantity 6.3 says a quiet box moves and a loaded one cannot
# supply - it is why this leg is worth taking twice on two different loads.
CHASEMS=$(sed -n 's/.*chase [0-9]* worker(s) \([0-9]*\) ms.*/\1/p' "$LOGD/run.log" | tail -1)

# The two load figures on the LEG LINE itself, not only in the header: a row
# lifted into a table has to carry the load it was taken at, or it becomes a
# wall figure with no provenance - which is what 6.3 refused to publish.
L1=$(echo "$UPB"  | sed -n 's/.*load averages*:[ ]*\([0-9.]*\) .*/\1/p')
L15=$(echo "$UPB" | sed -n 's/.*load averages*:[ ]*[0-9.]* [0-9.]* \([0-9.]*\).*/\1/p')
L1A=$(echo "$UPA" | sed -n 's/.*load averages*:[ ]*\([0-9.]*\) .*/\1/p')

echo "LEG tag=$TAG line=$LINE rc=$RC sha=$SHAOK holdspk=${HOLDS:-?}MB trimmed=${TRIM:-?}MB dropped=${DROP:-?}MB rss=${RSS:-?}GB dpeak=${DPEAK:-?}KB passes=${PASSES:-0} chasems=${CHASEMS:-?} wall=${WALL}s load1=${L1:-?} load15=${L15:-?} load1after=${L1A:-?} env=$*"
echo "--- output ---"; ls -l "$OUT"
echo "--- mem/extract lines ---"
grep -E '\[mem\]|backpressure|volumes never touched disk|materializ|\[extract\]' "$LOGD/run.log" | tail -20
echo "--- time -l ---"
grep -E "maximum resident|real|user|sys" "$LOGD/time.log" | head -5
exit 0
