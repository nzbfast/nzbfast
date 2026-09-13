#!/bin/bash
# parfast repair PHASE ladder: delete k whole members, repair with
# NZBFAST_REPAIR_TIMING=1, gate on SHA-256, and print one LEG line per
# leg carrying the wall, rc, the gate verdict and every engine phase
# mark, so the intercept-versus-slope fit of a depth ladder can be read
# phase by phase instead of as one number
# (research/PARFAST-REPAIR-PHASE-PROFILE-2026-09-10.md).
#
#   phase-ladder.sh <fixture> <work> <parfast> "<k list>" <reps> [cold-hook]
#
# The three arms the 10 Sep 2026 round ran on an M3 Ultra Mac, verbatim:
#   warm SSD   phase-ladder.sh $F $F/work $PF "0 1 2 3 4" 3
#   RAM disk   dev=$(hdiutil attach -nomount ram://$((48*1024*2048)) | awk '{print $1}')
#              diskutil erasevolume APFS phaseram $dev
#              phase-ladder.sh $F /Volumes/phaseram/work $PF "0 1 2 3 4" 3
#   cold SSD   diskutil apfs addVolume disk3 APFS phasecold   (no sudo needed)
#              phase-ladder.sh $F /Volumes/phasecold/work $PF "0 1 2 3 4" 3 \
#                "sync; diskutil unmount /Volumes/phasecold >/dev/null && diskutil mount disk3s7 >/dev/null"
# A remount drops that volume's page cache to zero resident pages
# (verify with bench/component/resident.c before believing a cold leg);
# an hdiutil sparse image does NOT make a cold arm - its reads cap at
# 2.6 GB/s and its backing file stays warm in the host cache.
#
# <fixture>   holds pristine/ (members + set) and pristine.sha, from
#             phase-fixture.sh
# <work>      the directory the repair runs in; on the same volume as
#             <fixture> it is populated by APFS clone, elsewhere (a RAM
#             disk, a disk image) by a plain copy, ONCE
# "<k list>"  members deleted per leg, e.g. "1 2 3 4"; k=0 is a verify-only
#             leg (nothing deleted, parfast still runs `r`)
# [cold-hook] a command run before every timed leg, after the damage, to
#             make the page cache cold (e.g. a detach/reattach of the
#             volume that holds <work>); absent = warm arm
#
# Every leg: rc captured, stderr kept under <work>/../legs/, the rebuilt
# members SHA-256 checked against pristine.sha, the untouched members
# size-checked, and a leg whose gate fails STOPS the round - a refusal
# exits fast and would publish as a win (bench/lib/legrc.sh).
set -uo pipefail
FIX=${1:?fixture}; WORK=${2:?work dir}; PF=${3:?parfast}; KS=${4:?k list}; REPS=${5:-3}; COLD=${6:-}
LEGS=${LEGS:-$(dirname "$WORK")/legs}; mkdir -p "$LEGS" "$WORK"
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
say() { echo "$(date -u +%FT%TZ) $*"; }
members=$(awk '{print $2}' "$FIX/pristine.sha")
populate() {
  # Anything missing or short is restored from pristine; a successful
  # repair leaves the set byte-identical so this is a no-op after one.
  for f in $members $(cd "$FIX/pristine" && ls *.par2); do
    if [ ! -s "$WORK/$f" ] || [ "$(stat -f %z "$WORK/$f")" != "$(stat -f %z "$FIX/pristine/$f")" ]; then
      rm -f "$WORK/$f"
      cp -c "$FIX/pristine/$f" "$WORK/$f" 2>/dev/null || cp "$FIX/pristine/$f" "$WORK/$f"
    fi
  done
}
say "LADDER parfast=$(shasum -a 256 "$PF" | cut -c1-16) fixture=$FIX work=$WORK ks=[$KS] reps=$REPS cold=${COLD:-none} load=$(sysctl -n vm.loadavg) tm=$(tmutil currentphase 2>/dev/null)"
for rep in $(seq 1 "$REPS"); do
  for k in $KS; do
    populate
    deleted=$(echo $members | tr ' ' '\n' | head -n "$k")
    for f in $deleted; do rm -f "$WORK/$f"; done
    if [ -n "$COLD" ]; then eval "$COLD"; fi
    err=$LEGS/k$k-rep$rep.err
    t0=$(now)
    # /usr/bin/time -l puts user/sys CPU and peak RSS on stderr beside
    # the engine's phase marks; a phase's CPU-seconds against its wall is
    # what separates "waiting on a serial hash chain" from "all cores
    # busy", which the wall alone cannot.
    ( cd "$WORK" && NZBFAST_REPAIR_TIMING=1 /usr/bin/time -l "$PF" r -q set.par2 >"$LEGS/k$k-rep$rep.out" 2>"$err" ); rc=$?
    t1=$(now)
    wall=$(echo "$t1 - $t0" | bc)
    gate=ok
    if [ "$rc" != 0 ]; then gate="rc=$rc"; fi
    for f in $deleted; do
      want=$(grep " $f\$" "$FIX/pristine.sha" | cut -d' ' -f1)
      have=$(cd "$WORK" && shasum -a 256 "$f" 2>/dev/null | cut -d' ' -f1)
      [ "$want" = "$have" ] || gate="sha-mismatch:$f"
    done
    # Phase marks are `<label>: +<delta> (total <t>)`; deltas come in s,
    # ms or µs and are normalised to seconds here so a LEG line adds up.
    phases=$(grep 'repair-timing' "$err" | sed -E 's/.*repair-timing: //' | grep -E '^[a-z].*: \+' | perl -ne 'if (/^(.*?): \+([0-9.]+)(µs|ms|s) /) { my ($l,$v,$u)=($1,$2,$3); $v/=1e6 if $u eq "µs"; $v/=1e3 if $u eq "ms"; $l=~s/[ +]+/_/g; printf "%s=%.3f ", $l, $v }')
    cpu=$(awk '/ real .* user .* sys$/{u=$3; s=$5} /maximum resident/{r=$1} END{printf "user=%s sys=%s rss_mb=%d", u, s, r/1048576}' "$err")
    # Blocks the engine ADOPTED from in-set duplicate slices rather than
    # decoded (the CLI's "N block(s) recovered from duplicate slices" line,
    # since 88007afff7). A nonzero count is a copy, not a decode, and a
    # fixture of near-identical members reads 12x cheaper in decode CPU
    # for the same plan line - research/PAR2J-DECODE-ALGO-2026-09-10.md.
    adopted=$(grep -oE '^[0-9]+ block\(s\) recovered from duplicate slices' "$LEGS/k$k-rep$rep.out" | awk '{s+=$1} END{print s+0}')
    echo "LEG k=$k rep=$rep wall=$wall rc=$rc gate=$gate adopted=$adopted $cpu $phases"
    if [ "$gate" != ok ]; then say "STOP: gate failed ($gate) - see $err"; exit 1; fi
  done
done
say "LADDER DONE"
