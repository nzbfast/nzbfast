#!/bin/bash
# dcenrol.sh - the macOS half of the ENROL_THREADS ladder. Claim
# digest-cache-enrol-threads-close-the-question-16sep.
#
# The Mac arms the 16 Sep Windows round left owed: on a part with enough
# memory bandwidth to feed two BLAKE3 threads beside one MD5 chain, does the
# enrolment's own finish time move with `ENROL_THREADS` at all? If it is flat
# here too, nothing anywhere uses the second thread; if it is not, 2 is
# earning its keep and the constant is closed at 2 with a measured reason.
#
# THE PROTOCOL IS dcenrol.ps1's, which copied it from the small-core round and
# from design note 9b-3. Same 8,858,370,048-byte AES-CTR fixture, same
# `c -q -s4429188 -c100`, member warm, per-leg rig lock NEVER held while
# waiting for quiet, three mirrored reps, and the combined SHA-256 of
# set*.par2 in name order identical on every leg or the leg is void.
#
# THE THREE WINDOWS-SHAPED THINGS dcenrol.ps1's header names, translated:
#   - the store home is %LOCALAPPDATA% there and HOME here (digest_cache.rs
#     `default_dir()`: ~/Library/Caches/parfast/digests on macOS);
#   - quiet is plib's `foreign_cpu` there and a 1-minute LOAD AVERAGE here,
#     read 9b-3's way: under 5 before the leg and under 5 after it once the
#     leg's own burst has decayed, polling up to 150 s, VOIDING a leg that
#     does not settle;
#   - `attrib +I` (Windows Search exclusion) has no Mac equivalent and is
#     dropped; Spotlight is left alone and its cost is reported per leg in the
#     foreign-CPU column instead.
#
# THE PROBE: the binary this drives carries a throwaway
# PARFAST_ENROL_THREADS_PROBE knob in digest_cache.rs so one release build
# serves the whole ladder. IT MUST NOT LAND, and the ladder is only comparable
# because every rung is the same binary.
#
# usage: dcenrol.sh <exe> <work> [tag] [rungs] [reps]
set -u
EXE="$1"; WORK="$2"; TAG="${3:-dcenrol}"; RUNGS="${4:-1,2,3,4}"; REPS="${5:-3}"
REAL_HOME="$HOME"
LOCK="$REAL_HOME/.parfast-rig.lock"
OUT="$WORK/out"; LOGD="$WORK/logs"; MEMBER="$WORK/single.bin"
mkdir -p "$WORK" "$OUT" "$LOGD" "$WORK/store-null"
LOG="$LOGD/$TAG.log"
log() { echo "$*"; echo "$*" >> "$LOG"; }
now() { python3 -c 'import time;print("%.6f"%time.time())'; }
iso() { python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).isoformat())'; }
load1() { python3 -c 'import os;print("%.2f"%os.getloadavg()[0])'; }

log "ROUND $TAG start=$(iso) host=$(hostname -s) cores=$(sysctl -n hw.ncpu) rungs=$RUNGS reps=$REPS"
log "BOX cpu=$(sysctl -n machdep.cpu.brand_string) cores=$(sysctl -n hw.ncpu) ram_gb=$(python3 -c "print(round($(sysctl -n hw.memsize)/1e9,1))") os=$(sw_vers -productVersion)"
log "BIN parfast sha256=$(shasum -a 256 "$EXE" | cut -c1-16 | tr 'a-f' 'A-F') mtime=$(stat -f %Sm -t %FT%TZ "$EXE")"

if [ ! -f "$MEMBER" ] || [ "$(stat -f %z "$MEMBER")" != "8858370048" ]; then
  log "NO FIXTURE at $MEMBER (need 8858370048 bytes)"; exit 3
fi
log "FIXTURE sha256=$(shasum -a 256 "$MEMBER" | cut -d' ' -f1)"

# Combined SHA-256 of set*.par2 CONCATENATED in name order - the spelling
# every pristine leg of every round in this family has read as
# 5b8d41b8cae45152. A leg that does not match it is void.
set_sha() {
  python3 - "$OUT" <<'PY'
import hashlib, os, sys
d = sys.argv[1]
files = sorted(f for f in os.listdir(d) if f.startswith("set") and f.endswith(".par2"))
h = hashlib.sha256()
for f in files:
    with open(os.path.join(d, f), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            h.update(chunk)
print(h.hexdigest()[:16] + " files=" + str(len(files)))
PY
}

# 9b-3's quiet rule. NEVER called while the rig lock is held.
wait_quiet() {
  local where="$1" t0 waited l
  t0=$(now)
  while :; do
    l=$(load1)
    waited=$(python3 -c "print(int($(now)-$t0))")
    if python3 -c "import sys;sys.exit(0 if $l < 5.0 else 1)"; then
      if [ ! -e "$LOCK" ]; then
        log "BOX-FREE load1=$l waited_s=$waited at=$where"; return 0
      fi
      log "BOX-QUEUE load1=$l locked=yes held_by=$(tr -d '\n' < "$LOCK" 2>/dev/null) waited_s=$waited at=$where"
    else
      log "BOX-QUEUE load1=$l locked=$([ -e "$LOCK" ] && echo yes || echo no) waited_s=$waited at=$where"
    fi
    if [ "$waited" -ge 150 ]; then
      log "BOX-QUEUE-SLOW load1=$l waited_s=$waited at=$where - still waiting"
    fi
    sleep 15
  done
}

take_lock() {
  local t0 waited
  t0=$(now)
  while :; do
    if ( set -o noclobber; echo "round=$TAG pid=$$ started=$(iso)" > "$LOCK" ) 2>/dev/null; then return 0; fi
    waited=$(python3 -c "print(int($(now)-$t0))")
    log "LOCK-WAIT waited_s=$waited held_by=$(tr -d '\n' < "$LOCK" 2>/dev/null)"
    if [ "$waited" -ge 3600 ]; then log "LOCK-TIMEOUT"; exit 17; fi
    sleep 20
  done
}
release_lock() { grep -q "pid=$$\b" "$LOCK" 2>/dev/null && rm -f "$LOCK"; }
trap 'release_lock' EXIT

# Other processes' CPU while the leg runs, sampled every 2 s, in cores.
foreign_sampler() {
  local pidfile="$1" outfile="$2"
  : > "$outfile"
  while [ -e "$pidfile" ]; do
    ps -A -o %cpu=,pid= | awk -v me="$$" '{s+=$1} END {print s/100.0}' >> "$outfile"
    sleep 2
  done
}

run_arm() {
  local arm="$1" rep="$2" store n home base t0 t1 wall rc dc fused fold chain fcpu fafter
  rm -f "$OUT"/*.par2 2>/dev/null
  # member warm
  dd if="$MEMBER" of=/dev/null bs=16m > /dev/null 2>&1
  base="$LOGD/$TAG-$arm-$rep"
  if [ "$arm" = "fresh" ]; then
    home="$WORK/store-null"
    ARGS=(c -q -s4429188 -c100 -B "$WORK" "$OUT/set.par2" "$MEMBER")
    PROBE=""
  else
    n="${arm#e}"
    store="$WORK/store-$arm-$rep"
    rm -rf "$store"; mkdir -p "$store"
    home="$store"
    ARGS=(c -q -s4429188 -c100 --digest-cache -B "$WORK" "$OUT/set.par2" "$MEMBER")
    PROBE="$n"
  fi
  local sampf="$base.foreign" pidf="$base.running"
  touch "$pidf"
  foreign_sampler "$pidf" "$sampf" &
  local sampler=$!
  t0=$(now)
  if [ -n "$PROBE" ]; then
    HOME="$home" NZBFAST_REPAIR_TIMING=1 PARFAST_ENROL_THREADS_PROBE="$PROBE" \
      /usr/bin/time -l "$EXE" "${ARGS[@]}" > "$base.out" 2> "$base.err"
  else
    HOME="$home" NZBFAST_REPAIR_TIMING=1 \
      /usr/bin/time -l "$EXE" "${ARGS[@]}" > "$base.out" 2> "$base.err"
  fi
  rc=$?
  t1=$(now)
  rm -f "$pidf"; wait $sampler 2>/dev/null
  wall=$(python3 -c "print('%.2f'%($t1-$t0))")
  fcpu=$(python3 -c "
xs=[float(x) for x in open('$sampf') if x.strip()]
print('%.2f'%(sum(xs)/len(xs)) if xs else 'na')" 2>/dev/null || echo na)
  # /usr/bin/time -l writes to stderr: "real user sys" then a resource block.
  local cpu peakmb
  cpu=$(awk '/ real .* user .* sys/ {printf "%.3f", $3+$5}' "$base.err" | head -1); cpu=${cpu:--}
  peakmb=$(awk '/maximum resident set size/ {printf "%.1f", $1/1048576}' "$base.err" | head -1); peakmb=${peakmb:--}
  local txt; txt=$(cat "$base.out" "$base.err" 2>/dev/null)
  fused=$(echo "$txt" | sed -n 's/.*fused=\([a-z]*\).*/\1/p' | head -1); fused=${fused:-?}
  dc=$(echo "$txt" | grep -o 'digest-cache [^|]*' | head -1 | tr -s ' '); dc=${dc:--}
  fold=$(echo "$txt" | sed -n 's/.*fold alone \([0-9.]*[a-z]*\).*/\1/p' | head -1); fold=${fold:--}
  chain=$(echo "$txt" | sed -n 's/.*chain alone \([0-9.]*[a-z]*\).*/\1/p' | head -1); chain=${chain:--}
  # 9b-3's AFTER half: the leg is void unless the box settles back under 5
  # within 150 s once its own burst has decayed.
  local a0 aw al void=0
  a0=$(now)
  while :; do
    al=$(load1); aw=$(python3 -c "print(int($(now)-$a0))")
    python3 -c "import sys;sys.exit(0 if $al < 5.0 else 1)" && break
    if [ "$aw" -ge 150 ]; then void=1; break; fi
    sleep 10
  done
  fafter="$al/settled_s=$aw"
  [ "$void" = 1 ] && fafter="$fafter VOID-DID-NOT-SETTLE"
  log "LEG arm=$arm rep=$rep rc=$rc wall=$wall cpu=$cpu peakmb=$peakmb foreign_cores=$fcpu load_after=$fafter fused=$fused fold_alone=$fold chain_alone=$chain dc=[$dc] sha=$(set_sha) ts=$(iso)"
}

IFS=',' read -ra RL <<< "$RUNGS"
FORWARD=(fresh)
for r in "${RL[@]}"; do FORWARD+=("e$r"); done
REVERSE=()
for ((i=${#FORWARD[@]}-1; i>=0; i--)); do REVERSE+=("${FORWARD[$i]}"); done

for ((rep=1; rep<=REPS; rep++)); do
  if [ $((rep % 2)) -eq 0 ]; then ORDER=("${REVERSE[@]}"); else ORDER=("${FORWARD[@]}"); fi
  for arm in "${ORDER[@]}"; do
    wait_quiet "pre-$arm-$rep"
    take_lock
    run_arm "$arm" "$rep"
    release_lock
  done
done
log "ROUND $TAG done=$(iso)"
