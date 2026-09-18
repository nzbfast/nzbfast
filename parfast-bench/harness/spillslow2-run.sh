#!/bin/bash
# spillslow2-16sep on amd-epyc-vm (claim parfast-spill-flush-throttled-disk-cgroup-15sep).
#
# WHY THIS ROUND EXISTS. spillslow-15sep ran its 60 legs on binaries built from
# origin/main ecf1d7a2f and branch b198573b4, both of which PREDATE ac1b302b4
# ("parfast: fix glibc's mmap threshold when memory is bounded", landed
# 22:09:48Z 15 Sep, about a minute before that runner was written). Measured
# there: the 512M cells sit at anon 445-504 MiB against a 512 MiB limit and are
# OOM-killed, where the kill-attribution note puts this exact cell at 270-272
# MiB WITH the fix. So that round's 512M half attributes to the disk and the
# flush what belongs to an absent allocator fix, exactly as cgcap round 1 did
# (COORDINATION-vps 00:14:10Z). Its 1G half and its in-process flush figures
# stand; this round replaces the 512M answer.
#
# AND IT IS A BETTER DESIGN, because 672b1cb72 shipped the flush: ONE binary
# from current origin/main serves all three arms by env, so unlike the parent
# round there is no build difference between arms at all.
#   gated  no env       -> spill_flush_wanted() reads the cgroup limit -> ON  (4 flush lines)
#   off    _FLUSH=0     -> forced OFF                                        (0 flush lines)
#   aa     _FLUSH=0     -> same, on a BYTE COPY of the binary: the A/A floor  (0 flush lines)
# gated-vs-off is the effect; off-vs-aa is this box's noise on the same work,
# and on this box that floor has reached 13.6-36.9% with the quiet-box guard
# passing throughout, so nothing is read against zero.
#
# Build is OUTSIDE the lock and niced (lanes ahead see no foreign CPU from the
# lock's point of view); everything from the fixture down is UNDER the lock.
set -uo pipefail
D=/root/spillslow2-16sep
cd $D
log(){ echo "$(date -u +%FT%TZ) $*" | tee -a $D/run.log; }
L=/root/.parfast-rig.lock

# ---- PHASE 1: build, OUTSIDE the lock, niced ----
if [ ! -x bin/parfast ]; then
  log "build start (outside the lock, nice 19) from $(cat main2.sha)"
  mkdir -p bin
  rm -rf src tgt
  tar xzf main2.tgz || { log "FAIL untar"; exit 1; }
  (cd src && CARGO_TARGET_DIR=$D/tgt nice -n 19 cargo build --release --locked -p parfast) >> $D/build.log 2>&1 \
    || { log "FAIL build"; exit 1; }
  cp $D/tgt/release/parfast bin/parfast
  cp bin/parfast bin/parfast-aa
  nice -n 19 gcc -O2 -o bin/uncache uncache.c || { log "FAIL uncache"; exit 1; }
  # The flush must BE in this binary - it is the shipped gate, not a patch.
  grep -a -q NZBFAST_SPILL_FLUSH bin/parfast || { log "FAIL binary lacks the flush string"; exit 1; }
  cmp bin/parfast bin/parfast-aa || { log "FAIL A/A copy differs"; exit 1; }
  (cd bin && sha256sum parfast parfast-aa uncache) | tee -a run.log
  rm -rf src tgt
  log "built; string check ok; A/A copy byte-identical; sources and target deleted"
fi

# ---- PHASE 2: the rig lock. Blocking flock in a reopen-recheck LOOP ----
# Never a poll of flock -n (loses every handover to a blocking waiter) and
# never an exit on the inode mismatch (that IS the ordinary handover, because
# the releaser unlinks). harness/cg512.py's header carries both.
#
# Winning the flock is not the same as the box being free: a `set -o
# noclobber` shell taker has no flock to lose, so the flock alone cannot tell
# that holder from a genuine orphan. harness/riglock_state.py is the
# ONE rule this mirrors (liveness from the holder, never the clock, no age
# bound, no --force) - spelled inline in shell rather than imported, the same
# choice cg512.py's header makes, because this script cannot import Python
# cheaply either.
log "waiting for rig lock (pid $$)"
got=no
for _try in $(seq 1 2000); do
  exec 9>>$L
  if flock -w 300 9 && [ "$(stat -c %i $L 2>/dev/null)" = "$(stat -L -c %i /proc/$$/fd/9)" ]; then
    held=$(sed -n 's/.*pid=\([0-9]\{1,\}\).*/\1/p' $L | head -1)
    if [ -n "$held" ] && [ "$held" != "$$" ] && kill -0 "$held" 2>/dev/null; then
      log "rig lock names a live pid $held with no flock on it, waiting"
      exec 9>&-; sleep 2; continue
    fi
    got=yes; break
  fi
  exec 9>&-; sleep 2
done
[ $got = yes ] || { log "FAIL never got the rig lock"; exit 1; }
trap '[ "$(stat -c %i '$L' 2>/dev/null)" = "$(stat -L -c %i /proc/$$/fd/9)" ] && rm -f '$L'; exec 9>&-' EXIT
echo "round=spillslow2-16sep pid=$$ started=$(date -u +%FT%TZ) claim=parfast-spill-flush-throttled-disk-cgroup-15sep" > $L
log "rig lock TAKEN, load $(cut -d' ' -f1-3 /proc/loadavg)"
echo "NOTE $(date -u +%FT%TZ) parfast-spill-flush-throttled-disk-cgroup-15sep ACCOUNTS=none - rig lock TAKEN by $D/run.sh pid $$ (fixture, io.max validation, then 60 timed legs; build was done outside the lock). Kill by pid, never by pattern." >> /root/bench-out/COORDINATION-vps.txt

# ---- fixture: the same 16 x 64 MiB shape as the parent round ----
F=$D/fix
if [ ! -f $F/gold.sha ]; then
  mkdir -p $F/pristine && cd $F/pristine
  for i in $(seq -w 1 16); do dd if=/dev/urandom of=m$i.bin bs=1048576 count=64 status=none; done
  $D/bin/parfast c -q -t4 -s65536 -c4096 set.par2 m*.bin || { log "FAIL fixture create"; exit 1; }
  sha256sum m*.bin > ../gold.sha
  cd $D && rm -rf $F/work && cp -R $F/pristine $F/work
  log "fixture built"
fi
cd $D

# ---- io.max validation. RE-RUN rather than reusing the parent round's
# decision: a rung that no longer bites has to be caught here, not assumed. ----
DEV=/dev/sda
mbps(){ echo "$1" | awk '{for(i=1;i<=NF;i++) if($i ~ /\/s,?$/){v=$(i-1); u=$i; if(u ~ /^GB/) v*=1000; else if(u ~ /^kB/) v/=1000; print v; exit}}'; }
val(){
  local name=$1; shift
  rm -f $D/v.bin
  local w=$(systemd-run --scope --quiet --unit vs2-$name-w-$$ -p MemoryMax=512M "$@" dd if=/dev/zero of=$D/v.bin bs=1M count=1024 conv=fsync 2>&1 | tail -1)
  sync; bin/uncache $D/v.bin > /dev/null
  local r=$(systemd-run --scope --quiet --unit vs2-$name-r-$$ -p MemoryMax=512M "$@" dd if=$D/v.bin of=/dev/null bs=1M 2>&1 | tail -1)
  log "VALIDATE $name write: $w"
  log "VALIDATE $name read:  $r"
  echo "$name $(mbps "$w") $(mbps "$r")" >> $D/validate.tsv
}
if ! grep -q VALIDATE-DONE run.log; then
  val none
  for rung in 160:150 100:80; do
    bps=${rung%%:*}; iops=${rung##*:}
    val d${bps}-bps -p "IOReadBandwidthMax=$DEV ${bps}M" -p "IOWriteBandwidthMax=$DEV ${bps}M"
    val d${bps}-bps-iops -p "IOReadBandwidthMax=$DEV ${bps}M" -p "IOWriteBandwidthMax=$DEV ${bps}M" -p "IOReadIOPSMax=$DEV $iops" -p "IOWriteIOPSMax=$DEV $iops"
  done
  rm -f $D/v.bin
  log "VALIDATE-DONE"
fi
# Same rule as the parent round: a rung keeps its IOPS cap only if sequential
# write AND read with it stay >= 85% of the bandwidth-only rates. (The parent
# dropped both; an io.max IOPS cap counts sequential readahead requests, while
# a spindle's IOPS rating is a random-I/O figure.)
RUNGS=""
for rung in 160:150 100:80; do
  bps=${rung%%:*}; iops=${rung##*:}
  keep=$(awk -v a=d${bps}-bps -v b=d${bps}-bps-iops '$1==a{w=$2;r=$3} $1==b{wi=$2;ri=$3} END{print (w>0 && r>0 && wi>=0.85*w && ri>=0.85*r) ? "yes" : "no"}' $D/validate.tsv)
  if [ "$keep" = yes ]; then RUNGS="$RUNGS d${bps}=$DEV:${bps}M:${bps}M:$iops:$iops"; else RUNGS="$RUNGS d${bps}=$DEV:${bps}M:${bps}M::"; fi
  log "DECISION d${bps}: keep IOPS cap $iops = $keep ($(grep "^d${bps}-" $D/validate.tsv | tr '\n' ';'))"
done
log "RUNGS:$RUNGS"

# ---- the round: 5 reps x 2 disks x 2 limits x 3 arms, rotated ----
PIN="NZBFAST_REPAIR_SOLVE_BUDGET=134217728,NZBFAST_NTT_BUDGET=134217728"
ARMSEQ=(gated off aa)
for rep in 1 2 3 4 5; do
  order=$RUNGS; [ $((rep % 2)) = 0 ] && order=$(echo $RUNGS | tr ' ' '\n' | tac | tr '\n' ' ')
  for rs in $order; do
    disk=${rs%%=*}; iomax=${rs#*=}
    for limit in 512M 1G; do
      for k in 0 1 2; do
        arm=${ARMSEQ[$(( (k + rep - 1) % 3 ))]}
        tagv=$arm-$disk-r$rep
        lname=$([ $limit = 512M ] && echo L512 || echo L$limit)
        grep -q "\"tag\": \"fix-m4096-192-auto-$lname-r1-$tagv\"" round.jsonl 2>/dev/null && { log "SKIP $tagv $limit"; continue; }
        case $arm in
          gated) bin=$D/bin/parfast;    xenv=$PIN ;;
          off)   bin=$D/bin/parfast;    xenv="$PIN,NZBFAST_SPILL_FLUSH=0" ;;
          aa)    bin=$D/bin/parfast-aa; xenv="$PIN,NZBFAST_SPILL_FLUSH=0" ;;
        esac
        env -u NZBFAST_SPILL_FLUSH R=$D BIN=$bin NICE=0 IOMAX=$iomax UNCACHE=$D/bin/uncache XENV=$xenv \
          REPS=1 SERIES_ALL=1 LIMITS=$limit SETS=fix RUNGS=4096 BUDGETS=192 ARMS=auto TAG=$tagv OUT=round.jsonl \
          python3 $D/harness/cg512.py 2>&1 | grep -E "^LEG|Error|Traceback|SystemExit|refus" | tee -a run.log
        [ ${PIPESTATUS[0]} = 0 ] || { log "FAIL leg $tagv $limit"; exit 1; }
        chk=$(python3 - "$D" "fix-m4096-192-auto-$lname-r1-$tagv" "$arm" <<'CHK'
import json, sys
d, tag, arm = sys.argv[1:]
rec = [json.loads(l) for l in open(d + "/round.jsonl") if ('"tag": "%s"' % tag) in l][-1]
err = open(d + "/legs/" + tag + ".err", errors="replace").read()
want = 4 if arm == "gated" else 0
bad = []
if rec["slabs"] != 4 or rec["slab_width"] != 16384 or "output Spill" not in err:
    bad.append("shape slabs=%s width=%s spill=%s" % (rec["slabs"], rec["slab_width"], "output Spill" in err))
if len(rec["flush_s"]) != want and not rec["oom_kill"]:
    bad.append("flush lines %d, want %d" % (len(rec["flush_s"]), want))
if rec["drop_before_after"] is None or rec["drop_before_after"][1] != 0:
    bad.append("drop %s" % rec["drop_before_after"])
if not rec["iomax_cg"] or "rbps" not in rec["iomax_cg"]:
    bad.append("io.max not on the scope: %r" % rec["iomax_cg"])
print("BAD " + "; ".join(bad) if bad else "OK")
CHK
)
        log "CHECK $tagv $limit: $chk"
        [ "$chk" = OK ] || { log "STOP: leg check failed"; exit 1; }
      done
    done
  done
done
log "ROUND DONE, load $(cut -d' ' -f1-3 /proc/loadavg)"
rm -rf $F
tar czf results.tgz run.log round.jsonl validate.tsv legs build.log 2>/dev/null
log "fixture deleted; results in results.tgz; releasing lock"
echo "NOTE $(date -u +%FT%TZ) parfast-spill-flush-throttled-disk-cgroup-15sep ACCOUNTS=none - spillslow2 round done (one binary from origin/main $(cat $D/main2.sha | cut -c1-9), three arms by env incl. a byte-copy A/A), fixture deleted, rig lock RELEASED; results.tgz left in $D for copying off." >> /root/bench-out/COORDINATION-vps.txt
