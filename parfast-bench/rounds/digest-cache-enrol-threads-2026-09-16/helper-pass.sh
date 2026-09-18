#!/bin/bash
# The helper's OWN finish across rungs, beside a live chain - the number the
# banked round could not see. Same fixture, same command, member warm, rig
# lock per leg, three mirrored reps over the rungs.
set -u
W=$HOME/dcenrol16sep; EXE=$W/parfast2; LOG=$W/logs/helper.log
: > $LOG
log(){ echo "$*"; echo "$*" >> $LOG; }
load1(){ python3 -c 'import os;print("%.2f"%os.getloadavg()[0])'; }
log "HELPER-PASS host=$(hostname -s) cpu=$(sysctl -n machdep.cpu.brand_string) cores=$(sysctl -n hw.ncpu) bin=$(shasum -a 256 $EXE|cut -c1-16) start=$(date -u +%FT%TZ)"
RUNGS_F="1 2 3 4 8"; RUNGS_R="8 4 3 2 1"
for rep in 1 2 3; do
  if [ $((rep%2)) -eq 0 ]; then O=$RUNGS_R; else O=$RUNGS_F; fi
  for n in $O; do
    while :; do l=$(load1); python3 -c "import sys;sys.exit(0 if $l<5.0 else 1)" && [ ! -e $HOME/.parfast-rig.lock ] && break; log "QUEUE load1=$l rung=$n rep=$rep"; sleep 15; done
    ( set -o noclobber; echo "round=helperpass pid=$$" > $HOME/.parfast-rig.lock ) 2>/dev/null || { log "LOCK-BUSY rung=$n rep=$rep"; sleep 20; continue; }
    S=$W/hstore-$n-$rep; rm -rf $S; mkdir -p $S; rm -f $W/out/*.par2
    dd if=$W/single.bin of=/dev/null bs=16m >/dev/null 2>&1
    t0=$(python3 -c 'import time;print(time.time())')
    HOME=$S NZBFAST_REPAIR_TIMING=1 PARFAST_ENROL_THREADS_PROBE=$n \
      $EXE c -q -s4429188 -c100 --digest-cache -B $W $W/out/set.par2 $W/single.bin > $W/logs/h-$n-$rep.out 2> $W/logs/h-$n-$rep.err
    rc=$?
    t1=$(python3 -c 'import time;print(time.time())')
    rm -f $HOME/.parfast-rig.lock
    wall=$(python3 -c "print('%.2f'%($t1-$t0))")
    own=$(grep -o 'own_finish_s=[0-9.]*' $W/logs/h-$n-$rep.err|head -1|cut -d= -f2)
    thr=$(grep -o 'ENROL-HELPER threads=[0-9]*' $W/logs/h-$n-$rep.err|head -1|cut -d= -f2)
    chain=$(grep -o 'chain alone [0-9.]*s' $W/logs/h-$n-$rep.err|head -1|sed 's/chain alone //')
    dc=$(grep -o 'enrolling ([0-9.]*s)' $W/logs/h-$n-$rep.err|head -1)
    sha=$(python3 - $W/out <<'PY'
import hashlib,os,sys
d=sys.argv[1];h=hashlib.sha256()
for f in sorted(x for x in os.listdir(d) if x.startswith("set") and x.endswith(".par2")):
    h.update(open(os.path.join(d,f),'rb').read())
print(h.hexdigest()[:16])
PY
)
    log "HLEG rung=$n rep=$rep rc=$rc wall=$wall helper_threads=$thr helper_own_s=$own chain_alone=$chain reported=[$dc] sha=$sha load1=$(load1)"
  done
done
log "HELPER-PASS done=$(date -u +%FT%TZ)"
