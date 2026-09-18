#!/bin/sh
# run.sh OUT PLANFILE REPS - one memround round, detached from ssh.
cd ~/parfast-slabwidth-15sep
export SCRATCH=$HOME/parfast-slabwidth-15sep BIN_BASE=$HOME/parfast-slabwidth-15sep/bin/parfast
export NZBFAST_NO_ENRICH=1 OUT=$1 REPS=$3
export EXTRA_ARMS="$(cat harness/arms.json)" PLAN="$(cat harness/$2)"
exec python3 harness/memround.py
