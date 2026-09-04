#!/bin/zsh
# run-legs.sh - drive the nested-corpus legs through the loopback rig,
# nzbfast vs nzbget vs SABnzbd vs rustnzb vs Weaver. One LEG result line
# per client per leg (daemon start/append/poll/stop), plus a
# du(1) poller for disk high-water - the number nested extraction is
# supposed to improve.
#
#   ./run-legs.sh <leg-dir|tier-dir|corpus-root> [client ...]
#
# Clients: nzbfast nzbget nzbget_testing sab rustnzb weaver weaver083 (default:
# "nzbfast nzbget"; a client whose binary/env is missing is skipped with a
# SKIP line). `weaver` and `weaver083` are two ARMS of the same client -
# the newest PUBLISHED release and a source build of the newest VERSION -
# and both may run in one round.
#
# Env:
#   NZBFAST   nzbfast binary (default ../../target/release/nzbfast)
#   NZBSERVE  rig binary (default ./nzbserve/target/release/nzbserve,
#             auto-built when cargo is available)
#   NZBGET    nzbget binary (default: `command -v nzbget`)
#   SAB_CMD   SABnzbd launcher, e.g.
#             /Applications/SABnzbd.app/Contents/MacOS/SABnzbd
#   RUSTNZB   rustnzb binary
#   WEAVER    weaver binary (one-shot CLI; needs no keychain, see leg_weaver)
#   WEAVER083 second weaver binary for the source-build arm
#   NZBGET_TESTING  second nzbget binary for the rolling `testing` arm
#   PORT=11901  CONNS=8  TIMEOUT=1800  STALL=120  OUTROOT=$PWD/corpus-run
#   DISK_HZ=50  PROC_HZ=100  DISCOVER_HZ=5  PHASE_HZ=5  (see below)
#   SAB_PW_CAP=300  per-leg cap for the password leg (see cap_for)
#   WEAVER_CAP=600  per-leg cap for the weaver arms (see cap_for)
#
# One result line per client per leg, appended to $OUTROOT/suite.log:
#   LEG <leg> <client> wall_s=<s> hiwater_mb=<MB> rss_mb=<MB> cpu_s=<s>
#       disk_hz=<achieved> disk_n=<samples> disk_comparable=<yes|no>
#       rc=<rc> class=<c> ...
#
# ---- SAMPLING: fast, and measured not to perturb ----------------------
# `leg_sampler.py` and `procsample.py` carry the argument; the short
# version is that the old rate was chosen to dodge an observer effect that
# came from the METHOD, not the rate. `ps -axo` forks a process and walks
# the whole process table (47.5 ms a call here); the syscall engine reads
# the same numbers at ~0.002 ms per pid and separates discovery from
# sampling, so it runs 200x faster for a fraction of the cost. Measured
# against an unsampled reference with the old sampler as a positive
# control: on the bursty workload the effect was originally found on, the
# old poll moves cpu_s by +55.8% and this one by -0.1%; the full
# instrument together is +0.1%.
#
#   PROC_HZ=100     CPU and RSS, with DISCOVER_HZ=5 finding new pids.
#   DISK_HZ=50      high-water, which must outrun the LEG not the byte
#                   rate - the 27 Aug round polled at 2 Hz and published
#                   hiwater_mb=0 on three cells whose leg finished inside
#                   one poll.
#   PHASE_HZ=5      bounded by FAIRNESS rather than cost: it is an HTTP
#                   request to the client under test, so raising it loads
#                   the thing being measured. Raise it only with a
#                   measurement.
#
# The sampler records the ACHIEVED rate, never the requested one, and
# marks a high-water taken from too few samples rather than publishing it.
#
# ---- PER-STEP STATS ---------------------------------------------------
# Every client's own log is kept PER LEG under $OUTROOT/<leg>/, and each
# leg gets a phase timeline in <prefix>.phases:
#   nzbfast, weaver  stdout piped through stamp.py - both are Rust, whose
#                    stdout is a LineWriter, so arrival time is emit time.
#   nzbget, rustnzb  their OWN log files, which carry their own timestamps.
#   sab              polled over its API: per-slot `status` + `labels` is
#                    the phase signal (it is how the a3 ENCRYPTED pause
#                    announces itself) and its log is not.
# The final history JSON is captured per leg for the three API clients,
# which is where SABnzbd's and NZBGet's post-processing stage lists live.
#
# Loopback rig - no providers, no Usenet account, no network access.
#
# ---- FAIRNESS: every client runs at its documented best --------------
# House rule - a competitor must never lose because we failed to
# configure it. What each client is given, and why:
#
#   nzbfast   --connections $CONNS --window 4 --decoders 8. Defaults
#             otherwise (auto memory budget, fast verify).
#   nzbget    ArticleCache=1000, WriteBuffer=1024, DirectWrite=yes,
#             DirectUnpack=yes, ParQuick=yes, ParBuffer=500,
#             ParThreads=0 (auto), UnpackCleanupDisk + NzbCleanupDisk=yes
#             (there is NO ParCleanupDisk option - an invalid option
#             makes NZBGet start fully PAUSED, which reads as 0 MB/s). NOTE: a standalone `-c` config uses
#             NZBGet's BUILT-IN defaults for anything unset (article
#             cache OFF, DirectWrite off) rather than the values in its
#             shipped nzbget.conf - so each must be stated explicitly.
#             Cleanup matters twice: leftovers, and disk high-water.
#   sab       pipelining_requests=8 PER SERVER (SABnzbd ships 1, i.e.
#             unpipelined - the single most valuable setting it has,
#             ~22% on a big job), receive_threads=4, cache_limit=1G,
#             direct_unpack=1, direct_unpack_threads=3.
#   rustnzb   pipelining=4, cache_size=1G, direct_unpack=false. The
#             last one is REQUIRED, not a handicap: its DirectUnpack
#             drives `unrar -vp` prompts that RARLab unrar never emits,
#             and the run hangs.
#   weaver    connections=$CONNS. One-shot `download` CLI; no further
#             documented tuning knobs found. Revisit if its docs grow.
#
# When a setting changes, say so alongside the published numbers - they
# are only defensible if the tuning is auditable.

set -u
cd "$(dirname "$0")"
# ABSOLUTE, and every helper below is reached through it rather than
# through $PWD. The weaver leg runs its client from the client's OWN
# directory (see leg_weaver), and a $PWD-relative helper path silently
# became relative to THAT directory the moment it did: stamp.py could not
# be found, so weaver's log came back EMPTY, so the log-verdict test could
# not fire, so a leg that had reported terminal failure ran out the stall
# timer and was graded HUNG instead - a much more serious published claim
# than a failure, and the one this rig already carries a comment warning
# about. Found by smoking; nothing about the run looked wrong.
HERE=$PWD

PORT=${PORT:-11901}
CONNS=${CONNS:-8}
TIMEOUT=${TIMEOUT:-1800}
# A client that stops making progress is hung, not slow. Waiting out the full
# TIMEOUT for it wastes half an hour per leg and tells us nothing extra, so a
# leg whose output tree has not grown for STALL seconds is called and killed.
STALL=${STALL:-120}
OUTROOT=${OUTROOT:-$PWD/corpus-run}
NZBFAST=${NZBFAST:-$PWD/../../target/release/nzbfast}
NZBSERVE=${NZBSERVE:-$PWD/nzbserve/target/release/nzbserve}
NZBGET=${NZBGET:-$(command -v nzbget || true)}
SAB_CMD=${SAB_CMD:-}
RUSTNZB=${RUSTNZB:-}
WEAVER=${WEAVER:-}
NG_PORT=${NG_PORT:-6795}
SAB_PORT=${SAB_PORT:-8086}
RN_PORT=${RN_PORT:-9091}
WEAVER083=${WEAVER083:-}
NZBGET_TESTING=${NZBGET_TESTING:-}
# THESE OVERRIDE leg_sampler.py's OWN DEFAULTS, so raising them there and
# not here leaves every round running at the old rates while the sampler
# reports itself as the new one. Caught on the r4 pilot: the fast engine
# was in place and still sampling at 0.5 Hz because this line said so.
DISK_HZ=${DISK_HZ:-50}
PROC_HZ=${PROC_HZ:-100}
DISCOVER_HZ=${DISCOVER_HZ:-5}
PHASE_HZ=${PHASE_HZ:-5}
# The password leg ends in an operator prompt no harness can answer, so
# waiting out the full TIMEOUT for it costs half an hour per round and
# tells us nothing the first 300 s did not. See cap_for.
SAB_PW_CAP=${SAB_PW_CAP:-300}
# Weaver's own bound. Once the done-poll stopped mistaking a staged file
# for a delivered one (see leg_weaver), a Weaver leg that is going to fail
# runs until something else stops it: the a3 leg burned 1,833 s of wall
# and 1,780 s of CPU at 100% of one core, writing nothing, before the
# harness clock called it. That is a DNF either way and the extra 20
# minutes buys no information, so the arms are bounded - generously, at
# more than 3x the longest Weaver leg ever recorded on this rig.
WEAVER_CAP=${WEAVER_CAP:-600}

[[ $# -ge 1 ]] || { echo "usage: run-legs.sh <leg-or-tier-dir> [clients...]" >&2; exit 2; }
ROOT=$1; shift
CLIENTS=(${@:-nzbfast nzbget})
mkdir -p "$OUTROOT"
SUITE=$OUTROOT/suite.log

if [[ ! -x $NZBSERVE ]]; then
    command -v cargo >/dev/null || { echo "nzbserve missing and no cargo" >&2; exit 1; }
    cargo build --release --quiet --manifest-path "$PWD/nzbserve/Cargo.toml"
fi

# ---- helpers ----------------------------------------------------------

# WHOLE SECONDS IS NOT A CLOCK FOR THESE LEGS. `date +%s` was the timer
# until 27 Aug 2026 and most legs on this rig run 0-8 s, so quantisation
# alone put up to +-50% on a 2 s leg and published one leg as `wall_s=0`.
# That error is larger than anything the box's background load contributes
# and no amount of quiescing the machine reduces it. zsh's EPOCHREALTIME is
# a float with microsecond resolution and costs no process.
zmodload zsh/datetime 2>/dev/null || true
now() { print -r -- $EPOCHREALTIME }
# Integer seconds, still, for anything that only needs a coarse elapsed
# check (stall timers, caps). Never for a published figure.
now_i() { print -r -- ${EPOCHREALTIME%%.*} }
secs() { printf '%.3f' $(( $2 - $1 )) }
log() { echo "$*" | tee -a "$SUITE"; }

# Per-leg instrument: disk high-water at DISK_HZ, tree RSS/CPU at PS_HZ,
# and an optional API phase timeline at PHASE_HZ. See leg_sampler.py.
#
# THE --match PATTERN IS A UNIQUE PATH AND NEVER A BINARY NAME, and that
# is load-bearing on a SHARED DEVELOPMENT BOX rather than fastidiousness:
# this rig runs on a machine with several agent sessions working at once,
# and other lanes routinely have their own
# `nzbfast` test daemons alive. Matching the word `nzbfast` would fold a
# neighbouring lane's process tree into our RSS and cpu_s columns and
# nothing would say so. Every client below is therefore matched on the
# per-round config or output path we ourselves passed it, which no other
# process on the box can carry.
sampler_start() { # $1 tree $2 prefix $3 phase-kind $4 phase-url $5.. match
    local tree=$1 pfx=$2 kind=$3 purl=$4; shift 4
    local margs=(); local m
    for m in "$@"; do margs+=(--match "$m"); done
    rm -f "$pfx.json" "$pfx.phases"
    python3 "$HERE/leg_sampler.py" --out "$pfx" --tree "$tree" \
        --disk-hz "$DISK_HZ" --proc-hz "$PROC_HZ" \
        --discover-hz "$DISCOVER_HZ" --phase-hz "$PHASE_HZ" \
        --phase-kind "$kind" --phase-url "$purl" "${margs[@]}" \
        > "$pfx.sampler.out" 2>&1 &
    SAMP_PID=$!
    SAMP_PFX=$pfx
}
# SIGTERM, then WAIT for the json: the sampler writes its summary in the
# handler, so killing and reading immediately races it and yields an empty
# column that looks exactly like a client that used no memory.
sampler_stop() {
    kill -TERM $SAMP_PID 2>/dev/null
    local n=0
    while kill -0 $SAMP_PID 2>/dev/null && [[ $n -lt 100 ]]; do sleep 0.1; n=$((n+1)); done
    kill -9 $SAMP_PID 2>/dev/null
    wait $SAMP_PID 2>/dev/null
    [[ -s $SAMP_PFX.json ]] || echo "  WARN sampler wrote no json for $SAMP_PFX" | tee -a "$SUITE"
}

# Compose the LEG line from the sampler summary and the classifier verdict.
#
# disk_comparable IS THE POINT OF THIS FUNCTION. A disk high-water is only
# comparable among clients that COMPLETED the same leg - anything else is
# the cost of not finishing, and reads as efficiency. The 27 Aug round is
# the clean demonstration: Weaver's 7,995 MB was the SMALLEST total of the
# five and it completed nothing, its x1 and x2 legs writing literally
# nothing before giving up, while SABnzbd's a2 is 27 MB against everyone
# else's ~770 MB because it abandons the job in 2 s. Marking it here means
# a totals row cannot silently average a DNF's small number into a field.
emit_leg() { # $1 leg $2 client $3 wall_s $4 sampler-prefix $5 rc $6 classline
    local j=$4.json cls hw rss cpu dhz dn und comp psn psu lavg rdmb wrmb
    cls=$(echo "$6" | grep -o 'class=[a-z-]*' | head -1 | cut -d= -f2)
    if [[ -s $j ]]; then
        hw=$(jq -r '.hiwater_mb // "na"' "$j")
        rss=$(jq -r '.peak_rss_mb // "na"' "$j")
        cpu=$(jq -r '.cpu_s // "na"' "$j")
        dhz=$(jq -r '.disk_hz_achieved // "na"' "$j")
        dn=$(jq -r '.disk_samples // "na"' "$j")
        und=$(jq -r 'if .disk_undersampled then "yes" else "no" end' "$j")
        psn=$(jq -r '.ps_samples // "na"' "$j")
        psu=$(jq -r 'if .ps_undersampled then "yes" else "no" end' "$j")
        lavg=$(jq -r '.load_mean // "na"' "$j")
        rdmb=$(jq -r '.disk_read_mb // "na"' "$j")
        wrmb=$(jq -r '.disk_write_mb // "na"' "$j")
    fi
    comp=no; [[ ${cls:-} == auto-complete ]] && comp=yes
    log "LEG $1 $2 wall_s=$3 hiwater_mb=${hw:-na} rss_mb=${rss:-na} cpu_s=${cpu:-na} disk_hz=${dhz:-na} disk_n=${dn:-na} disk_comparable=$comp disk_undersampled=${und:-na} ps_n=${psn:-na} ps_undersampled=${psu:-na} load=${lavg:-na} rd_mb=${rdmb:-na} wr_mb=${wrmb:-na} rc=$5 $6"
}

# Per-leg, per-client cap. The password leg ends in an operator prompt
# that no harness can answer: SABnzbd DETECTS the encryption and PAUSES at
# 45% with an ENCRYPTED label and an empty password field, so it burns the
# whole 1800 s cap every round for a verdict the first 300 s already show.
# The CLASS is unchanged by the shorter cap - it is manual intervention
# either way, and only the harness clock ever called it a timeout - but
# the wall figure IS changed, so a round that shortens it must say so
# beside the number rather than letting it read as a faster client.
# THE OPERATOR PASS. A client that stops early looks FAST: its elapsed time
# is the time it took to give up, and putting that beside a client that ran
# through to a finished payload compares two different pieces of work, in the
# direction that flatters the one that did less. On `r4` four clients hand
# back the damaged archive WITH its complete recovery set and stop, and every
# one of their wall figures is shorter than the client that repaired it and
# carried on.
#
# So after every client, on every leg, the same scripted operator runs the
# standard tools over whatever was left behind - par2 repair, then extract,
# repeated until the payload appears or a pass changes nothing - and reports
# how many passes it needed, how long they took, and what they cost in disk.
# Time to a usable payload is the client's own time PLUS that.
#
# It runs on the clients that finished too, where it finds nothing to do and
# reports zero passes. A comparison that post-processes only the losers is
# not a comparison.
# THE OPERATOR GETS THE CLIENT'S WHOLE WORKING AREA, not just its delivery
# directory, and the difference is not academic. A client that cannot unpack
# a job often leaves everything in its INCOMPLETE folder and delivers
# nothing: NZBGet's `dst` is empty on the password leg while five archives
# sit in `inter/`, and SABnzbd's `complete` is empty on the par-only leg
# while eleven files sit in `incomplete`. Scoped to the delivery directory
# the operator finds nothing to do and the cell reads "never delivered",
# which is wrong twice over - the bytes ARE on disk, and a person would
# finish the job from there. Four cells in one pass were mis-scored that
# way. The CLIENT's own grade is unaffected and still reads only what the
# client delivered; this scope decides what the operator may work WITH.
run_operator() { # $1 leg $2 client $3 tree (the client's whole base)
    [[ ${OPERATOR:-1} == 1 ]] || return
    local pfx=$OUTROOT/$1/op.$2
    [[ -d $3 ]] || { log "OP $1 $2 passes=0 outcome=no-tree"; return; }
    python3 "$HERE/operator_passes.py" --tree "$3" --manifest "$MANIFEST" \
        --max-passes ${OP_MAX_PASSES:-6} --json "$pfx.json" > /dev/null 2>"$pfx.err"
    if [[ -s $pfx.json ]]; then
        log "OP $1 $2 passes=$(jq -r '.passes' $pfx.json) op_wall_s=$(jq -r '.total_seconds' $pfx.json) op_hiwater_mb=$(jq -r '.hiwater_mb // "na"' $pfx.json) op_rd_mb=$(jq -r '.disk_read_mb // "na"' $pfx.json) op_wr_mb=$(jq -r '.disk_write_mb // "na"' $pfx.json) op_cpu_s=$(jq -r '.cpu_s // "na"' $pfx.json) repairs=$(jq -r '.repairs' $pfx.json) extracts=$(jq -r '.extracts' $pfx.json) outcome=$(jq -r '.outcome' $pfx.json)"
    else
        log "OP $1 $2 passes=na outcome=operator-failed"
    fi
}

cap_for() { # $1 client $2 legname -> seconds
    if [[ $1 == sab && $2 == *password* ]]; then echo $SAB_PW_CAP
    elif [[ $1 == weaver* ]]; then echo $WEAVER_CAP
    else echo $TIMEOUT; fi
}

# Foreground command with a hard timeout (rc 124 on expiry).
tmo() {
    python3 - "$TIMEOUT" "$@" <<'PY'
import subprocess, sys
t = float(sys.argv[1])
p = subprocess.Popen(sys.argv[2:])
try:
    sys.exit(p.wait(t))
except subprocess.TimeoutExpired:
    p.kill(); p.wait(); sys.exit(124)
PY
}

wait_gone() { # poll fn until it returns >0 or the cap; echoes done|timeout
    local fn=$1 before=$2 t0=$3 cap=${4:-$TIMEOUT}
    while :; do
        sleep 2
        [[ $($fn) -gt $before ]] && { echo done; return; }
        (( $(now) - t0 > cap )) && { echo timeout; return; }
    done
}

serve_start() { # $1 legdir
    "$NZBSERVE" serve "$1" --port $PORT > "$OUTROOT/nzbserve.log" 2>&1 &
    SRV_PID=$!
    local n=0
    until nc -z 127.0.0.1 $PORT 2>/dev/null; do
        sleep 0.3
        n=$((n+1))
        [[ $n -gt 200 ]] && { echo "nzbserve never came up (see $OUTROOT/nzbserve.log)" >&2; return 1; }
        kill -0 $SRV_PID 2>/dev/null || { echo "nzbserve exited (see $OUTROOT/nzbserve.log)" >&2; return 1; }
    done
}
serve_stop() { kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null; }

classify() { # $1 manifest, $2 outdir, $3 rc [extra args]
    # CLASSIFY_EXTRA: extra classify.py flags for the whole round, e.g.
    # CLASSIFY_EXTRA=--names-strict for the deobfuscation legs, where
    # bytes-right-name-wrong must grade manual-intervention, not auto.
    python3 "$HERE/classify.py" "$@" ${=CLASSIFY_EXTRA:-}
}

# ---- client legs ------------------------------------------------------
# Each leg_<client> gets: $LEGDIR $LEGNAME $NZB $MANIFEST set.

leg_nzbfast() {
    [[ -x $NZBFAST ]] || { log "SKIP $LEGNAME nzbfast (binary not found: $NZBFAST)"; return; }
    local out=$OUTROOT/$LEGNAME/nzbfast
    rm -rf "$out"; mkdir -p "$out"
    printf '{"servers":[{"host":"127.0.0.1","port":%s,"tls":false,"connections":32}]}' $PORT \
        > "$OUTROOT/loopback.json"
    # NO --password, AND THAT IS THE FAIRNESS FIX RATHER THAN A HANDICAP.
    # The harness used to read `.passwords.level1` out of the manifest and
    # hand it to nzbfast with `--password`, while SABnzbd, rustnzb, Weaver
    # and NZBGet were each given NOTHING (NZBGet's only password setting
    # here is its ControlPassword, which is the API's, not an archive's).
    # So on the a3 leg we were handed the answer and the other six had to
    # find it - and a3 is the leg whose published headline is nzbfast 3/3
    # against 0/3 for the entire field. That daylight was partly the rig's.
    # It does not need to be: the corpus posts `password_l1.txt` IN THE
    # CLEAR beside the volumes, in the NZB, so the chain is fully
    # self-describing and every client can in principle walk it - level 1's
    # password opens level 1, which contains level 2's, and so on. Measured
    # with the hand-off removed: nzbfast still auto-completes 3/3, finding
    # it itself ("archive password found in password_l1.txt (in-stream
    # probe)"). So the advantage is real and is now earned on the same
    # terms as everyone else's. Do NOT reinstate this flag to make a leg
    # pass; if a future leg needs an out-of-band secret, give it to EVERY
    # client through that client's own documented channel (SAB's
    # `&password=`, NZBGet's `{{...}}` nzb name, weaver's `--password`).
    local pwargs=()
    local pfx=$OUTROOT/$LEGNAME/samp.nzbfast
    # Matched on the per-round config path, not on the word "nzbfast" -
    # other lanes on this box have their own nzbfast processes alive.
    sampler_start "$out" "$pfx" none "" "$OUTROOT/loopback.json"
    local t0=$(now)
    # Piped through stamp.py so the log IS the phase timeline: nzbfast tags
    # every line ([get] [par2] [verify] [extract] [mem]) and Rust's stdout
    # is a LineWriter, so arrival time is emit time.
    tmo "$NZBFAST" --config "$OUTROOT/loopback.json" get "$NZB" --out "$out" \
        --connections $CONNS --window 4 --decoders 8 "${pwargs[@]}" 2>&1 \
        | python3 "$HERE/stamp.py" > "$OUTROOT/$LEGNAME/nzbfast.log"
    local rc=${pipestatus[1]}
    local t1=$(now)
    sampler_stop
    # `[mem]`, not `^mem:`. Both prior rounds grepped `^mem:` while nzbfast
    # has always printed `[mem]`, so the LEG line's trailing mem field was
    # EMPTY on every leg of both and nobody noticed - the numbers had to be
    # read out of the logs by hand. The stamp prefix means the tag is no
    # longer at the start of the line either.
    local memline=$(grep -F '[mem]' "$OUTROOT/$LEGNAME/nzbfast.log" | tail -1 | sed 's/^ *[0-9.]*  *//')
    emit_leg "$LEGNAME" nzbfast $(secs $t0 $t1) "$pfx" $rc "$(classify "$MANIFEST" "$out" $rc) $memline"
    run_operator "$LEGNAME" nzbfast "$out"
}

ng_done() { curl -s "http://127.0.0.1:$NG_PORT/jsonrpc/history" | grep -c '"NZBName"'; }

# TWO ARMS, for the same reason Weaver has two. `nzbgetcom/nzbget` carries
# a single pre-release tagged `testing` whose ASSETS ARE REPLACED IN PLACE:
# the tag name never changes and the version inside it does. On 27 Aug 2026
# it went from 26.3-testing-20260820 to 27.0-testing-20260827 - a different
# MAJOR version - at 13:47Z, while stable v26.3 shipped at 11:09Z the same
# morning. So "nzbget testing" names no build at all; only the ASSET
# FILENAME carries the version and the date, and it is what a round must
# cite. Racing the stable line and the pre-release line as separate arms is
# the only way that table means anything a week later.
leg_nzbget() { # $1 label $2 binary
    local LABEL=$1 NZBGET=$2
    [[ -n $NZBGET && -x $NZBGET ]] || { log "SKIP $LEGNAME $LABEL (binary not found: ${NZBGET:-unset})"; return; }
    local base=$OUTROOT/$LEGNAME/$LABEL
    rm -rf "$base"; mkdir -p "$base"
    cat > "$OUTROOT/nzbget-$LABEL.conf" <<EOF
MainDir=$base
DestDir=$base/dst
InterDir=$base/inter
TempDir=$base/tmp
QueueDir=$base/queue
LockFile=$base/lock
LogFile=$base/log
WebDir=
ConfigTemplate=
Server1.Host=127.0.0.1
Server1.Port=$PORT
Server1.Connections=$CONNS
Server1.Encryption=no
ControlIP=127.0.0.1
ControlPort=$NG_PORT
ControlUsername=
ControlPassword=
OutputMode=log
ParCheck=auto
ParRename=yes
RarRename=yes
Unpack=yes
DirectUnpack=yes
DirectWrite=yes
# Perf tuning to NZBGet's documented best. A standalone -c config takes
# NZBGet's BUILT-IN defaults for anything unset (ArticleCache=0,
# DirectWrite=no), NOT the values in its shipped nzbget.conf - so these
# must be stated explicitly or we would be benchmarking it with article
# caching switched off.
ArticleCache=1000
WriteBuffer=1024
ParQuick=yes
ParBuffer=500
ParThreads=0
# Tune NZBGet to its documented best, as the house rule requires: clean
# up archives + par2 after a successful unpack. Without these it leaves
# volumes behind and carries them in its disk high-water, which would be
# our misconfiguration showing up as its result.
UnpackCleanupDisk=yes
NzbCleanupDisk=yes
HealthCheck=none
NzbLog=no
DupeCheck=no
# A standalone -c config also inherits NZBGet's BUILT-IN UnrarCmd="unrar" /
# SevenZipCmd="7z", which resolve against PATH - and the bench boxes have
# neither on PATH, so every leg ended "Could not start unrar: No such file
# or directory" and the whole NZBGet column read manual-intervention on
# shapes it can actually finish (found 2 Aug 2026; the m3 25 Jul round has
# the same fault). Point both at the binaries NZBGet itself ships.
UnrarCmd=${NG_UNRAR:-$(dirname $NZBGET)/unrar}
SevenZipCmd=${NG_7Z:-$(dirname $NZBGET)/7za}
EOF
    "$NZBGET" -c "$OUTROOT/nzbget-$LABEL.conf" -D || { log "LEG $LEGNAME $LABEL rc=start-failed class=fail"; return; }
    sleep 2
    local before=$(ng_done)
    local pfx=$OUTROOT/$LEGNAME/samp.$LABEL
    sampler_start "$base" "$pfx" nzbget "http://127.0.0.1:$NG_PORT" "$OUTROOT/nzbget-$LABEL.conf"
    local t0=$(now)
    "$NZBGET" -c "$OUTROOT/nzbget-$LABEL.conf" -A "$NZB" >/dev/null 2>&1
    local st=$(wait_gone ng_done $before $t0 $(cap_for "$LABEL" "$LEGNAME"))
    local t1=$(now)
    # History BEFORE the shutdown - it carries the post-processing stage
    # list, which is the per-step record for this client, and -Q takes it.
    curl -s "http://127.0.0.1:$NG_PORT/jsonrpc/history" > "$OUTROOT/$LEGNAME/$LABEL.history.json" 2>/dev/null
    sampler_stop
    local hs=$(grep -o '"Status" : "[^"]*"' "$OUTROOT/$LEGNAME/$LABEL.history.json" 2>/dev/null | head -1 | tr -d '" ')
    "$NZBGET" -c "$OUTROOT/nzbget-$LABEL.conf" -Q >/dev/null 2>&1
    sleep 1
    # NZBGet writes its own timestamped log; keep it per leg before the
    # payload tree is cleared.
    cp -f "$base/log" "$OUTROOT/$LEGNAME/$LABEL.log" 2>/dev/null || true
    local rc=0; [[ $st == timeout ]] && rc=124
    emit_leg "$LEGNAME" "$LABEL" $(secs $t0 $t1) "$pfx" "$rc:$hs" "$(classify "$MANIFEST" "$base/dst" $rc)"
    run_operator "$LEGNAME" "$LABEL" "$base"
}

sab_done() { curl -s "http://127.0.0.1:$SAB_PORT/api?mode=history&apikey=harnesskey&output=json" | grep -oE '"status": ?"(Completed|Failed)"' | wc -l | tr -d ' '; }

leg_sab() {
    [[ -n $SAB_CMD && -x $SAB_CMD ]] || { log "SKIP $LEGNAME sab (set SAB_CMD to the SABnzbd launcher)"; return; }
    local base=$OUTROOT/$LEGNAME/sab
    rm -rf "$base"; mkdir -p "$base/complete" "$base/incomplete" "$base/admin"
    cat > "$OUTROOT/sabnzbd-bench.ini" <<EOF
[misc]
api_key = harnesskey
nzb_key = harnesskey
port = $SAB_PORT
host = 127.0.0.1
download_dir = $base/incomplete
complete_dir = $base/complete
admin_dir = $base/admin
auto_browser = 0
check_new_rel = 0
# SABnzbd's documented best, mirroring the provider harness. Pipelining
# is the decisive one: SAB SHIPS pipelining_requests=1 (unpipelined),
# and raising it to 8 is worth ~22% on a big job. Leaving it at the
# shipped default would make our result look better than it is.
cache_limit = 1G
receive_threads = 4
direct_unpack = 1
direct_unpack_threads = 3
[servers]
[[loopback]]
host = 127.0.0.1
port = $PORT
connections = $CONNS
ssl = 0
pipelining_requests = 8
enabled = 1
EOF
    nohup "$SAB_CMD" -f "$OUTROOT/sabnzbd-bench.ini" -s 127.0.0.1:$SAB_PORT -b0 \
        > "$OUTROOT/$LEGNAME/sab.out" 2>&1 &
    local sab_pid=$!
    sleep 8
    # SABnzbd REWRITES its ini on startup and reset our
    # pipelining_requests=8 back to its shipped 1, so the file is not a
    # reliable way to tune it - set it over the API where the value
    # sticks, then read it back and say so. Unpipelined SAB is the single
    # biggest handicap we could accidentally hand it.
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=set_config&section=servers&keyword=loopback&pipelining_requests=8&apikey=harnesskey&output=json" >/dev/null 2>&1
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=set_config&section=misc&keyword=receive_threads&value=4&apikey=harnesskey&output=json" >/dev/null 2>&1
    local pipe=$(curl -s "http://127.0.0.1:$SAB_PORT/api?mode=get_config&section=servers&apikey=harnesskey&output=json" 2>/dev/null | tr ',' '\n' | grep -o '"pipelining_requests": *[0-9]*' | grep -o '[0-9]*$' | head -1)
    log "  sab tuning: pipelining_requests=${pipe:-unknown} (SAB ships 1)"
    local before=$(sab_done)
    local pfx=$OUTROOT/$LEGNAME/samp.sab
    local cap=$(cap_for sab "$LEGNAME")
    [[ $cap -ne $TIMEOUT ]] && log "  sab cap: ${cap}s for $LEGNAME (operator-prompt leg; class is unaffected, wall is)"
    sampler_start "$base" "$pfx" sab "http://127.0.0.1:$SAB_PORT/api?apikey=harnesskey&output=json" "$OUTROOT/sabnzbd-bench.ini"
    local t0=$(now)
    curl -s -F "name=@$NZB" "http://127.0.0.1:$SAB_PORT/api?mode=addfile&apikey=harnesskey" >/dev/null
    local st=$(wait_gone sab_done $before $t0 $cap)
    local t1=$(now)
    # Queue AND history before the shutdown. The queue slot is where the
    # a3 ENCRYPTED label lives (a paused job is in neither history nor a
    # crash), and history's stage_log is SAB's own per-step record.
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=queue&apikey=harnesskey&output=json" > "$OUTROOT/$LEGNAME/sab.queue.json" 2>/dev/null
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=history&apikey=harnesskey&output=json" > "$OUTROOT/$LEGNAME/sab.history.json" 2>/dev/null
    sampler_stop
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=shutdown&apikey=harnesskey" >/dev/null
    sleep 3; kill $sab_pid 2>/dev/null
    local rc=0; [[ $st == timeout ]] && rc=124
    emit_leg "$LEGNAME" sab $(secs $t0 $t1) "$pfx" $rc "$(classify "$MANIFEST" "$base/complete" $rc)"
    run_operator "$LEGNAME" sab "$base"
}

rn_done() { curl -s "http://127.0.0.1:$RN_PORT/api?mode=history&output=json" | grep -oE '"status": ?"(Completed|Failed)"' | wc -l | tr -d ' '; }

leg_rustnzb() {
    [[ -n $RUSTNZB && -x $RUSTNZB ]] || { log "SKIP $LEGNAME rustnzb (set RUSTNZB)"; return; }
    local base=$OUTROOT/$LEGNAME/rustnzb
    rm -rf "$base"; mkdir -p "$base/complete" "$base/incomplete" "$base/data"
    cat > "$OUTROOT/rustnzb-bench.toml" <<EOF
[general]
listen_addr = "127.0.0.1"
port = $RN_PORT
incomplete_dir = "$base/incomplete"
complete_dir = "$base/complete"
data_dir = "$base/data"
speed_limit_bps = 0
direct_unpack = false
cache_size = 1073741824
log_level = "info"
log_file = "$base/rustnzb.log"

[[servers]]
id = "loopback"
name = "loopback"
host = "127.0.0.1"
port = $PORT
ssl = false
ssl_verify = false
connections = $CONNS
priority = 0
enabled = true
retention = 5000
pipelining = 4
optional = false

[[categories]]
name = "Default"
post_processing = 3
EOF
    nohup "$RUSTNZB" -c "$OUTROOT/rustnzb-bench.toml" > "$OUTROOT/$LEGNAME/rustnzb.out" 2>&1 &
    local rn_pid=$!
    sleep 5
    local before=$(rn_done)
    local pfx=$OUTROOT/$LEGNAME/samp.rustnzb
    sampler_start "$base" "$pfx" rustnzb "http://127.0.0.1:$RN_PORT/api" "$OUTROOT/rustnzb-bench.toml"
    local t0=$(now)
    curl -s -F "name=@$NZB" "http://127.0.0.1:$RN_PORT/api?mode=addfile" >/dev/null
    local st=$(wait_gone rn_done $before $t0 $(cap_for rustnzb "$LEGNAME"))
    local t1=$(now)
    curl -s "http://127.0.0.1:$RN_PORT/api?mode=history&output=json" > "$OUTROOT/$LEGNAME/rustnzb.history.json" 2>/dev/null
    sampler_stop
    kill $rn_pid 2>/dev/null
    # rustnzb writes its own timestamped log_file; keep it per leg.
    cp -f "$base/rustnzb.log" "$OUTROOT/$LEGNAME/rustnzb.log" 2>/dev/null || true
    local rc=0; [[ $st == timeout ]] && rc=124
    emit_leg "$LEGNAME" rustnzb $(secs $t0 $t1) "$pfx" $rc "$(classify "$MANIFEST" "$base/complete" $rc)"
    run_operator "$LEGNAME" rustnzb "$base"
}

# TWO ARMS OF ONE CLIENT, and both belong in a round. 0.7.8 is the newest
# PUBLISHED release and every banked Weaver cell is on it; 0.8.3 is the
# newest VERSION and ships no binary, so it can only be a source build.
# The 27 Aug round declined to race 0.8.3 on the ground that a source
# build is "a different fairness question", and that reasoning does not
# survive contact with the rest of that table: our rustnzb 1.4.5 arm is
# ITSELF a source build, since v1.4.5 is tagged and not released and
# upstream ships no macOS asset. That round therefore source-built one
# competitor and refused to source-build another in the same table. The
# fix is to raise Weaver, not to lower rustnzb - and to LABEL the 0.8.3
# cell a source build, never a shipped build.
leg_weaver() { # $1 label (weaver|weaver083) $2 binary
    local LABEL=$1 WVBIN=$2
    [[ -n $WVBIN && -x $WVBIN ]] || { log "SKIP $LEGNAME $LABEL (binary not found: ${WVBIN:-unset})"; return; }
    local base=${OUTROOT:A}/$LEGNAME/$LABEL
    # Absolute, because the client below is run from its OWN directory.
    local nzbabs=${NZB:A}
    rm -rf "$base"; mkdir -p "$base/complete" "$base/inter" "$base/data"
    local pfx=$OUTROOT/$LEGNAME/samp.$LABEL
    sampler_start "$base" "$pfx" none "" "$base/complete"
    local t0=$(now)
    # Weaver has a one-shot CLI (`download`), so no daemon/API dance.
    # It bootstraps an encryption key through the macOS Keychain, which
    # fails outright over ssh ("User interaction is not allowed") -
    # WEAVER_ENCRYPTION_KEY supplies one directly, freshly generated per
    # run so nothing persistent is stored. Servers come from env too.
    # PER LEG, never one shared file. cost1g.sh had exactly this gap - a
    # single weaver.out that each leg overwrote - and it blocked a
    # follow-up outright; run-legs.sh carried the same shape until now, so
    # only the LAST leg's Weaver output survived a round. A stale verdict
    # from the previous leg must not leak in either.
    : > "$OUTROOT/$LEGNAME/$LABEL.out"
    # Weaver dedupes submissions against its own state and answers a repeat
    # NZB with "duplicate submission blocked", writing nothing at all - so a
    # re-run of a leg measures the dedupe, not the client. Start it clean.
    rm -rf "$base/data" "$base/inter"
    (
        export WEAVER_ENCRYPTION_KEY=$(openssl rand -base64 32)
        export WEAVER_DATA_DIR=$base/data
        export WEAVER_INTERMEDIATE_DIR=$base/inter
        export WEAVER_COMPLETE_DIR=$base/complete
        export WEAVER_CLEANUP_AFTER_EXTRACT=true
        export WEAVER_SERVER_1_HOSTNAME=127.0.0.1
        export WEAVER_SERVER_1_PORT=$PORT
        export WEAVER_SERVER_1_TLS=false
        export WEAVER_SERVER_1_CONNECTIONS=$CONNS
        export WEAVER_SERVER_1_ACTIVE=true
        # --force bypasses Weaver's semantic duplicate blocking. Without it a
        # leg it has seen before - and it matches on release identity, not
        # content, so the quick corpus poisons the full one - is rejected
        # outright with "duplicate submission blocked", writes nothing, and
        # scores as a failure of the client rather than of the harness.
        # The pipe lives INSIDE the subshell on purpose: $! on a
        # backgrounded PIPELINE names its LAST process (zsh, verified on
        # this box), so piping outside would make $wv the stamper and the
        # kill below would take out the instrument, not the client.
        # RUN FROM ITS OWN DIRECTORY. Weaver keeps its sqlite database in
        # the CURRENT WORKING DIRECTORY, not under WEAVER_DATA_DIR, so
        # every weaver leg of every round so far has shared ONE
        # ~/nested-corpus/weaver.db. That was survivable while a round
        # raced one Weaver; it is not survivable now that a round races
        # two, and the failure is silent in the direction that matters.
        # Measured while smoking this change: running the 0.8.3 arm
        # MIGRATED the shared database to schema version 38, after which
        # the 0.7.8 arm could not open it at all and answered every leg
        # "failed to open database: database has unknown migration
        # version 38" - a whole column of DNFs that would have read as
        # Weaver 0.7.8 regressing, when it was the rig. A per-arm,
        # per-leg cwd also means no leg inherits the previous leg's
        # accumulated state, which can only help the client.
        cd "$base"
        "$WVBIN" download --force "$nzbabs" -o "$base/complete" 2>&1 \
            | python3 "$HERE/stamp.py" > "$OUTROOT/$LEGNAME/$LABEL.out"
    ) &
    local wv=$!
    # Weaver's `download` does NOT exit after finishing (observed: still
    # running at a 900 s cap with every payload already byte-correct and
    # an empty log). Process exit is therefore not a finish signal -
    # poll for the manifest's payload sizes appearing in the output tree
    # and take THAT as time-to-usable-files, which is what the other
    # clients' completion signals mean too.
    local want=$(python3 -c "import json;m=json.load(open('$MANIFEST'));print(' '.join(str(p['bytes']) for p in m['payloads']))")
    local nwant=$(echo $want | wc -w | tr -d ' ')
    local cap=$(cap_for "$LABEL" "$LEGNAME")
    local rc=124 i n sz last_sz=-1 last_move=$(now)
    for i in $(seq 1 $((cap/2))); do
        sleep 2
        n=0
        for w in ${=want}; do
            # NOT under .weaver-staging. Weaver writes the payload there
            # while the job runs and MOVES it out on completion, so a
            # full-size file in staging is work in progress. Counting it
            # made the poll declare the leg finished and KILL Weaver
            # mid-job, then grade the staged file auto-complete: three
            # legs scored that way, each with an `inner.rar.partial`
            # beside the payload and no completion in the log. That is
            # the rig actively harming a competitor, which is the one
            # thing the fairness rule at the top of this file forbids.
            find "$base/complete" -type f -size "${w}c" \
                -not -path '*/.weaver-staging/*' 2>/dev/null | grep -q . && n=$((n+1))
        done
        [[ $n -eq $nwant ]] && { rc=0; break; }
        # progress = the output tree growing. Weaver's `download` never exits,
        # so process liveness proves nothing; bytes on disk do.
        # Weaver reports terminal failure in its own log and then keeps
        # running, so read the log before judging it by disk activity. Without
        # this the stall timer fires on every failed leg and reports a HANG,
        # which is a different and much more serious claim than a failure.
        # Weaver emits at least two terminal strings - "job failed" and
        # "download failed" - and matching only the first made legs that
        # reported the second run out the stall timer and read as HUNG.
        # A failure and a hang are very different published claims.
        if grep -qE "job failed|download failed|ERROR .*failed" "$OUTROOT/$LEGNAME/$LABEL.out" 2>/dev/null; then rc=1; break; fi
        sz=$(du -sk "$base" 2>/dev/null | cut -f1)
        if [[ ${sz:-0} -ne $last_sz ]]; then last_sz=${sz:-0}; last_move=$(now); fi
        # a genuine hang: no payloads, no log verdict, and nothing written for
        # STALL seconds. Only this may be called hung.
        (( $(now) - last_move >= STALL )) && { rc=125; break; }
    done
    local t1=$(now)
    kill -9 $wv 2>/dev/null
    # STOP THE INSTRUMENT BEFORE THE PKILL, and match on more than the
    # path. Both halves are one bug, found by smoking this leg: the
    # sampler's OWN command line carries `--tree $base` and
    # `--match $base/complete`, so `pkill -9 -f "$base/complete"` SIGKILLed
    # the sampler a moment before sampler_stop could ask it for its
    # summary - and a SIGKILLed sampler writes no json, so weaver's memory
    # and disk columns came back `na` while the leg itself looked fine.
    # That is the house rule about killing by pattern (a bare
    # `pkill nzbfast` has killed another session's benchmark leg) turned on
    # our own measurement. Ordering is the fix; the `download --force`
    # anchor, which no sampler command line can carry, is what stops the
    # next person who reorders these three lines from reintroducing it.
    sampler_stop
    # By the UNIQUE INVOCATION, never by binary name. A `pkill -f weaver`
    # on this shared box reaches any other lane's weaver and the other arm
    # of this same round.
    pkill -9 -f "download --force .*$base/complete" 2>/dev/null
    local cls=$(classify "$MANIFEST" "$base/complete" $rc --skip-dirs .weaver-staging)
    [[ $rc -eq 125 ]] && cls=$(echo "$cls" | sed 's/class=[a-z-]*/class=hung/')
    emit_leg "$LEGNAME" "$LABEL" $(secs $t0 $t1) "$pfx" $rc "$cls"
    run_operator "$LEGNAME" "$LABEL" "$base"
}

# ---- main -------------------------------------------------------------

run_leg() { # $1 legdir
    LEGDIR=$1
    LEGNAME=$(basename "$LEGDIR")
    MANIFEST=$LEGDIR/manifest.json
    NZB=$LEGDIR/$LEGNAME.nzb
    [[ -f $MANIFEST && -f $NZB ]] || { echo "skipping $LEGDIR (no manifest/nzb)" >&2; return; }
    mkdir -p "$OUTROOT/$LEGNAME"
    log "### leg $LEGNAME shape=$(jq -r .shape "$MANIFEST") depth=$(jq -r .depth "$MANIFEST")"
    serve_start "$LEGDIR" || return
    for c in $CLIENTS; do
        case $c in
            nzbfast) leg_nzbfast ;;
            nzbget) leg_nzbget nzbget "$NZBGET" ;;
            nzbget_testing) leg_nzbget nzbget_testing "$NZBGET_TESTING" ;;
            sab) leg_sab ;;
            rustnzb) leg_rustnzb ;;
            weaver) leg_weaver weaver "$WEAVER" ;;
            weaver083) leg_weaver weaver083 "$WEAVER083" ;;
            *) echo "unknown client $c" >&2 ;;
        esac
    done
    serve_stop
}

log "### run-legs $(date -u +%Y-%m-%dT%H:%M:%SZ) root=$ROOT clients=$CLIENTS conns=$CONNS timeout=$TIMEOUT"
if [[ -f $ROOT/manifest.json ]]; then
    run_leg "$ROOT"
else
    for m in "$ROOT"/**/manifest.json(N); do
        run_leg "$(dirname "$m")"
    done
fi
log "### run-legs END"
