#!/bin/bash
# PAR2 bench round, macOS rigs. Same protocol as the existing round.sh, plus
# the classic par2cmdline column: fresh copy of the corpus -> PRE-WARM (read
# every byte once) -> time. Pre-warming is what makes the three rigs
# comparable: `cp -c` here is an APFS clone that leaves pages cached while a
# Windows copy does not.
#
#   round2.sh <leg> <rounds> <root> <ours-bin> [tools]
#
# SCENARIO LEGS (added 6 Sep 2026). `round2.sh row<N> ...` runs the ten
# published scenarios instead - the shapes a reader recognises, built by
# `par2-scenarios-build.sh` and damaged in ARTICLE units by the `amap-*.txt`
# maps. They take a different protocol from the legs above, because they are
# what gets published: each round runs the tool order forward and then
# MIRRORED, idles `SETTLE_MS` between legs outside every timed region, and
# records wall, CPU and peak RSS rather than wall alone. Mirroring is not
# optional politeness - an A/A on this rig has read 5-7% between byte-identical
# binaries from position alone, and a rotate-only order does not cancel it
# (see the README's protocol section, and run `aa-protocol.sh` on any box
# before believing a sub-10% delta measured there).
#
#   round2.sh <row|all> <rounds> <scenario-root> <parfast-bin> [tools]
#
# Rows: row1 row2 row3a row3b row4 row5s100 row5s110 row5m100 row5m110
#       row6 row7a row7b row8 row9 row10 row10v
# Tools: parfast turbo turboT turbo140 parpar (creates only) rarpar classic
#        gopar par2rs (verify/repair only, never creates) turbo120 parmesan
#
# gopar and par2rs (added 7 Sep 2026, roster completion from
# research/PAR2-RIVAL-SURVEY-2026-09-05.md): both take the same `r`/`v`
# verb par2cmdline does, so they ride $verb directly. gopar PANICS with
# "invalid goroutine count" on Apple silicon unless `-g <n>` is passed
# (its default comes out 0 there); every gopar invocation below carries
# `-g "$THREADS"`. gopar's create dialect takes a recovery BLOCK COUNT,
# not a percentage, so run_create derives it from the members' block
# count at that slice size. par2rs has no create subcommand at all -
# its create arm is a no-op, same as rarpar/parpar's out-of-scope arms.
#
# parmesan (added 13 Sep 2026, for the next full all-tools round) is
# pesto's PAR2 tool, https://github.com/franzopl/pesto
# crates/parmesan - build `cargo build --release -p parmesan-par2` and copy
# target/release/parmesan into $BIN. It does NOT speak par2cmdline's
# dialect: subcommands `create` / `verify` / `repair`, `-o <dir> -b <base>`
# instead of an output path, and verify/repair scan the INDEX file's own
# directory for members and volumes (no -B). Arms run at its defaults (auto
# threads, 1 GiB memory limit). Its exit codes are par2cmdline's (0 ok,
# 1 damaged-repairable, 2 not repairable), so it needs no rc-ok.tsv row.
# First measured in research/PARMESAN-COMPARE-2026-09-13.md: creation near
# turbo, repair 5-16x behind turbo on a 1,000-file set (no NEON/GFNI decode
# kernel yet), 18/18 cross-tool repairs byte-identical.
set -euo pipefail

# Timed-leg discipline: rc captured, stderr kept, success decided PER TOOL
# from bench/rc-ok.tsv. See the library header, and the README's trap list
# for the round this came out of.
# shellcheck source=../lib/legrc.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/legrc.sh"

# ===========================================================================
# The scenario legs. Everything below this line is the published rig; the
# legs above it are the older block-named round and stay as they were so the
# earlier numbers remain reproducible.
# ===========================================================================
if [[ ${1:-} == row* || ${1:-} == all ]]; then
  row=$1; rounds=${2:-2}; ROOT=${3:?scenario root}; OURS=${4:?parfast binary}
  TOOLS=${5:-parfast,turboT,parpar,rarpar}
  BIN=${BIN:-$HOME/parshoot3/bin}
  TURBO=${TURBO:-$BIN/par2turbo150}
  # 1.4.0 is the build NZBGet ships, so it is the version most readers
  # actually have rather than the newest one.
  TURBO14=${TURBO14:-$BIN/par2turbo}
  PARPAR=${PARPAR:-$BIN/parpar}
  RARPAR=${RARPAR:-$BIN/rarpar}
  CLASSIC=${CLASSIC:-$BIN/par2}
  # Rival-survey arms, roster completion 7 Sep 2026 - see the header note.
  GOPAR=${GOPAR:-$BIN/gopar}
  PAR2RS=${PAR2RS:-$BIN/par2rs-cli}
  TURBO120=${TURBO120:-$BIN/par2turbo120utf8}
  PARMESAN=${PARMESAN:-$BIN/parmesan}
  # Recovery percentage for the CREATE legs (row7a/row7b) - see the fuller
  # comment on the legacy path's own default below. Redefined here because
  # the scenario block returns via `exit 0` before ever reaching that line,
  # so a row-based invocation left it unbound (found 7 Sep 2026 racing the
  # rival-roster arms: every create leg died "REDUND: unbound variable").
  REDUND=${REDUND:-10}
  THREADS=${THREADS:-$( (sysctl -n hw.logicalcpu 2>/dev/null || nproc) )}
  SETTLE_MS=${SETTLE_MS:-1000}
  W=${W:-${TMPDIR:-/tmp}/parscen-work}
  L=$W/logs; mkdir -p "$L"
  HERE=$(cd "$(dirname "$0")" && pwd)

  # ONE work dir per box, so two lanes running this rig at once do not merely
  # contend for CPU - they overwrite each other's fixture copy between the
  # prepare and the timed region, and the leg then times ANOTHER ROW'S BYTES.
  # Measured 7 Sep 2026, two chips four minutes apart on the M1: the row5m100
  # legs ran over the other lane's row1 tree and read 0.43 s / 1.01 s with
  # sha=MISMATCH on both arms. The gate caught it, which is the only reason it
  # was not published as a result - a shape whose two arms both "fail" reads
  # like a fixture problem, not like a second lane. So refuse rather than
  # clobber: the second lane gets its own dir with `W=<path> round2.sh ...`.
  # The lock is re-entrant through the environment, because `all` re-invokes
  # this script once per row and those children are the SAME run.
  if [[ ${PARSCEN_LOCK:-} != "$W.lock" ]]; then
    if ! mkdir "$W.lock" 2>/dev/null; then
      holder=$(cat "$W.lock/pid" 2>/dev/null || true)
      if [[ -n ${holder:-} ]] && kill -0 "$holder" 2>/dev/null; then
        echo "round2.sh: $W is held by pid $holder (another lane's round)." >&2
        echo "  Read \$HOME/bench-out/COORDINATION-*.txt; then either wait, or" >&2
        echo "  run with a work dir of your own:  W=\$TMPDIR/parscen-mine $0 ..." >&2
        exit 3
      fi
      # The holder is gone: a killed or crashed run left the lock behind.
      rm -rf "$W.lock"; mkdir "$W.lock"
    fi
    echo $$ > "$W.lock/pid"
    trap 'rm -rf "$W.lock"' EXIT
    export PARSCEN_LOCK="$W.lock"
  fi

  now() { python3 -c 'import time; print(time.time())'; }
  settle() { python3 -c "import time; time.sleep($SETTLE_MS/1000.0)"; }

  # wall + CPU + peak RSS for one child. macOS `time -l` reports RSS in bytes,
  # GNU `time -v` in KiB; neither is on PATH as the shell builtin, so the
  # absolute path is load-bearing.
  timed() { # timed <label> <cmd...>
    local label=$1; shift
    local t0 t1 rc rss cpu
    t0=$(now)
    # `cmd; rc=$?` is NOT enough under `set -e`: a tool that exits nonzero
    # takes the whole round down silently, which is exactly what an arm that
    # REFUSES a shape does - and refusing is a result the rig has to publish,
    # not a reason to lose the other arms' legs with it.
    rc=0
    if [[ $(uname) == Darwin ]]; then
      /usr/bin/time -l "$@" > "$L/$label.out" 2> "$L/$label.err" || rc=$?
      rss=$(( $(awk '/maximum resident/ {print $1; exit}' "$L/$label.err" || echo 0) / 1048576 ))
      cpu=$(awk '/ real/ {print $3 + $5; exit}' "$L/$label.err")
    else
      /usr/bin/time -v "$@" > "$L/$label.out" 2> "$L/$label.err" || rc=$?
      rss=$(( $(awk -F': ' '/Maximum resident/ {print $2; exit}' "$L/$label.err" || echo 0) / 1024 ))
      cpu=$(awk -F': ' '/User time|System time/ {s+=$2} END {print s}' "$L/$label.err")
    fi
    t1=$(now)
    WALL=$(python3 -c "print('%.2f' % ($t1 - $t0))"); RC=$rc; RSS=$rss; CPU=${cpu:-0}
    # The rc is already on the LEG line for the summariser; STATUS puts the
    # same verdict where a HUMAN reads it, so an arm that refused cannot pass
    # for a fast wall. `rc_ok` is per tool - par2j's 16 is a repair that
    # WORKED - and its table is bench/rc-ok.tsv, the single definition.
    if rc_ok "${TOOL:-}" "$rc"; then STATUS=OK; else STATUS=FAILED-rc$rc; fi
    LEG_ERR=$L/$label.err
  }

  # Every repaired or verified set is checked against the pristine reference,
  # so a tool that finishes fast by not fixing anything reports sha=MISMATCH
  # rather than a winning time. A blank cell is not an acceptable result and
  # neither is an unchecked one.
  sha_gate() { # sha_gate <workdir> <reference .sha>
    ( cd "$1" && shasum -a 256 -c "$2" > /dev/null 2>&1 ) && echo OK || echo MISMATCH
  }

  # --- the rig each row runs over -----------------------------------------
  # fixture   = the damaged (or clean) directory to copy
  # reference = the pristine .sha the repair is gated against, "" for verify
  # kind      = repair | verify | create
  # fixture   = the damaged directory to copy, when the rig holds one
  # pristine  = the clean fixture, and `map` the damage to cut into a copy of
  #             it when `fixture` is absent. A rig on a filesystem with no
  #             cheap clones (NTFS) holds only the pristine trees and pays one
  #             copy per leg instead of eight standing copies of a 10 GiB
  #             fixture - the i5 has 75 GB free, and the M3's clones cost the
  #             blocks they damage. Either way the leg times the same bytes.
  # reference = the pristine .sha the repair is gated against, "" for verify
  # kind      = repair | verify | create
  map=
  case $row in
    row1)     fixture=row1-tv-2articles;     pristine=tv;    map=amap-row1-tv.txt;         reference=$ROOT/tv.sha;    kind=repair ;;
    row2)     fixture=row2-movie-12articles; pristine=movie; map=amap-row2-movie.txt;      reference=$ROOT/movie.sha; kind=repair ;;
    row3a)    fixture=row3-movie-gap;        pristine=movie; map=amap-row3-movie-gap.txt;  reference=$ROOT/movie.sha; kind=repair ;;
    row3b)    fixture=row3-movie-volgone;    pristine=movie; map=amap-row3-movie-most.txt; reference=$ROOT/movie.sha; kind=repair ;;
    row4)     fixture=row4-movie-deleted;    pristine=movie; map=amap-row4-movie.txt;      reference=$ROOT/movie.sha; kind=repair ;;
    row5s100) fixture=row5-single-100; pristine=pars-single-100; map=amap-row5-single.txt; reference=$ROOT/pars-single.sha; kind=repair ;;
    row5s110) fixture=row5-single-110; pristine=pars-single-110; map=amap-row5-single.txt; reference=$ROOT/pars-single.sha; kind=repair ;;
    row5m100) fixture=row5-multi-100;  pristine=pars-multi-100;  map=amap-row5-multi.txt;  reference=$ROOT/pars-multi.sha;  kind=repair ;;
    row5m110) fixture=row5-multi-110;  pristine=pars-multi-110;  map=amap-row5-multi.txt;  reference=$ROOT/pars-multi.sha;  kind=repair ;;
    row6)     fixture=movie;                 pristine=movie;  reference=;               kind=verify ;;
    row7a)    fixture=create;                pristine=create; reference=;               kind=create; cbs=1048576 ;;
    row7b)    fixture=create;                pristine=create; reference=;               kind=create; cbs=1536000 ;;
    row8)     fixture=row8-album-1article;   pristine=album;  map=amap-row8-album.txt;  reference=$ROOT/album.sha; kind=repair ;;
    row9)     fixture=row9-heavy-1500blocks; pristine=heavy;  map=map-heavy-1500.txt;   reference=$ROOT/heavy.sha; kind=repair ;;
    row10)    fixture=row10-sports-1article; pristine=sports; map=amap-row10-sports.txt; reference=$ROOT/sports.sha; kind=repair ;;
    row10v)   fixture=sports;                pristine=sports; reference=;               kind=verify ;;
    all) for r in row1 row2 row3a row3b row4 row6 row5s100 row5s110 row5m100 row5m110 \
                  row7a row7b row8 row9 row10 row10v; do
           "$0" "$r" "$rounds" "$ROOT" "$OURS" "$TOOLS"
         done; exit 0 ;;
    *) echo "unknown row $row" >&2; exit 2 ;;
  esac

  prepare() { # a fresh copy of the fixture, then an explicit pre-warm
    rm -rf "$W/r"
    if [[ -d "$ROOT/$fixture" ]]; then
      cp -c -R "$ROOT/$fixture" "$W/r" 2>/dev/null || cp -R "$ROOT/$fixture" "$W/r"
    else
      # No standing damaged copy: cut this row's damage into a fresh copy of
      # the pristine fixture. Same bytes, same map, outside the timed region.
      python3 "$HERE/apply-damage.py" "$ROOT/$pristine" "$W/r" "$HERE/$map" > /dev/null
    fi
    cat "$W/r"/* > /dev/null 2>&1 || true
  }

  run_repair_or_verify() { # <tool> <obs>
    # `local a=$1 b="$a"` does NOT work: local expands all its words before
    # it assigns any of them, so the label is built on its own line.
    local tool=$1 o=$2 par
    local label="$row-$tool-$o"
    TOOL=$tool
    prepare; settle
    # The INDEX file, never a volume: `ls *.par2 | grep -v vol` is the rule the
    # rig has always used and the .vol-NN naming on row 10 goes through it too.
    par=$(cd "$W/r" && ls ./*.par2 | grep -v 'vol' | head -1)
    local verb=r; [[ $kind == verify ]] && verb=v
    case $tool in
      parfast) timed "$label" "$OURS" $verb -q "$W/r/$par" ;;
      # `-T` is turbo's FILES-HASHED-IN-PARALLEL count, not its compute-thread
      # knob - that is lower-case `-t` and already defaults to the detected
      # core count, so this arm is a wide hash fan-out and the plain `turbo`
      # arm is not handicapped. Name kept for comparability; README trap.
      turboT)  timed "$label" "$TURBO" $verb -q -T"$THREADS" "$W/r/$par" ;;
      turbo)   timed "$label" "$TURBO" $verb -q "$W/r/$par" ;;
      turbo140) timed "$label" "$TURBO14" $verb -q -T"$THREADS" "$W/r/$par" ;;
      classic) timed "$label" env DYLD_FALLBACK_LIBRARY_PATH="$BIN" "$CLASSIC" $verb -q "$W/r/$par" ;;
      rarpar)  if [[ $kind == verify ]]; then timed "$label" "$RARPAR" par verify "$W/r"
               else timed "$label" "$RARPAR" par repair -C "$W/r" "$W/r"; fi ;;
      parpar)  return 0 ;;   # creates only
      turbo120) timed "$label" "$TURBO120" $verb -q -T"$THREADS" "$W/r/$par" ;;
      # gopar and par2rs both speak par2cmdline's r/v verbs, so $verb
      # carries straight through. gopar needs -g (see the header note).
      gopar)   timed "$label" "$GOPAR" -g "$THREADS" "$verb" "$W/r/$par" ;;
      par2rs)  timed "$label" "$PAR2RS" "$verb" "$W/r/$par" ;;
      # parmesan spells the verbs out; see the header note.
      parmesan) if [[ $kind == verify ]]; then timed "$label" "$PARMESAN" verify -q "$W/r/$par"
                else timed "$label" "$PARMESAN" repair -q "$W/r/$par"; fi ;;
      *) echo "unknown tool $tool" >&2; return 0 ;;
    esac
    local sha=n/a
    [[ -n $reference ]] && sha=$(sha_gate "$W/r" "$reference")
    printf 'LEG row=%s tool=%-7s obs=%s wall=%s cpu=%s rss_mb=%s rc=%s status=%s sha=%s err=%s\n' \
      "$row" "$tool" "$o" "$WALL" "$CPU" "$RSS" "$RC" "$STATUS" "$sha" "$LEG_ERR"
  }

  # The SAME trap REDUND hit on 7 Sep, one variable over: the scenario block
  # returns via `exit 0` long before the legacy path's `SLICE=${SLICE:-}`, so
  # a row invocation reached this line with SLICE unbound and `set -u` killed
  # the round before its first leg. Found 10 Sep 2026 smoking the rc/stderr
  # work on a synthetic row6 fixture - `round2.sh row<N> ...` could only run
  # at all with SLICE exported into the environment.
  SLICE=${SLICE:-}
  if [[ -n $SLICE ]]; then cbs=$SLICE; fi

  run_create() { # <tool> <obs>
    local tool=$1 o=$2 src=$ROOT/$fixture out=$W/c
    local label="$row-$tool-$o"
    TOOL=$tool
    rm -rf "$out"; mkdir -p "$out"
    local files; files=$(ls "$src"/*.bin)
    cat $files > /dev/null; settle
    # shellcheck disable=SC2086
    case $tool in
      parfast) timed "$label" "$OURS" c -q -s$cbs -r"$REDUND" -B"$src" "$out/set.par2" $files ;;
      turboT)  timed "$label" "$TURBO" c -q -s$cbs -r"$REDUND" -T"$THREADS" -B"$src" "$out/set.par2" $files ;;
      turbo)   timed "$label" "$TURBO" c -q -s$cbs -r"$REDUND" -B"$src" "$out/set.par2" $files ;;
      turbo140) timed "$label" "$TURBO14" c -q -s$cbs -r"$REDUND" -T"$THREADS" -B"$src" "$out/set.par2" $files ;;
      parpar)  timed "$label" "$PARPAR" -q -s${cbs}b -r "$REDUND%" -o "$out/set.par2" $files ;;
      classic) timed "$label" env DYLD_FALLBACK_LIBRARY_PATH="$BIN" "$CLASSIC" c -q -s$cbs -r"$REDUND" -B"$src" "$out/set.par2" $files ;;
      rarpar)  return 0 ;;   # repairs only
      par2rs)  return 0 ;;   # verify/repair only, never creates
      turbo120) timed "$label" "$TURBO120" c -q -s$cbs -r"$REDUND" -T"$THREADS" -B"$src" "$out/set.par2" $files ;;
      gopar)
        # A recovery COUNT, not a percentage: derive it from the members'
        # block count at this leg's slice size so gopar asks for the same
        # 10% redundancy every other arm gets (par2-create-legs.sh trap).
        # gopar has no -B: it refuses with "data files must lie in
        # basePath" unless every input shares the output's directory
        # (a literal path-prefix check, not a symlink-following one), so
        # the members are symlinked into $out first and gopar is pointed
        # at the symlinks rather than $files in $src.
        local nb=0 f sz gfiles=()
        for f in $files; do
          sz=$(wc -c < "$f"); nb=$((nb + (sz + cbs - 1) / cbs))
          ln -sf "$f" "$out/$(basename "$f")"; gfiles+=("$out/$(basename "$f")")
        done
        timed "$label" "$GOPAR" -g "$THREADS" c -s "$cbs" -c "$(( (nb * REDUND + 99) / 100 ))" "$out/set.par2" "${gfiles[@]}" ;;
      # parmesan names its output by directory + base name, never by path,
      # and stores each member by its bare file name like the others.
      parmesan) timed "$label" "$PARMESAN" create -q -s "$cbs" -r "$REDUND" -o "$out" -b set $files ;;
      *) echo "unknown tool $tool" >&2; return 0 ;;
    esac
    # A created set counts only if a DIFFERENT tool can read it back.
    for f in $files; do ln -sf "$f" "$out/"; done
    "$TURBO" v -q "$out/set.par2" > "$L/$label.verify" 2>&1; local vrc=$?
    find "$out" -type l -delete
    printf 'LEG row=%s tool=%-7s obs=%s wall=%s cpu=%s rss_mb=%s rc=%s status=%s turbo_verify=%s r=%s slice=%s err=%s\n' \
      "$row" "$tool" "$o" "$WALL" "$CPU" "$RSS" "$RC" "$STATUS" "$vrc" "$REDUND" "$cbs" "$LEG_ERR"
  }

  one() { if [[ $kind == create ]]; then run_create "$@"; else run_repair_or_verify "$@"; fi; }

  echo "=== $row ($kind, $fixture, $rounds round(s) mirrored, tools $TOOLS, settle ${SETTLE_MS}ms)"
  IFS=',' read -r -a arms <<< "$TOOLS"
  obs=0
  for _ in $(seq "$rounds"); do
    obs=$((obs + 1)); for t in "${arms[@]}"; do one "$t" "$obs"; done
    obs=$((obs + 1))
    for ((i = ${#arms[@]} - 1; i >= 0; i--)); do one "${arms[$i]}" "$obs"; done
  done
  rm -rf "$W/r" "$W/c"
  exit 0
fi

# Recovery percentage for the CREATE legs.  10 is the census MODE and not a
# bucket: of 189 random PAR2-bearing posts over 1 GB, 65 sit at exactly 10%
# and only 2 at 15%, and 10 is modal for ParPar, MultiPar and QuickPar taken
# separately (par2cmdline's own 8% default is the exception).  20 is the
# second real cluster at 10.6% of posts.  Sweeping this is a SENSITIVITY
# line, never a second population row.
REDUND=${REDUND:-10}
# Override a row's slice size in BYTES; empty keeps the row's own.  The sizes
# worth sweeping are the ones posters use, and they are NOT round numbers:
# over 189 random PAR2-bearing posts over 1 GB the repeating values are
# 1048576 (n=29, the median), 768000 (n=20), 716800 (n=14) and 1536000 (n=7).
# 4194304 appears ZERO times, which is why row7b stopped being a 4 MiB leg.
SLICE=${SLICE:-}
leg=${1:-verify}; rounds=${2:-3}; ROOT=${3:?root}; OURS=${4:?ours binary}
tools=${5:-ours,turboT,turboD,rarpar,classic}
TURBO=${TURBO:-$ROOT/bin/par2turbo}
RARPAR=${RARPAR:-$ROOT/bin/rarpar}
CLASSIC=${CLASSIC:-$ROOT/bin/par2}
WORK=$ROOT/work-round2

D_SITE=${D_SITE:-pristine}
D_R101=${D_R101:-damaged-101}
D_R3=${D_R3:-damaged-3}
D_HEAVYP=${D_HEAVYP:-pristine-heavy}
D_HEAVYD=${D_HEAVYD:-damaged-heavy}
case $leg in
  verify) src=$D_SITE;   pris=$D_SITE;   repair=0 ;;
  rep101) src=$D_R101;   pris=$D_SITE;   repair=1 ;;
  rep3)   src=$D_R3;     pris=$D_SITE;   repair=1 ;;
  heavy)  src=$D_HEAVYD; pris=$D_HEAVYP; repair=1 ;;
  *) echo "unknown leg $leg" >&2; exit 2 ;;
esac
par2=$(cd "$ROOT/$src" && ls ./*.par2 | grep -v vol | head -1)

# Per-leg stderr, kept where a reader can find it after the run. Overridable
# so two lanes on one box do not write over each other.
leg_errdir "${ROUND2_LOGS:-$ROOT/logs-round2}"
obsn=0

run_one() {
  local tool=$1
  rm -rf "$WORK"
  cp -c -R "$ROOT/$src" "$WORK" 2>/dev/null || cp -R "$ROOT/$src" "$WORK"
  cat "$WORK"/* > /dev/null 2>&1   # pre-warm
  local verb=verify; [[ $repair == 1 ]] && verb=repair
  local label="$leg-$tool-$obsn" back=$PWD
  # Every arm below runs through `leg_timed`, which captures the exit code and
  # keeps stderr. It used to run through `>/dev/null 2>&1 || true`, and on
  # 9 Sep 2026 that exact shape published a REFUSAL as a 115x win: the tool
  # printed the budget it was over and the variable that raises it, exited 5,
  # and the harness recorded the fast return as a time. Discarding a timed
  # leg's streams is how a rig lies about its own subject.
  cd "$WORK"
  case $tool in
    # The product default since e206ede6: the driver mirrors the daemon's
    # "fast par mode", so this row is what a user gets today.
    ours)   leg_timed "$tool" "$label" "$OURS" . ;;
    # `oursntt` is retained as an explicit-NTT row for older drivers and
    # for A/B against the fold; on a current driver it matches `ours`.
    oursntt) leg_timed "$tool" "$label" env NZBFAST_NTT=1 "$OURS" . ;;
    # The fold, i.e. fast par mode turned off. This is the comparison
    # column, not the shipping one.
    oursfold) leg_timed "$tool" "$label" env NZBFAST_NTT=0 "$OURS" . ;;
    # `-T16` is turbo's FILES-HASHED-IN-PARALLEL knob, not its compute
    # thread count - that is lower-case `-t`, and it defaults to the
    # detected core count. This arm is therefore "turbo with a wide hash
    # fan-out", not "turbo pinned to 16 threads", and it has never
    # handicapped turbo. The name is kept so the older numbers stay
    # comparable; the flag is what it always was. See the README's trap
    # list.
    turboT) leg_timed "$tool" "$label" "$TURBO" $verb -q -T16 "$par2" ;;
    turboD) leg_timed "$tool" "$label" "$TURBO" $verb -q "$par2" ;;
    rarpar) if [[ $repair == 1 ]]; then leg_timed "$tool" "$label" "$RARPAR" par repair -C "$WORK" "$WORK"
            else leg_timed "$tool" "$label" "$RARPAR" par verify "$WORK"; fi ;;
    classic) leg_timed "$tool" "$label" env DYLD_FALLBACK_LIBRARY_PATH="$ROOT/bin" "$CLASSIC" $verb -q "$par2" ;;
    *) cd "$back"; echo "unknown tool $tool" >&2; return 0 ;;
  esac
  cd "$back"
  # The OUTPUT gate stays, and stays SEPARATE: a tool can exit 0 having
  # produced the wrong bytes, which no exit code can catch.
  local bad=0
  if [[ $repair == 1 ]]; then
    for f in "$ROOT/$pris"/*.rar; do cmp -s "$f" "$WORK/$(basename "$f")" || bad=1; done
  fi
  local gate=""
  [[ $bad == 0 ]] || gate="!! MISMATCH"
  # An unexpected rc prints INSTEAD of a bare time, so neither a human nor a
  # parser can read a refusal as a result.
  printf '  %-8s %8.3fs rc=%-3s%s\n' "$tool" "$LEG_WALL" "$LEG_RC" "$(leg_flag "$LEG_STATUS" "$gate")"
}

echo "=== $leg (warm protocol, $rounds rounds, $tools) ==="
echo "    per-leg stderr: $LEG_ERRDIR"
for _ in $(seq "$rounds"); do
  obsn=$((obsn + 1))
  for t in ${tools//,/ }; do run_one "$t"; done
done
rm -rf "$WORK"
