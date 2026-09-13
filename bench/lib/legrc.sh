#!/usr/bin/env bash
# Sourced as a library by the harnesses; the shebang is for the --selftest
# arm at the foot of the file, which a runner may invoke directly.
# Timed-leg discipline for the bench harnesses: capture the exit code, keep
# stderr, and decide success PER TOOL.
#
# Source it, then use `leg_timed` around anything whose wall time you are
# going to publish:
#
#     . "$(dirname "$0")/../lib/legrc.sh"
#     leg_errdir "$ROOT/logs"
#     leg_timed turboT "myleg" "$TURBO" repair -q "$par2"
#     # -> LEG_WALL LEG_RC LEG_STATUS LEG_ERR
#
# THE RULE, out of a 9 Sep 2026 publication round (bench/component/README.md's
# trap list carries the full account):
# any invocation whose wall time is being recorded must capture its exit code
# and must keep its stderr somewhere a reader can find. A leg whose tool
# exited unexpectedly is a FAILURE, never a time - a refusal returns fast and
# reads as a win. That round published 12.3 s against a rival's 1,413.6 s and
# called it 115x; parfast had declined the solve, named the budget and the
# override on stderr, and exited 5 into `>/dev/null 2>&1`.
#
# `rc != 0` is NOT the test. MultiPar's par2j returns 16 after a SUCCESSFUL
# repair. The per-tool codes live in bench/rc-ok.tsv, which is the single
# definition; scen-summarise.py reads the same file.
#
# This does NOT replace the output gate. A tool can exit 0 having produced the
# wrong bytes, which is what the sha/cmp checks catch. Both gates, always.

# Where per-leg stderr is kept. Defaults beside the script that sourced this.
leg_errdir() { LEG_ERRDIR=$1; mkdir -p "$LEG_ERRDIR"; }
: "${LEG_ERRDIR:=${TMPDIR:-/tmp}/benchlegs}"

# The rc-ok table, resolved once against this file's own directory so a
# harness in any subdirectory finds it.
_LEGRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LEG_RC_TABLE=${LEG_RC_TABLE:-$_LEGRC_DIR/../rc-ok.tsv}

# rc_ok <tool> <rc> - true when <rc> means success for <tool>.
# A tool with no row in the table succeeds on 0 alone. A MISSING table is a
# failure, not a default: it would silently turn par2j's 16 into a failed leg
# (and, worse, a future tool's success code into one).
rc_ok() {
  local tool=$1 rc=$2 codes c
  if [[ ! -f $LEG_RC_TABLE ]]; then
    echo "legrc: rc-ok table missing at $LEG_RC_TABLE" >&2
    return 2
  fi
  codes=$(awk -v t="$tool" '$1 == t && $0 !~ /^#/ { $1 = ""; print; exit }' "$LEG_RC_TABLE")
  [[ -z ${codes// /} ]] && codes=0
  for c in $codes; do [[ $rc == "$c" ]] && return 0; done
  return 1
}

# leg_timed <tool> <label> <cmd...>
# Runs the command, times it, keeps stdout and stderr in $LEG_ERRDIR/<label>.{out,err},
# and sets:
#   LEG_WALL   seconds, 3dp
#   LEG_RC     the exit code
#   LEG_STATUS OK, or RC<n> when the code is not a success code for this tool
#   LEG_ERR    path to the kept stderr
# `|| rc=$?` rather than `cmd; rc=$?`, because under `set -e` a nonzero exit
# takes the whole round down and loses every other arm's leg with it - and a
# refusing arm is a result the rig has to publish.
# shellcheck disable=SC2034  # LEG_* are this function's OUT-parameters.
leg_timed() {
  local tool=$1 label=$2; shift 2
  local t0 t1 rc=0
  mkdir -p "$LEG_ERRDIR"
  LEG_ERR=$LEG_ERRDIR/$label.err
  t0=$(python3 -c 'import time; print(time.time())')
  "$@" > "$LEG_ERRDIR/$label.out" 2> "$LEG_ERR" || rc=$?
  t1=$(python3 -c 'import time; print(time.time())')
  LEG_WALL=$(python3 -c "print('%.3f' % ($t1 - $t0))")
  LEG_RC=$rc
  if rc_ok "$tool" "$rc"; then LEG_STATUS=OK; else LEG_STATUS=RC$rc; fi
}

# leg_flag <status> <gate-flag>
# One place that decides what a leg PRINTS, so an unexpected rc reads as a
# failure in the line itself rather than as a fast wall. The first line of
# the kept stderr is quoted, because that is where the tool said why.
leg_flag() {
  local status=$1 gate=${2:-}
  local out=""
  if [[ $status != OK ]]; then
    local first=""
    [[ -s ${LEG_ERR:-} ]] && first=$(head -1 "$LEG_ERR" | cut -c1-100)
    out="  !! FAILED rc=${status#RC}${first:+ - $first} (stderr: $LEG_ERR)"
  fi
  [[ -n $gate ]] && out="$out  $gate"
  printf '%s' "$out"
}

# --- selftest ---------------------------------------------------------------
# `bash bench/lib/legrc.sh --selftest`. Proves the two things a reader has to
# take on trust: that a nonzero success code is honoured per tool, and that
# BOTH readers of bench/rc-ok.tsv agree - the shell one here and the Python
# one in bench/component/scen-summarise.py. A second copy of that table would
# fail this.
if [[ ${BASH_SOURCE[0]} == "$0" && ${1:-} == --selftest ]]; then
  fail=0
  chk() { # chk <expected ok|no> <tool> <rc>
    if rc_ok "$2" "$3"; then got=ok; else got=no; fi
    if [[ $got == "$1" ]]; then echo "  ok   rc_ok $2 $3 -> $got"
    else echo "  FAIL rc_ok $2 $3 -> $got, wanted $1"; fail=1; fi
  }
  echo "legrc selftest (table: $LEG_RC_TABLE)"
  chk ok par2j 16      # MultiPar: 16 is a repair that WORKED
  chk ok par2j 0
  chk no par2j 5
  chk no turboT 16     # every other arm means 0 and nothing else
  chk ok turboT 0
  chk no parfast 5     # the pain65 refusal

  # One definition, two readers: for every tool the Python reader knows and
  # every code in a sane range, `rc_ok` must give the same verdict. This
  # compares the two IMPLEMENTATIONS, not two copies of a parse, so a second
  # table smuggled into either side fails here.
  n=0
  while read -r tool rc want; do
    if rc_ok "$tool" "$rc"; then got=ok; else got=no; fi
    if [[ $got != "$want" ]]; then
      echo "  FAIL $tool rc=$rc: shell says $got, scen-summarise says $want"; fail=1
    fi
    n=$((n + 1))
  done < <(python3 -c '
import importlib.util, os, sys
d = os.path.dirname(os.path.abspath(sys.argv[1]))
spec = importlib.util.spec_from_file_location(
    "s", os.path.join(d, "..", "component", "scen-summarise.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
# ...plus a tool with no row, whose only success code must be 0.
for tool in sorted(m.RC_OK) + ["some-tool-with-no-row"]:
    ok = m.RC_OK.get(tool, {"0"})
    for rc in range(0, 21):
        print(tool, rc, "ok" if str(rc) in ok else "no")
' "${BASH_SOURCE[0]}")
  # Zero cases is a failure, not a pass: it means the cross-check found
  # nothing to compare, which is the shape every rubber-stamp gate has.
  [[ $n -gt 0 ]] || { echo "  FAIL cross-check produced no cases"; fail=1; }
  [[ $fail == 0 ]] && echo "  ok   both readers agree on $n (tool, rc) cases"

  # A missing table is an error, never a silent default.
  if LEG_RC_TABLE=/nonexistent-rc-ok.tsv rc_ok par2j 16 2>/dev/null; then
    echo "  FAIL a missing table defaulted instead of erroring"; fail=1
  else echo "  ok   a missing table is an error, not a default"; fi

  [[ $fail == 0 ]] && echo "legrc selftest: PASS" || echo "legrc selftest: FAIL"
  exit $fail
fi
