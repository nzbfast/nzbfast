#!/bin/bash
# Retired instructions, cycles and peak RSS for one command, on either
# host this fleet measures PAR2 on.
#
#   par2-icount.sh <command> [args...]     -> "<instructions> <cycles> <maxrss_bytes>"
#
# WHY THIS EXISTS. Wall time on a shared box is not a score:
# research/PAR2-RIGS-2026-09-02.md is explicit that interleaving removes
# drift and not variance, and on 3 Sep 2026 a 1 GiB repair leg swung +51%
# median between two arms that retired instructions 0.18% apart, because
# four lanes were on the machine. Retired instructions for a FIXED-WORK
# program are very nearly load-independent - measured spread on that same
# leg was 0.15-0.31% across runs at loads from 8 to 113 - so a candidate
# can still be scored on a box somebody else is also using. Cycles and
# RSS are printed beside them and are NOT load-independent; treat them as
# context, not as verdicts.
#
# HOW TO USE IT ON THE TWO KINDS OF SUBJECT:
#
#   * A one-shot driver like `par2_repair_dir` IS its own measurement -
#     the fresh corpus copy and the pre-warm happen outside the process,
#     so the process is the repair. Just wrap it.
#
#   * A harness that BUILDS ITS FIXTURE INSIDE the process (for example
#     `par2_survey_bench`) needs the fixture's cost removed, and it
#     cancels: instr(N) = fixture + N x subject for a fixture whose cost
#     is identical in both arms, so run the harness at 1 pass and at N
#     passes and take (instr(N) - instr(1)) / (N - 1).
#
#     Watch the resolution when you do. A subject whose per-pass cost is
#     a fraction of a percent of the fixture cannot be read at N=21: one
#     shape came out at -99.06%, +99.98% and -103.71% at N=21 depending
#     on which pair was read, and settled to -98.93%, +1.22% and -0.01%
#     at N=501. If the per-pass figure is under about a tenth of a
#     percent of the whole-process count, raise N until it is not, or
#     measure something exact instead - a `pread64` count from
#     `strace -c -f -e trace=pread64` does not care about load either,
#     and is a count rather than a statistic.
#
# Prints "NA NA NA" rather than failing if the counters are unavailable,
# so a caller can tell "not measured" from "measured as zero".
set -u
if [ "$(uname)" = "Darwin" ]; then
  # `/usr/bin/time -l` reports both counters on Apple Silicon.
  out=$(/usr/bin/time -l "$@" 2>&1 >/dev/null)
  i=$(echo "$out" | awk '/instructions retired/{print $1}')
  c=$(echo "$out" | awk '/cycles elapsed/{print $1}')
  m=$(echo "$out" | awk '/maximum resident set size/{print $1}')
else
  # `time -f %M` reports peak RSS in KiB; perf reports the counters.
  out=$(perf stat -x, -e instructions,cycles /usr/bin/time -f '%M' "$@" 2>&1 >/dev/null)
  i=$(echo "$out" | awk -F, '/,instructions/{print $1}')
  c=$(echo "$out" | awk -F, '/,cycles/{print $1}')
  m=$(( $(echo "$out" | grep -E '^[0-9]+$' | tail -1) * 1024 ))
fi
echo "${i:-NA} ${c:-NA} ${m:-NA}"
