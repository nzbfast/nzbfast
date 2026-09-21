# hlib.sh - the round-start harness stamp for SHELL round drivers.
# SOURCE it (`. "$HARNESS/hlib.sh"`), never execute it.
#
# WHY THIS FILE EXISTS. `plib.ps1`'s `Write-HarnessFacts` and `pdrv.py`'s
# `harness_facts` put one `HARNESS <basename> sha256=... bytes=...` line per
# sourced file, then a `HARNESS-RIG <basename>:<sha16>+...` token, into the
# round log, so a log banked months ago still names the harness revision that
# wrote it (an internal note). Both are
# per-language. The SECOND census over the drivers that live beside their own
# round rather than in this directory found thirteen SHELL round drivers -
# the whole an internal note family and four others - for which
# no such function existed in any language they could call
# (an internal note). This is it.
#
# IT IS NOT the bench rig library's `rig_gen`, AND THE TWO ANSWER
# DIFFERENT QUESTIONS. That library stamps ` rig=rig-lib.sh:<sha16>` onto every
# LEG LINE of a throughput round, naming THE LIBRARY by default (only a driver
# that sets `RIG_GEN_FILE` names itself - one does). This names the DRIVER and
# everything it sources, once, at round start, in the format the other two
# harness libraries already emit, which is the format
# `tools/jcross-position-audit.py`'s `driver_label()` reads. A round wanting
# both is welcome to both; neither is a substitute for the other, and the
# throughput farm was deliberately left on its own mechanism.
#
# POSIX sh, NOT bash. Three of the thirteen drivers are `#!/bin/sh`, so there
# are no arrays and no `local` here - the shell variables are prefixed `_hl_`
# instead, which is the price of being sourceable from all three shells.
#
# IT PRINTS THE LINES AND RETURNS 0 WHATEVER HAPPENS. A stamp is a nicety and
# must never be able to end a round - `Get-RigStamp`'s header in plib.ps1
# carries the same rule and names the field round it killed before it had it.
# An unreadable or missing file is stamped `unreadable` rather than left off,
# for `pdrv.rig_stamp`'s reason: an absent token is indistinguishable from a
# harness older than this block, which never had one.
#
# USE. Pass every file the round sources, starting with the driver itself. A
# driver that writes its log by redirect calls it bare:
#
#     harness_lines "$0"
#
# and one that tees through its own `log` / `say` helper pipes it through that
# helper instead, which is the whole reason this returns lines on stdout
# rather than appending to a file it would have to be told about:
#
#     harness_lines "$0" | while IFS= read -r _l; do log "$_l"; done

_hl_sha256() {  # $1 = path. Prints the 64-hex digest, or nothing.
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  fi
}

harness_lines() {  # $@ = the files this round sources. Prints the stamp.
  # SORTED BY BASENAME then path, matching plib.ps1 and pdrv.py, so the same
  # round driven from two directories composes the same token.
  _hl_sorted=$(for _hl_f in "$@"; do
                 printf '%s\t%s\n' "$(basename "$_hl_f")" "$_hl_f"
               done | LC_ALL=C sort | cut -f2-)
  # ONE pass, and the `HARNESS-RIG` line is printed INSIDE the same subshell
  # that accumulates it. That is the one trap in this file and it fails
  # silently: a `while` fed by a pipe runs in a SUBSHELL in all three shells
  # this is sourced from, so a token built in the loop and printed after it
  # comes out EMPTY while every HARNESS line above it looks right.
  printf '%s\n' "$_hl_sorted" | {
    _hl_parts=''
    while IFS= read -r _hl_f; do
      [ -n "$_hl_f" ] || continue
      _hl_n=$(basename "$_hl_f")
      _hl_h=$(_hl_sha256 "$_hl_f")
      if [ -n "$_hl_h" ]; then
        _hl_b=$(wc -c < "$_hl_f" 2>/dev/null | tr -d ' ')
        printf 'HARNESS %s sha256=%s bytes=%s\n' "$_hl_n" "$_hl_h" "${_hl_b:-0}"
        _hl_parts="$_hl_parts+${_hl_n}:$(printf '%s' "$_hl_h" | cut -c1-16)"
      else
        printf 'HARNESS %s sha256=unreadable bytes=0\n' "$_hl_n"
        _hl_parts="$_hl_parts+${_hl_n}:unreadable"
      fi
    done
    # `${_hl_n}` BRACED, in both branches above, AND IT IS NOT STYLE. zsh
    # applies history-style modifiers to a bare parameter expansion, so
    # `$_hl_n:unreadable` is read as `$_hl_n` with the `:u` UPPERCASE modifier
    # and composes `FILEnreadable` - right under bash and sh, silently wrong
    # under zsh, which is the shell every driver in `the bench rig library` uses.
    # Measured 20 Sep 2026 while writing this file.
    _hl_parts=${_hl_parts#+}
    printf 'HARNESS-RIG %s\n' "${_hl_parts:-unknown}"
  }
  return 0
}
