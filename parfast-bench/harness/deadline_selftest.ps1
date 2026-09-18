#!/usr/bin/env pwsh
#
# deadline_selftest.ps1 - the selftest for deadline.ps1's PID CONFIRMATION.
#
#     pwsh -NoProfile -File harness/deadline_selftest.ps1
#
# Runs in CI on a macOS runner through `tools/rig-selftest-gate.py
# --run-deadline` (job `plib-selftest` in .github/workflows/rig-selftest.yml),
# beside plib_selftest.ps1 and for the same reason: this is Windows-only code,
# no Mac on this fleet runs the Windows drivers, and every line of the
# documented gate suite in CLAUDE.md is host-target and blind to it.
#
# WHAT IT HOLDS, AND WHY IT IS WORTH A FILE. deadline.ps1 is the safety
# mechanism for BORROWED machines - two of the boxes it guards are borrowed
# gaming PCs, lent for a stated window - and on 17 Sep 2026 it failed in the
# worst available way, on both of them, in the same minute. wlaunch.ps1 armed
# it on the FIRST powershell child of the cmd.exe it spawned, which was a
# transient rather than the round (21900 against a round of 2864; 1596 against
# 10028). Each watcher saw that process vanish, counted three empty samples,
# and exited printing `DEADLINE-ROUND-FINISHED on its own` - 32 and 36 minutes
# before those rounds ended. An operator reading the log saw a success-shaped
# line over a guard that had stopped guarding, and it was caught only because a
# later lane matched pids by hand.
#
# The fix is a REFUSAL, and a refusal is exactly the arm that never runs in
# normal operation and so rots unseen. Hence this file. Every case below is a
# way that failure could come back:
#
#   1. a pid that is not the round is CORRECTED against the round's own
#      RIG-LOCK-TAKEN line, and the kill lands on the corrected pid;
#   2. an UNCONFIRMED pid never disarms the watcher, however many empty
#      samples it sees, and the run ends nonzero saying a human must look;
#   3. a CONFIRMED pid still retires the watcher early on three empty samples -
#      the fix must not turn every finished round into a watcher that outlives
#      it;
#   4. an unconfirmed watcher DOES stand down when the round's own log says the
#      round is over, because that is evidence rather than an absence;
#   5. the RIG-LOCK-TAKEN parse itself, including against a log a writer still
#      holds open, which is the shape it is read in on a live box.
#
# HERMETIC. `$env:USERPROFILE` is repointed at a temp directory before anything
# runs, so the lock-release block at the end of deadline.ps1 cannot touch a real
# `.parfast-rig.lock`; the "rounds" are `pwsh -Command Start-Sleep` processes
# this file starts and reaps itself; the deadlines are seconds out and the
# watcher is driven at `-pollSec 1`. No Windows, no quiet box, no rig.
#
# WHAT IT DOES NOT REACH, stated rather than left to be found:
#
#   - the PATTERN (`-match`) arm, which is Win32_Process on Windows and has no
#     macOS equivalent. It is unchanged by this work and its own wart is
#     documented in deadline.ps1's header.
#   - DEADLINE-REFUSING-KILL, the recycled-pid guard. Producing it needs a
#     process that STARTS AFTER the watcher armed and holds a pid the watcher
#     was already given, which cannot be arranged without knowing that pid
#     before the process exists. The arm is three lines and fails safe (it
#     kills nothing and exits 3); it is read, not driven.
#   - the CIM half of Update-Confirmation's weak command-line check, for the
#     same reason as the pattern arm.
$ErrorActionPreference = 'Stop'
$HERE = Split-Path -Parent $PSCommandPath
$script:checks = 0
$script:fails = 0

function Check([bool]$ok, [string]$what) {
  $script:checks++
  if ($ok) { "ok   $what" } else { $script:fails++; "FAIL $what" }
}

function Has([string]$text, [string]$needle) { return ($text -match [regex]::Escape($needle)) }

# A round log as plib.ps1 writes one. The RIG-LOCK-TAKEN line is
# Write-RigLockIdentity's, byte for byte in shape - if that format moves, these
# fixtures are what notice.
function New-RoundLog([string]$path, [int]$pid_, [string]$round, [switch]$Finished) {
  $lines = @()
  if ($pid_ -gt 0) {
    $lines += "RIG-LOCK-TAKEN $env:USERPROFILE/.parfast-rig.lock round=$round pid=$pid_ started=$((Get-Date).ToUniversalTime().ToString('o'))"
  }
  $lines += "ROUND tag=$round phase=rowgate start=$((Get-Date).ToUniversalTime().ToString('o'))"
  if ($Finished) {
    $lines += "ALL DONE end=$((Get-Date).ToUniversalTime().ToString('o'))"
    $lines += "RIG-LOCK-RELEASED $env:USERPROFILE/.parfast-rig.lock"
  }
  Set-Content -Path $path -Value ($lines -join "`n")
}

function Start-Sleeper([int]$seconds) {
  return Start-Process -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoProfile', '-Command', "Start-Sleep -Seconds $seconds") -PassThru
}

# A DEAD pid that was ONCE a real process - which is what the watcher was given
# on 17 Sep 2026. Killed and WAITED FOR rather than given a short sleep and
# raced: a `Start-Sleep 1` child can still be starting two seconds later on a
# loaded runner, and a case that sometimes watches a LIVE process is a case
# that sometimes tests nothing.
function New-DeadPid {
  $p = Start-Sleeper 120
  Stop-Process -Id $p.Id -Force
  $p.WaitForExit(15000) | Out-Null
  return $p
}

# Runs deadline.ps1 as a REAL child process, the way a box runs it, and returns
# its transcript and exit code. Not dot-sourced: this script's subject calls
# `exit`, and a dot-sourced exit takes the selftest down with it.
function Invoke-Deadline([string[]]$ps1args) {
  $out = Join-Path $TMP ("dl-" + [guid]::NewGuid().ToString('N') + ".log")
  $p = Start-Process -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList (@('-NoProfile', '-File', (Join-Path $HERE 'deadline.ps1')) + $ps1args) `
    -RedirectStandardOutput $out -RedirectStandardError "$out.err" -PassThru -Wait
  $text = ''
  if (Test-Path $out) { $text = Get-Content $out -Raw }
  if (-not $text) { $text = '' }
  return [pscustomobject]@{ Text = $text; Code = $p.ExitCode }
}

function In([int]$seconds) { return (Get-Date).ToUniversalTime().AddSeconds($seconds).ToString('o') }

$TMP = Join-Path ([IO.Path]::GetTempPath()) ("deadline-selftest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TMP -Force | Out-Null
$env:USERPROFILE = $TMP
$env:HOME = $env:HOME   # untouched; only USERPROFILE is read by the subject

try {
  "== deadline_selftest.ps1 =="

  # ---------------------------------------------------------------- 1. parse
  . (Join-Path $HERE 'plib.ps1')
  $ErrorActionPreference = 'Stop'
  $lg = Join-Path $TMP 'parse.log'
  New-RoundLog $lg 4242 'rgx'
  $f = Get-RoundLogFacts $lg
  Check ($f.Pid -eq 4242) 'Get-RoundLogFacts reads the pid out of RIG-LOCK-TAKEN'
  Check ($f.Round -eq 'rgx') 'Get-RoundLogFacts reads the round tag'
  Check (-not $f.Finished) 'a running round is not Finished'

  New-RoundLog $lg 4242 'rgx' -Finished
  $f = Get-RoundLogFacts $lg
  Check ($f.Finished) 'ALL DONE / RIG-LOCK-RELEASED makes it Finished'

  $lg2 = Join-Path $TMP 'nolock.log'
  Set-Content -Path $lg2 -Value "ROUND tag=rgx phase=rowgate`nsome output"
  $f = Get-RoundLogFacts $lg2
  Check ($f.Pid -eq 0) 'a log with no RIG-LOCK-TAKEN line yields no pid'
  Check ((Get-RoundLogFacts (Join-Path $TMP 'nope.log')).Pid -eq 0) 'a missing log yields no pid and does not throw'
  Check ((Get-RoundLogFacts '').Pid -eq 0) 'an empty path yields no pid and does not throw'

  # The shape it is read in on a live box: the round's stdout is held open by
  # the cmd.exe redirect that launched it. A plain Get-Content can lose to that
  # on Windows; Read-SharedText is why this one does not.
  $lg3 = Join-Path $TMP 'open.log'
  $fs = [IO.File]::Open($lg3, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  $sw = New-Object IO.StreamWriter($fs)
  $sw.WriteLine("RIG-LOCK-TAKEN $TMP/.parfast-rig.lock round=live pid=777 started=x")
  $sw.Flush()
  $f = Get-RoundLogFacts $lg3
  Check ($f.Pid -eq 777) 'the pid is readable while a writer still holds the log open'
  $sw.Dispose(); $fs.Dispose()

  # ----------------------------------------------------- 2. the CORRECTION
  # The 17 Sep 2026 shape exactly: the watcher is handed a transient that dies
  # at once, and the round - a different, live process - names itself in the
  # log. The watcher must notice, re-arm, and kill the ROUND at the deadline.
  "-- case: a pid that is not the round is corrected against the round's log"
  $round = Start-Sleeper 120
  $decoy = New-DeadPid
  $decoyPid = $decoy.Id
  $lg = Join-Path $TMP 'correct.log'
  New-RoundLog $lg $round.Id 'rgcorrect'
  Check ($decoy.HasExited) 'the decoy process is gone before the watcher polls'
  $r = Invoke-Deadline @('-untilUtc', (In 6), '-roundPid', "$decoyPid", '-tag', 'rgcorrect',
                         '-roundLog', $lg, '-pollSec', '1')
  Check (Has $r.Text 'DEADLINE-PID-CORRECTED') 'a pid that is not the round is CORRECTED'
  Check (Has $r.Text "round=$($round.Id)") 'the correction names the round pid out of the log'
  Check (-not (Has $r.Text 'DEADLINE-ROUND-FINISHED')) 'the dead decoy did NOT retire the watcher'
  Check (Has $r.Text "DEADLINE-KILL-ROUND pid=$($round.Id)") 'the kill lands on the CORRECTED pid'
  Start-Sleep -Seconds 1
  Check ($round.HasExited) 'the round process is actually dead'
  Check ($r.Code -eq 0) 'a corrected, killed round exits 0'

  # --------------------------------------------------------- 3. the REFUSAL
  # Nothing to confirm against: the log exists but the round never took the
  # lock. Today's code would have counted three empty samples and reported a
  # finished round. It must refuse, hold, and end nonzero.
  "-- case: an UNCONFIRMED pid never disarms the watcher"
  $decoy = New-DeadPid
  $decoyPid = $decoy.Id
  $lg = Join-Path $TMP 'refuse.log'
  Set-Content -Path $lg -Value 'ROUND tag=rgrefuse phase=rowgate'
  $r = Invoke-Deadline @('-untilUtc', (In 6), '-roundPid', "$decoyPid", '-tag', 'rgrefuse',
                         '-roundLog', $lg, '-pollSec', '1')
  Check (Has $r.Text 'DEADLINE-PID-UNCONFIRMED') 'the watcher says at once that its pid is unconfirmed'
  $empties = ([regex]::Matches($r.Text, 'DEADLINE-UNCONFIRMED-EMPTY-SAMPLE')).Count
  Check ($empties -ge 3) "it refuses to disarm past three empty samples (saw $empties)"
  Check (-not (Has $r.Text 'DEADLINE-ROUND-FINISHED')) 'it NEVER claims the round finished'
  Check (Has $r.Text 'DEADLINE-REACHED-UNCONFIRMED') 'it ends by saying a human must check the box'
  Check ($r.Code -eq 3) 'an unconfirmed watcher exits NONZERO (3), not 0'

  # ------------------------------------------------- 4. the good path stays
  # The fix must not cost every finished round a watcher that runs to the
  # deadline: a CONFIRMED pid still retires on three empty samples.
  "-- case: a CONFIRMED pid still retires the watcher early"
  $decoy = New-DeadPid
  $decoyPid = $decoy.Id
  $lg = Join-Path $TMP 'confirmed.log'
  New-RoundLog $lg $decoyPid 'rgconf'
  $r = Invoke-Deadline @('-untilUtc', (In 120), '-roundPid', "$decoyPid", '-tag', 'rgconf',
                         '-roundLog', $lg, '-pollSec', '1')
  Check (Has $r.Text 'DEADLINE-PID-CONFIRMED') 'the pid is confirmed against RIG-LOCK-TAKEN'
  Check (Has $r.Text 'DEADLINE-ROUND-FINISHED on its own') 'a confirmed, finished round still retires the watcher'
  Check ($r.Code -eq 0) 'that exits 0'

  # --------------------------------------------- 5. evidence retires it too
  "-- case: an unconfirmed watcher stands down when the LOG says the round is over"
  $decoy = New-DeadPid
  $decoyPid = $decoy.Id
  $lg = Join-Path $TMP 'bylog.log'
  Set-Content -Path $lg -Value "ROUND tag=rgbylog phase=rowgate`nALL DONE end=now"
  $r = Invoke-Deadline @('-untilUtc', (In 120), '-roundPid', "$decoyPid", '-tag', 'rgbylog',
                         '-roundLog', $lg, '-pollSec', '1')
  Check (Has $r.Text 'DEADLINE-ROUND-FINISHED-BY-LOG') 'the round log ending the round is evidence, and it stands down'
  Check ($r.Code -eq 0) 'that exits 0'

  # ------------------------------------------------------- 6. arming rules
  "-- case: arming with nothing to watch is still a refusal"
  $r = Invoke-Deadline @('-untilUtc', (In 60))
  Check (Has $r.Text 'DEADLINE-FAIL') 'no pid and no pattern is refused'
  Check ($r.Code -eq 2) 'and exits 2'
}
finally {
  foreach ($p in @(Get-Variable -Name 'round', 'decoy' -ErrorAction SilentlyContinue)) {
    if ($p.Value -and -not $p.Value.HasExited) { Stop-Process -Id $p.Value.Id -Force -EA SilentlyContinue }
  }
  Remove-Item -Recurse -Force $TMP -ErrorAction SilentlyContinue
}

# THE CLOSING LINE IS PRINTED ON BOTH OUTCOMES, and the verdict is a separate
# line. tools/rig-selftest-gate.py judges "did it run to the end" by the first
# and "did it pass" by the FAIL lines, and conflating the two would make a run
# that stopped halfway indistinguishable from a run that failed a case.
"DEADLINE-SELFTEST DONE $script:checks check(s), $script:fails failure(s)"
if ($script:fails) { "DEADLINE-SELFTEST FAIL"; exit 1 }
"DEADLINE-SELFTEST OK"
exit 0
