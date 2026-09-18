param(
  [Parameter(Mandatory=$true)][string]$Script,   # e.g. <rig>\s2x86.ps1
  [Parameter(Mandatory=$true)][string]$Tag,      # e.g. s2x86 - names the logs
  [string]$Root = '<rig>',
  [string]$DeadlineUtc = '',                     # e.g. 2026-09-11T20:05:00Z
  [int]$ConfirmSec = 20,                         # how long to wait for the round to name its own pid
  [switch]$Force                                 # overwrite an existing log
)
# wlaunch.ps1 - start a Windows round DETACHED from the ssh that launched it.
#
# THE TRAP THIS EXISTS FOR, PAID FOR AT 17:49Z ON 11 Sep 2026. A round started
# over ssh with `Start-Process` died three seconds in, silently. Its log held
# the header and the ARGV lines and stopped; stderr was empty; the rig lock was
# left behind still naming a pid that no longer existed. Nothing in the log
# said anything had gone wrong, and four minutes were spent reading it as a
# slow fixture hash. The cause is not PowerShell: Windows OpenSSH puts the
# whole session in a JOB OBJECT and terminates every process in it when the
# session closes, and `Start-Process` does not leave that job. A round launched
# that way lives exactly as long as the ssh command that started it, which for
# a `ssh box "..."` one-liner is about a second.
#
# `Win32_Process::Create` is spawned by WmiPrvSE instead, so the new process is
# not in the caller's job and survives the disconnect. That is the whole trick.
#
# The hard kill has a second cost worth knowing: the round never runs its
# `finally { Release-RigLock }`, so it leaves a STALE rig lock naming a dead
# pid. This script refuses a lock whose pid is still ALIVE (that is somebody's
# round, and item 0e of the bench-suite skill is why you do not take it), and
# clears one whose pid is gone, saying so. Never clear a lock any other way.
#
# This is the Windows half of what detach.py and jlaunch.py do on macOS, and it
# is written down because the macOS halves carry their own hard-won note about
# SIGHUP and session leaders - the same class of bug, a different mechanism,
# and neither box's answer works on the other.
$ErrorActionPreference = 'Stop'
$log = Join-Path $Root "$Tag.log"
$err = Join-Path $Root "$Tag.err"
if ((Test-Path $log) -and -not $Force) {
  "WLAUNCH-REFUSED $log exists - bank it first, or pass -Force"; exit 1
}
# THE RIG LOCK, VIA plib - this script hand-rolled the whole check until
# 16 Sep 2026 and carried TWO defects for it, which is the argument for not
# having a second copy of a rule rather than for writing a better one.
#
# DEFECT A, the one that WEDGED A BOX, and it had nothing to do with the share
# mode: a ZERO-BYTE lock has no `pid=` to match, so it fell through the pid
# parse into a final `else` that printed "rig lock present and unparseable" and
# exited 17 - forever, on every launch, until a human deleted the file. That is
# the exact shape of the apple-m3-ultra orphan of 16 Sep 2026, whose lock was zero
# bytes and cost that box eight hours
# (an internal note). Measured here on
# windows-gaming-pc-b: `Get-Content -Raw` on a zero-byte file returns $null, and
# `$null -match 'pid=(\d+)'` is False. Under the rule as landed, a lock that
# names nobody is an ORPHAN and is takeable at any age - which is precisely
# what Get-RigLockHolder answers, and what the hand-rolled copy could not.
#
# DEFECT B, a stale premise and a backwards HINT: the old block argued that "a
# lock you CANNOT read is held by something ALIVE, and a lock left behind by a
# hard-killed round is always READABLE", and printed that to an operator as
# advice. It was true under [IO.FileShare]::None and stopped being true on
# 16 Sep 2026, when Take-RigLock moved to ::Read so a HELD lock is readable
# too. The verdict never changed - the pid parse below reached the same
# refusal, and now names the holder - but a human following the printed hint
# would have concluded a held lock was stale, which is backwards at the one
# moment it matters. The inference survives where it is still true and still
# free, as the unreadable BACKSTOP inside Get-RigLockHolder; it is no longer
# this script's primary path, and it is no longer printed as a rule of thumb.
#
# plib.ps1 lives beside this file and is dot-sourced rather than duplicated. A
# missing plib is BROKEN (exit 1), never BUSY (exit 17) - that distinction is
# itself the fix for a measured 11 Sep 2026 defect, where a caller telling
# "busy" from "broken" by exit code got the wrong answer, and it must survive
# every future edit to this block.
$plib = Join-Path $PSScriptRoot 'plib.ps1'
if (-not (Test-Path $plib)) {
  "WLAUNCH-FAILED plib.ps1 not found beside this script at $plib - cannot ask who holds the rig lock"
  exit 1
}
. $plib
$holder = Get-RigLockHolder
$lock = $holder.Path
if ($holder.Held) {
  "WLAUNCH-REFUSED rig lock $($holder.Why): " + ($holder.Text -replace "`r?`n",' | ')
  exit 17
}
if ($holder.Exists) {
  # Provably nobody's - a dead pid, or no pid at all. Clear it and SAY SO, on
  # stdout and on the box's coordination file. This script announced nothing
  # when it cleared a lock until 16 Sep 2026; the round it is about to launch
  # takes the lock properly for itself.
  Write-RigLockOrphanNote $lock $holder.Text "cleared by wlaunch tag=$Tag pid=$PID - $($holder.Why)"
  Remove-Item $lock -Force -ErrorAction SilentlyContinue
  if (Test-Path $lock) {
    "WLAUNCH-REFUSED could not clear orphan rig lock $lock - $($holder.Why)"
    exit 17
  }
}
foreach ($f in @($log, $err)) { if (Test-Path $f) { Remove-Item $f -Force } }
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $Script > $log 2> $err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
if ($r.ReturnValue -ne 0) { "WLAUNCH-FAILED rc=$($r.ReturnValue)"; exit 2 }
"WLAUNCH-OK tag=$Tag pid=$($r.ProcessId) log=$log"
# The deadline is armed SEPARATELY and the same way, because a borrowed machine
# is the normal case here: windows-gaming-pc-b and amd-ryzen-9800x3d are borrowed gaming PCs, lent
# for a stated window, and the rule is that nothing outlives it.
#
# ITS MATCH PATTERN MUST NOT MATCH THE WATCHER'S OWN COMMAND LINE. deadline.ps1
# polls for powershell processes matching a pattern and exits early when none
# are left; a watcher armed as `-match jcross` finds ITSELF every poll (the
# string is in its own arguments), so its early exit is unreachable and it runs
# to the deadline whatever the round did. Harmless, but it means a live watcher
# is NOT evidence that a round is still running. The tag is passed here as a
# distinct token for that reason.
if ($DeadlineUtc) {
  # RESOLVE THE ROUND'S OWN pid AND PASS IT, falling back to the pattern.
  #
  # `$r.ProcessId` above is the CMD.EXE pid, not the round's - `cmd /c
  # powershell ...` waits on a child - so handing that number straight to
  # deadline.ps1 would fail its `Name -eq 'powershell.exe'` check and the
  # watcher would conclude the round had already finished, at once. Hence the
  # pattern form this file shipped with, and hence the wart it documents: a
  # watcher armed `-match <tag>` finds ITSELF every poll, so its early exit is
  # unreachable and a live watcher is not evidence of a live round.
  #
  # The child is findable. Give cmd a moment to start it, then take the
  # powershell whose parent is that cmd. When it is there the watcher gets a
  # pid and its early exit works; when it is not, nothing is worse than before.
  #
  # AND THE FIRST POWERSHELL CHILD IS NOT NECESSARILY THE ROUND. That is the
  # 17 Sep 2026 defect, and it is the reason for everything below this
  # paragraph. The loop as it shipped took the first `powershell.exe` under
  # that cmd.exe and handed the number straight to the watcher. On both
  # borrowed Zen 5 boxes, in the same minute, that number was a TRANSIENT:
  # armed on 21900 where the round was 2864, and on 1596 where it was 10028.
  # Both watchers then saw their process vanish, took three empty samples as a
  # finished round, and printed `DEADLINE-ROUND-FINISHED on its own` 32 and 36
  # minutes before those rounds ended - so for that whole stretch nothing would
  # have stopped either round at its deadline, while the log said it was
  # guarded. The pattern fallback's wart above was documented; this path was
  # believed to be the good one, which is why it went unnoticed.
  # an internal note, defect A.
  #
  # THREE LAYERS NOW, and the tree walk is only the first of them.
  #
  #   1. The walk is FILTERED by the script it was asked to launch. The round's
  #      command line is `powershell ... -File <Script>`; a transient's is not,
  #      so one `-match` on $Script rejects the whole class of process that
  #      caused this. Cheap, and it needs nothing to have been written yet.
  #   2. The round's own log is polled for the `RIG-LOCK-TAKEN ... pid=<n>`
  #      line plib writes when the round takes the rig lock. That is the round
  #      naming itself, and it is what CONFIRMS the number this script prints.
  #   3. The watcher is handed `-roundLog` and confirms for itself, so the
  #      guarantee does not rest on this script having got it right.
  #
  # AN UNCONFIRMED PID IS STILL ARMED, AND IT IS ARMED AS UNCONFIRMED. Refusing
  # the launch outright was the other candidate and it is the wrong trade here:
  # a driver that builds before it takes the lock has no RIG-LOCK-TAKEN line
  # for a minute or more, and a launcher that refuses on that would refuse
  # legitimate rounds on a borrowed box - pressure to stop arming deadlines at
  # all, which is worse than the defect. deadline.ps1 is where the refusal
  # lives instead: it keeps trying to confirm, and until it does it will not
  # disarm on empty samples, which is the exact step that failed. Failing to
  # find is failing THERE, where the cost of being careful is a watcher that
  # outlives its round rather than a round that never launched.
  $roundPid = 0
  $rejected = 0
  foreach ($try in 1..10) {
    Start-Sleep -Milliseconds 300
    $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($r.ProcessId)" -EA SilentlyContinue |
              Where-Object { $_.Name -eq 'powershell.exe' })
    $mine = @($kids | Where-Object { $_.CommandLine -and $_.CommandLine -match [regex]::Escape($Script) } |
              Select-Object -First 1)
    if ($mine.Count) { $roundPid = [int]$mine[0].ProcessId; break }
    $rejected += @($kids).Count
  }
  if ($rejected -gt 0 -and $roundPid -le 0) {
    "WLAUNCH-WATCH-REJECTED $rejected powershell child(ren) of pid=$($r.ProcessId) did not carry -File $Script in their command line - not the round. THIS IS THE 17 Sep 2026 DEFECT'S SIGNATURE."
  }
  # The round names its own pid when it takes the rig lock. Wait for it, so the
  # number this script prints is one somebody can check rather than a guess.
  $confirmedPid = 0
  $facts = Get-RoundLogFacts $log
  $waited = 0
  while ($waited -lt $ConfirmSec) {
    $facts = Get-RoundLogFacts $log
    if ($facts.Pid -gt 0) { $confirmedPid = $facts.Pid; break }
    if ($facts.Finished) { break }
    Start-Sleep -Milliseconds 500
    $waited += 0.5
  }
  if ($confirmedPid -gt 0 -and $roundPid -gt 0 -and $confirmedPid -ne $roundPid) {
    "WLAUNCH-PID-CORRECTED tree=$roundPid log=$confirmedPid - the process tree and the round disagree, and the ROUND wins: $log says $($facts.Why)"
  }
  if ($confirmedPid -gt 0) { $roundPid = $confirmedPid }
  $watchArg = if ($roundPid -gt 0) { "-roundPid $roundPid" } else { "-match $Tag" }
  if ($roundPid -gt 0 -and $confirmedPid -gt 0) {
    "WLAUNCH-WATCH round pid=$roundPid CONFIRMED by $($facts.Why) in $log"
  } elseif ($roundPid -gt 0) {
    "WLAUNCH-WATCH round pid=$roundPid UNCONFIRMED after ${ConfirmSec}s - $($facts.Why). It carries -File $Script, so it is the round's process by the tree; the watcher will confirm it against the log itself and will NOT disarm until it does."
  } else {
    "WLAUNCH-WATCH PATTERN fallback - the round's pid could not be resolved, so the watcher's early exit stays unreachable"
  }
  $dlog = Join-Path $Root "$Tag-deadline.log"
  # deadline.ps1 lives BESIDE this script, not under $Root - $Root is the
  # ROUND root, which since the per-round-root convention took over is never
  # where the harness scripts themselves live. `$Root\deadline.ps1` resolved
  # to a -File the child cmd.exe could not find on every such root, and
  # Win32_Process::Create still returned rc=0 (it did start a cmd.exe) while
  # arming nothing - invisible unless something looks past that rc at the
  # grandchild. an internal note.
  $deadlineScript = Join-Path $PSScriptRoot 'deadline.ps1'
  # `-roundLog` is how the watcher checks the pid for ITSELF. It is passed on
  # both arms on purpose, the pattern one included: that arm cannot confirm a
  # pid it does not have, but the log still tells it whether the round is over.
  $dcmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $deadlineScript " +
          "-untilUtc $DeadlineUtc $watchArg -tag $Tag -roundLog $log > $dlog 2>&1"
  $d = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $dcmd }
  if ($d.ReturnValue -ne 0) {
    "WLAUNCH-DEADLINE-FAILED rc=$($d.ReturnValue) - Win32_Process::Create itself refused to start the watcher"
  } else {
    # VERIFY, do not just believe rc=0 - that is exactly the gap this handoff
    # is about: Create succeeding only means a cmd.exe started, not that
    # deadline.ps1 is running inside it. Same "resolve the real pid" loop as
    # the round's own pid above, aimed at this cmd.exe's child instead.
    #
    # FILTERED ON deadline.ps1 FOR THE SAME REASON THE ROUND'S WALK IS FILTERED
    # ON $Script, and it is not cosmetic here either: this number is what the
    # documented remedy has an operator KILL when a stale watcher has to be
    # cleared by hand, so a transient picked up here is a pid an operator kills
    # believing it is a watcher.
    $watcherPid = 0
    foreach ($try in 1..10) {
      Start-Sleep -Milliseconds 300
      $kid = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($d.ProcessId)" -EA SilentlyContinue |
             Where-Object { $_.Name -eq 'powershell.exe' -and $_.CommandLine -and
                            $_.CommandLine -match 'deadline\.ps1' } | Select-Object -First 1
      if ($kid) { $watcherPid = [int]$kid.ProcessId; break }
    }
    if ($watcherPid -gt 0) {
      "WLAUNCH-DEADLINE until=$DeadlineUtc pid=$watcherPid rc=$($d.ReturnValue)"
    } else {
      "WLAUNCH-DEADLINE-FAILED until=$DeadlineUtc cmdpid=$($d.ProcessId) rc=$($d.ReturnValue) - no deadline.ps1 child appeared within 3s, the watcher is NOT armed - check $dlog"
    }
  }
}
