param(
  [Parameter(Mandatory=$true)][string]$Script,   # e.g. <rig>\s2x86.ps1
  [Parameter(Mandatory=$true)][string]$Tag,      # e.g. s2x86 - names the logs
  [string]$Root = '<rig>',
  [string]$DeadlineUtc = '',                     # e.g. 2026-09-11T20:05:00Z
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
$lock = Join-Path $env:USERPROFILE '.parfast-rig.lock'
if (Test-Path $lock) {
  # AN UNREADABLE LOCK IS A HELD LOCK, AND THAT IS THE COMMON CASE.
  #
  # Take-RigLock opens it `[IO.File]::Open(..., 'CreateNew', 'Write', 'None')`
  # - share mode NONE - so while a round is running nobody else can even read
  # the file. This script read it with $ErrorActionPreference = 'Stop' and no
  # catch, so on any box with a round in flight it died with a raw .NET
  # "cannot access the file" and exit 1, instead of "refused, held by a live
  # round" and exit 17. Measured on both intel-i5-10600kf and intel-core-ultra-9-386h, 11 Sep.
  # It failed SAFE - it threw before deciding anything, so it never cleared a
  # live lock - but a caller telling "busy" from "broken" by exit code got the
  # wrong answer, and an operator got a file-permissions error for a perfectly
  # ordinary situation.
  #
  # The distinction is exact and worth stating, because it makes the pid parse
  # a second opinion rather than the only one: an exclusive handle dies with
  # the process that holds it, so a lock you CANNOT read is held by something
  # ALIVE, and a lock left behind by a hard-killed round is always READABLE.
  $c = $null
  try { $c = (Get-Content $lock -Raw -ErrorAction Stop) }
  catch {
    "WLAUNCH-REFUSED rig lock is held EXCLUSIVELY, so its owner is alive: $lock"
    "WLAUNCH-HINT a stale lock is readable; an unreadable one is somebody's round. Do not clear it."
    exit 17
  }
  if ($c -match 'pid=(\d+)') {
    $held = [int]$Matches[1]
    if (Get-Process -Id $held -ErrorAction SilentlyContinue) {
      "WLAUNCH-REFUSED rig lock held by LIVE pid=$held : " + ($c -replace "`r?`n",' | ')
      exit 17
    }
    Remove-Item $lock -Force
    "WLAUNCH-LOCK-CLEARED stale lock, pid=$held is gone: " + ($c -replace "`r?`n",' | ')
  } else {
    "WLAUNCH-REFUSED rig lock present and unparseable: " + ($c -replace "`r?`n",' | ')
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
  $roundPid = 0
  foreach ($try in 1..10) {
    Start-Sleep -Milliseconds 300
    $kid = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($r.ProcessId)" -EA SilentlyContinue |
           Where-Object { $_.Name -eq 'powershell.exe' } | Select-Object -First 1
    if ($kid) { $roundPid = [int]$kid.ProcessId; break }
  }
  $watchArg = if ($roundPid -gt 0) { "-roundPid $roundPid" } else { "-match $Tag" }
  "WLAUNCH-WATCH $(if ($roundPid -gt 0) { "round pid=$roundPid" } else { "PATTERN fallback - the round's pid could not be resolved, so the watcher's early exit stays unreachable" })"
  $dlog = Join-Path $Root "$Tag-deadline.log"
  $dcmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $Root\deadline.ps1 " +
          "-untilUtc $DeadlineUtc $watchArg -tag $Tag > $dlog 2>&1"
  $d = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $dcmd }
  "WLAUNCH-DEADLINE until=$DeadlineUtc pid=$($d.ProcessId) rc=$($d.ReturnValue)"
}
