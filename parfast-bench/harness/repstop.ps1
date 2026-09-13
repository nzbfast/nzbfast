param([string]$log, [int]$roundpid, [int]$queuePid = 0, [string]$marker = 'FULL-REP-END rep=1', [int]$capHours = 12)
# repstop.ps1 - let a round finish the repetition it is in, then stop it before
# it starts the next one.
#
# WHY THIS EXISTS. The i5's full-range ladder is a 100% redundancy round out to
# 32,177 blocks, and its deepest rungs are enormous on the rival tools: 4,446 s
# for par2turbo at m=24,576 and 7,139 s for par2j64. Repetition 1 is worth
# having and repetition 2 costs another nine hours on the one box the seven-tool
# comparison chart also has to run on. the maintainer's call, 11 Sep 2026: keep repetition
# 1, publish it as n=1 and say so, and give the chart the box tonight.
#
# IT WAITS FOR THE MARKER AND NEVER FOR A FIXED TIME. The two legs still to run
# when this was written are the most valuable in the round - parfast already has
# 1,135 s at m=32,177 and without its two rivals at that rung that number is not
# a comparison, it is a lone figure that would read as cherry-picking. So this
# does not stop the round early under any circumstances; it only denies it a
# second repetition.
#
# AND IT WATCHES A LOG IT DOES NOT OWN, WHICH IS THE FAILURE MODE TO GUARD.
# On 11 Sep two Macs sat for hours waiting on a marker in a log that had been
# RENAMED when the round was banked. Three defences: it also watches the round's
# PID, so a round that dies or is renamed out from under it ends the wait rather
# than extending it forever; it has a hard cap; and it says out loud every half
# hour that it is still waiting and what it can see. A silent waiter and a dead
# waiter look identical from outside.
$ErrorActionPreference = 'Continue'
"REPSTOP-START $((Get-Date).ToUniversalTime().ToString('o')) log=$log roundpid=$roundpid marker='$marker' cap_h=$capHours"
$waited = 0
$cap = $capHours * 3600
while ($true) {
  $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$roundpid" -EA SilentlyContinue
  if (-not $proc -or $proc.Name -ne 'powershell.exe') {
    "REPSTOP-ROUND-GONE the round exited on its own after $([int]($waited/60))m - nothing to stop $((Get-Date).ToUniversalTime().ToString('o'))"
    exit 0
  }
  $hit = $false
  try { $hit = @(Select-String -Path $log -Pattern ([regex]::Escape($marker)) -EA SilentlyContinue).Count -gt 0 } catch { }
  if ($hit) { break }
  if ($waited % 1800 -eq 0) {
    $legs = 0
    try { $legs = @(Select-String -Path $log -Pattern '^LEG ' -EA SilentlyContinue).Count } catch { }
    $tool = (Get-CimInstance Win32_Process -Filter "ParentProcessId=$roundpid" -EA SilentlyContinue | ForEach-Object { $_.Name }) -join ','
    "REPSTOP-ALIVE $([int]($waited/60))m legs=$legs running=[$tool] $((Get-Date).ToUniversalTime().ToString('o'))"
  }
  Start-Sleep -Seconds 60
  $waited += 60
  if ($waited -gt $cap) { "REPSTOP-TIMEOUT marker never appeared in $capHours h - LEAVING THE ROUND ALONE"; exit 19 }
}
"REPSTOP-MARKER-SEEN after $([int]($waited/60))m $((Get-Date).ToUniversalTime().ToString('o'))"
# THE QUEUE RUNNER GOES FIRST, AND THAT ORDER IS THE WHOLE POINT.
#
# runqueue3 parses its rounds file ONCE, at start, and this one started at
# 07:23Z holding `full,iswp` - a list the file no longer contains. So killing
# only the round hands the box straight to `iswp`, the 10-to-80 GiB create
# sweep, which is 60 creates and most of a day. The seven-tool comparison chart
# that this whole stop exists to start tonight would have been behind it.
#
# Killing the queue FIRST rather than last is deliberate: it cannot then
# advance to the next round in the window between the round dying and this
# script noticing. Nothing is lost by doing it in this order - the queue's only
# job here is piping the round's stdout to full.log, and everything up to and
# including the marker this script waited for is already written.
#
# `iswp` is not cancelled, it is re-queued: queue4.rounds now reads
# jsmoke, fld2, jcross, iswp.
if ($queuePid -gt 0) {
  $q = Get-CimInstance Win32_Process -Filter "ProcessId=$queuePid" -EA SilentlyContinue
  if ($q -and $q.Name -eq 'powershell.exe') {
    "REPSTOP-KILL-QUEUE pid=$queuePid (it holds a stale rounds list and would start the next round)"
    Stop-Process -Id $queuePid -Force -EA SilentlyContinue
    Start-Sleep -Seconds 2
  } else { "REPSTOP-QUEUE-GONE pid=$queuePid already exited" }
}
# The child next, so the tool is never orphaned at ppid 1 - that happened on
# 10 Sep and left a par2turbo running with nothing to reap it. Resolved by
# PARENT rather than by name, so this cannot reach another lane's tool.
foreach ($c in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$roundpid" -EA SilentlyContinue)) {
  "REPSTOP-KILL-CHILD pid=$($c.ProcessId) name=$($c.Name)"
  Stop-Process -Id $c.ProcessId -Force -EA SilentlyContinue
}
Start-Sleep -Seconds 3
"REPSTOP-KILL-ROUND pid=$roundpid"
Stop-Process -Id $roundpid -Force -EA SilentlyContinue
Start-Sleep -Seconds 5
# The round's `finally` does not run on a hard stop, so the per-box rig lock is
# left held and would refuse every later round on this machine.
$lk = Join-Path $env:USERPROFILE '.parfast-rig.lock'
if (Test-Path $lk) { "REPSTOP-LOCK-RELEASED $((Get-Content $lk -Raw).Trim())"; Remove-Item $lk -Force -EA SilentlyContinue }
else { "REPSTOP-LOCK already free" }
"REPSTOP-DONE $((Get-Date).ToUniversalTime().ToString('o')) - the queue behind this round now has the box"
