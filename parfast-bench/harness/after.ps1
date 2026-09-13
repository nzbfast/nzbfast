param(
  [Parameter(Mandatory=$true)][int]$WaitPid,
  [Parameter(Mandatory=$true)][string]$Script,
  [Parameter(Mandatory=$true)][string]$Tag,
  [string]$Root = '<rig>',
  [string]$DeadlineUtc = '',
  [int]$CapHours = 8
)
# after.ps1 - start a round when the one in front of it finishes.
#
# Not a queue: a queue parses a list once and then holds a plan that the files
# on disk no longer agree with, which cost this fleet the difference between a
# chart starting tonight and not. This waits on ONE pid and launches ONE thing.
#
# It polls a PID and never a marker line in a log. On 11 Sep two Macs sat for
# hours waiting on a marker in a log that had been renamed when the round was
# banked, and the same day a deadline watcher disarmed on a single empty sample
# from an API that could not answer from where it ran. So: Get-Process, three
# consecutive empty reads before believing it, a hard cap, and a heartbeat every
# half hour saying what it can see - because a silent waiter and a dead waiter
# look identical from outside.
$ErrorActionPreference = 'Continue'
"AFTER-START $((Get-Date).ToUniversalTime().ToString('o')) waiting on pid=$WaitPid then $Script tag=$Tag"
$waited = 0; $cap = $CapHours * 3600; $empties = 0
while ($true) {
  $live = @(Get-Process -Id $WaitPid -EA SilentlyContinue | Where-Object { $_.ProcessName -eq 'powershell' })
  if (-not $live.Count) {
    $empties++
    if ($empties -ge 3) { "AFTER-PREDECESSOR-GONE after $([int]($waited/60))m $((Get-Date).ToUniversalTime().ToString('o'))"; break }
    "AFTER-EMPTY-SAMPLE $empties of 3"
  } else { $empties = 0 }
  if ($waited % 1800 -eq 0) { "AFTER-ALIVE $([int]($waited/60))m pid=$WaitPid still running $((Get-Date).ToUniversalTime().ToString('o'))" }
  Start-Sleep -Seconds 60
  $waited += 60
  if ($waited -gt $cap) { "AFTER-TIMEOUT pid=$WaitPid alive after $CapHours h - NOT starting the successor"; exit 19 }
}
Start-Sleep -Seconds 10   # let the predecessor's finally release the rig lock
# A HASHTABLE, NOT AN ARRAY. Splatting an ARRAY passes its elements
# POSITIONALLY, so `@('-Script', $Script, '-Tag', $Tag, '-Root', $Root)` bound
# the literal string '-Script' to wlaunch's first positional parameter and then
# had nowhere to put '-Root'. It failed with "a positional parameter cannot be
# found that accepts argument '-Root'" AFTER the predecessor had finished and
# the box was free, so the machine sat idle for an hour with a launcher that
# had already reported AFTER-PREDECESSOR-GONE. Only a hashtable splat passes
# parameters BY NAME.
$splat = @{ Script = $Script; Tag = $Tag; Root = $Root }
if ($DeadlineUtc) { $splat['DeadlineUtc'] = $DeadlineUtc }
"AFTER-LAUNCH " + (($splat.Keys | Sort-Object | ForEach-Object { "-$_ $($splat[$_])" }) -join ' ')
& (Join-Path $Root 'wlaunch.ps1') @splat
"AFTER-DONE rc=$LASTEXITCODE $((Get-Date).ToUniversalTime().ToString('o'))"
