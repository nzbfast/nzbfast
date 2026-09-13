param([string]$root, [int]$waitpid, [string]$list = 'queue4.rounds')
# jwait.ps1 - start a queue AFTER the one already running on this box finishes.
#
# WHY NOT JUST START A SECOND QUEUE. Take-RigLock does not block; it prints
# LOCK-BUSY and EXITS 17. Two queue runners racing for a freed lock therefore
# do not serialise - the loser's round dies instantly and the queue walks on to
# the next one and kills that too. So a successor has to wait for the
# PREDECESSOR, not for the lock.
#
# AND IT POLLS A PID, NEVER A MARKER LINE IN A LOG. On 11 Sep 2026 two Macs sat
# for hours at 0.03 s of CPU waiting for `MSWP-END` to appear in a log that had
# been RENAMED when the round was banked. A pid either exists or it does not,
# and nothing a human does to the log files can disarm it.
#
# It also says so out loud every half hour. A silent waiter and a dead waiter
# look identical from outside, which is exactly how those hours were lost.
$ErrorActionPreference = 'Continue'
"JWAIT-START $((Get-Date).ToUniversalTime().ToString('o')) root=$root waitpid=$waitpid list=$list"
$waited = 0
$cap = 36 * 3600
while ($true) {
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$waitpid" -EA SilentlyContinue
  # A recycled pid wearing another program's name is not the predecessor.
  if (-not $p -or $p.Name -ne 'powershell.exe') { break }
  if ($waited % 1800 -eq 0) {
    "JWAIT-ALIVE $([int]($waited/60))m predecessor pid=$waitpid still running $((Get-Date).ToUniversalTime().ToString('o'))"
  }
  Start-Sleep -Seconds 60
  $waited += 60
  if ($waited -gt $cap) { "JWAIT-TIMEOUT predecessor pid=$waitpid still alive after 36h - NOT starting the successor"; exit 19 }
}
"JWAIT-PREDECESSOR-GONE after $([int]($waited/60))m $((Get-Date).ToUniversalTime().ToString('o'))"
$already = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA 0 | Where-Object { $_.CommandLine -match 'runqueue4' })
if ($already.Count) { "JWAIT-ABORT a runqueue4 is already running (pid=$(($already | ForEach-Object { $_.ProcessId }) -join ','))"; exit 18 }
"JWAIT-ROUNDS"; Get-Content (Join-Path $root $list) -EA 0 | ForEach-Object { "   $_" }
$cmd = 'cmd.exe /c "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + $root + '\runqueue4.ps1 -root ' + $root + ' -list ' + $list + ' > ' + $root + '\queue4.log 2>&1"'
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
"JWAIT-CREATE rc=$($r.ReturnValue) pid=$($r.ProcessId) $((Get-Date).ToUniversalTime().ToString('o'))"
