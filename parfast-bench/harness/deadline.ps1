param([string]$untilUtc, [int]$roundPid = 0, [string]$match = '', [string]$tag = 'round')
# deadline.ps1 - stop a round at a wall-clock time, whatever it is doing.
#
# For BORROWED machines. windows-gaming-pc-b and amd-ryzen-9800x3d are borrowed gaming PCs, lent by
# prior arrangement for a stated window, and the onboarding lane's rule is in as
# many words: do not start anything that outlives the window. A round that
# overruns on a borrowed desktop is not a slow round, it is a machine somebody
# wanted back.
#
# So the deadline is armed BEFORE the round rather than watched by a human, and
# it stops the round's tool child first so nothing is left orphaned at ppid 1.
# A round that finishes on its own leaves nothing for this to do and it exits
# quietly.
$ErrorActionPreference = 'Continue'
# TAKE A PID, NOT A PATTERN, AND REFUSE WITHOUT ONE.
#
# This script was armed with `-match jcross` and another lane started its own
# jcross round on the same borrowed box eight minutes later. The watcher then
# pointed at THEIR round and would have killed it at my deadline. Worse, a
# `deadline.ps1` pattern used to tidy up afterwards matched BOTH watchers and
# took theirs down with mine - the pattern-kill mistake CLAUDE.md invariant 2a
# exists to prevent, committed against a teammate's round rather than a
# competitor's daemon. Restored inside two minutes and their round never
# stopped, but only because someone happened to look.
#
# A pid is unambiguous and cannot grow a second owner. `-match` survives as a
# fallback ONLY when no pid is available, and it says so in the log so a reader
# knows which kind of watcher they are looking at.
$deadline = [datetime]::Parse($untilUtc).ToUniversalTime()
if ($roundPid -le 0 -and -not $match) {
  "DEADLINE-FAIL give -roundPid (preferred) or -match; refusing to watch nothing"
  exit 2
}
$empties = 0
$how = if ($roundPid -gt 0) { "pid=$roundPid" } else { "match='$match' (FALLBACK - a pattern can match another lane's round)" }
"DEADLINE-ARMED tag=$tag watching=$how until=$($deadline.ToString('o')) now=$((Get-Date).ToUniversalTime().ToString('o'))"
while ((Get-Date).ToUniversalTime() -lt $deadline) {
  # Get-Process, NOT a Win32_Process ProcessId filter. The WQL form returned
  # EMPTY from inside this watcher, every poll, while the round was plainly
  # running and while the SAME filter typed by hand in an ssh session matched
  # it perfectly. The watcher is spawned through Win32_Process::Create, so it
  # is a child of WmiPrvSE rather than of the shell, and the ProcessId filter
  # does not answer from there - the Name filter does, which is why the
  # pattern form never showed this. Get-Process is a different API and is not
  # affected. Two consecutive empty samples on a live round is what exposed it;
  # one would have disarmed the guard silently.
  $live = if ($roundPid -gt 0) {
    @(Get-Process -Id $roundPid -EA SilentlyContinue | Where-Object { $_.ProcessName -eq 'powershell' })
  } else {
    @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA 0 | Where-Object { $_.CommandLine -match $match })
  }
  # THREE CONSECUTIVE EMPTY SAMPLES, NOT ONE. On its first real use the pid
  # form disarmed 158 ms after arming, concluding the round had already
  # finished - while the round ran for another half hour. Queried by hand a
  # minute later the same filter matched the same pid perfectly, so the empty
  # read was transient: a process WMI had not yet published, or a momentary CIM
  # failure that `-EA 0` turned into "no such process".
  #
  # The exact cause does not matter, and chasing it would be the wrong fix. A
  # guard that disarms on ONE bad sample is fragile by construction, and this
  # is the second early-exit path in this file to misfire today. Three in a row,
  # a minute apart, is still under two minutes of lag on a real finish and
  # cannot be produced by a transient.
  if (-not $live.Count) {
    $empties++
    if ($empties -ge 3) {
      "DEADLINE-ROUND-FINISHED on its own after $empties consecutive empty samples $((Get-Date).ToUniversalTime().ToString('o'))"
      exit 0
    }
    "DEADLINE-EMPTY-SAMPLE $empties of 3 - not disarming on one reading $((Get-Date).ToUniversalTime().ToString('o'))"
  } else { $empties = 0 }
  $left = [int]($deadline - (Get-Date).ToUniversalTime()).TotalMinutes
    # `.Id` on a Get-Process object, `.ProcessId` on a CIM one - the two
    # branches above return different types, and printing the wrong property
    # gave a heartbeat reading `round pid=` with nothing after it. Cosmetic,
    # and worth fixing anyway: a guard whose own heartbeat looks broken is a
    # guard nobody trusts at the moment it matters.
    if ($left % 30 -eq 0) {
      $ids = ($live | ForEach-Object { if ($_.ProcessId) { $_.ProcessId } else { $_.Id } }) -join ','
      "DEADLINE-ALIVE ${left}m left, round pid=$ids"
    }
  Start-Sleep -Seconds 60
}
$live = if ($roundPid -gt 0) {
  @(Get-Process -Id $roundPid -EA SilentlyContinue | Where-Object { $_.ProcessName -eq 'powershell' })
} else {
  @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA 0 | Where-Object { $_.CommandLine -match $match })
}
if (-not $live.Count) { "DEADLINE-REACHED and the round had already finished"; exit 0 }
foreach ($r in $live) {
  $rpid = if ($r.ProcessId) { $r.ProcessId } else { $r.Id }   # CIM object vs Get-Process object
  foreach ($c in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$rpid" -EA 0)) {
    "DEADLINE-KILL-CHILD pid=$($c.ProcessId) name=$($c.Name)"
    Stop-Process -Id $c.ProcessId -Force -EA SilentlyContinue
  }
  Start-Sleep -Seconds 2
  "DEADLINE-KILL-ROUND pid=$rpid"
  Stop-Process -Id $rpid -Force -EA SilentlyContinue
}
Start-Sleep -Seconds 4
$lk = Join-Path $env:USERPROFILE '.parfast-rig.lock'
if (Test-Path $lk) { "DEADLINE-LOCK-RELEASED $((Get-Content $lk -Raw).Trim())"; Remove-Item $lk -Force -EA SilentlyContinue }
"DEADLINE-DONE $((Get-Date).ToUniversalTime().ToString('o')) - the box is handed back"
