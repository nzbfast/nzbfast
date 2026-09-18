# t6wait.ps1 - queue for intel-i5-10600kf, then run t6ctl.ps1. Lane
# parfast-t6-1mib-nibble-smt.
#
# THREE GATES, and each one is a documented incident on this box:
#
# 1. THE AHEAD-LIST, by the THIRD-TOKEN SUBJECT rule. An id must not merely
#    APPEAR on a line: every courteous DONE on this box names the lanes it is
#    handing the box to, so a `^DONE` + substring test clears lanes that never
#    finished (parfast-nibble-windowed-ask-1mib-16sep's second waiter bug,
#    14:38:52Z). Both record types put the subject in field 3 - `CLAIM <ts> <id>`
#    and `DONE <ts> <id>` - so a lane is FINISHED only when its own DONE comes
#    after its own most recent CLAIM. That also makes a multi-round campaign
#    safe: a lane that posts DONE and re-CLAIMs goes back to blocking.
# 2. THE LOCK, FREE TWICE 60 s APART. Take-RigLock opens the lock with share
#    mode Read, so a lock that cannot be OPENED FOR WRITE is held by something
#    alive. And free once means nothing: on 16 Sep a waiter logged the lock free
#    at 04:32:23Z and again at 04:43:23Z in the middle of a round that held it
#    continuously and simply was not burning CPU every second. The lock is free
#    BETWEEN CELLS.
# 3. NO parfast / cargo / rustc. A queued lane runs 10-20 minutes of cargo
#    BEFORE it takes the lock and is invisible to any look at the lock file.
#
# Only when all three agree, twice, do I post a CLAIM line and start. I kill
# nothing, by pattern or otherwise, and I delete nothing of anyone else's.
$ErrorActionPreference = 'Stop'
$root  = '<rig>\t6sep16'
$coord = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$lane  = 'parfast-t6-1mib-nibble-smt'
$ahead = @('nibble-crossover-quiet-box-confirm-16sep',
           'parfast-stripe-halving-nibble-i5-native-16sep',
           'parfast-nibble-windowed-ask-1mib-16sep')
$wlog  = Join-Path $root 't6wait.log'
New-Item -ItemType Directory -Force $root | Out-Null

function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" | Tee-Object -FilePath $wlog -Append | Out-Null }
function Coord([string]$line) {
  for ($i=0; $i -lt 60; $i++) {
    try { $fs=[IO.File]::Open($coord,'Append','Write','Read'); $sw=New-Object IO.StreamWriter($fs)
          $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close(); return $true } catch { Start-Sleep -Milliseconds 500 }
  }
  return $false
}
# Field 3 of a CLAIM/DONE line is the subject. Returns the ids still HOLDING.
function Get-Holding([string[]]$ids) {
  $lines = Get-Content $coord -ErrorAction SilentlyContinue
  $last = @{}
  foreach ($l in $lines) {
    $t = $l -split '\s+'
    if ($t.Count -lt 3) { continue }
    # BOTH FIELD ORDERS ARE IN THIS FILE and a reader that assumes one drops
    # the other silently. Most lanes post `CLAIM <ts> <id>`, but several post
    # `<ts> RELEASE <id>` / `<ts> NOTE <id>` (rar15-comet-lake-cell-16sep at
    # 14:04:54Z, rar15-comet-lake-cell-16sep at 14:01:48Z). The SUBJECT is
    # field 3 under both, which is what makes the third-token rule work at
    # all; only the keyword moves, so look for it in either of the first two.
    $kind = if ($t[0] -in @('CLAIM','DONE','RELEASE')) { $t[0] }
            elseif ($t[1] -in @('CLAIM','DONE','RELEASE')) { $t[1] } else { '' }
    $subj = $t[2]
    if (-not $kind) { continue }
    if ($ids -notcontains $subj) { continue }
    # A RELEASE ends a hold exactly as a DONE does - it is a lane standing
    # down - so only a CLAIM leaves a lane blocking.
    $last[$subj] = $kind   # file order is time order; the LAST wins
  }
  # A LANE IS CLEAR ONLY ON AN EXPLICIT DONE OR RELEASE, and "never seen" is
  # NOT clear. Both lanes ahead of me have posted only NOTEs - they queue in
  # prose and do not CLAIM until they actually take the box - so a reader that
  # cleared an unseen id would jump the queue the moment the current holder
  # finished, which is exactly the "the lock does not order two waiters"
  # hazard the ahead-list exists to answer. Verified against the live file at
  # 14:50Z on 16 Sep: nibble-crossover reads CLAIM, create-width-fill and
  # parfast-cf read DONE, rar15-comet-lake reads RELEASE, and my two queue
  # neighbours read as never seen.
  @($ids | Where-Object { $last[$_] -ne 'DONE' -and $last[$_] -ne 'RELEASE' })
}
function Test-BoxFree {
  $lp = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  if (Test-Path $lp) {
    try { $fs=[IO.File]::Open($lp,'Open','Write','None'); $fs.Close() } catch { return $false }
  }
  $p = @(Get-Process -Name parfast,cargo,rustc -ErrorAction SilentlyContinue)
  return ($p.Count -eq 0)
}

Say "T6WAIT start pid=$PID lane=$lane ahead=$($ahead -join ',')"
$deadline = (Get-Date).ToUniversalTime().AddHours(14)
while ($true) {
  if ((Get-Date).ToUniversalTime() -gt $deadline) {
    Say "T6WAIT GIVING UP at the 14 h deadline without ever taking the box"
    Coord "NOTE $((Get-Date).ToUniversalTime().ToString('o')) $lane - MY WAITER GAVE UP at its own 14 h deadline without ever taking the box, holding no lock and having run no leg. Nothing of mine is running here." | Out-Null
    exit 3
  }
  $holding = @(Get-Holding $ahead)
  if ($holding.Count -gt 0) { Say "WAIT ahead=$($holding -join ',')"; Start-Sleep -Seconds 120; continue }
  if (-not (Test-BoxFree)) { Say "WAIT ahead-list clear but box busy (lock or parfast/cargo/rustc)"; Start-Sleep -Seconds 60; continue }
  Say "FREE-1 ahead-list clear and box free; confirming in 60s"
  Start-Sleep -Seconds 60
  if (@(Get-Holding $ahead).Count -gt 0 -or -not (Test-BoxFree)) { Say "FREE-2 failed, back to waiting"; continue }
  Say "FREE-2 confirmed - taking the box"
  break
}
$ts = (Get-Date).ToUniversalTime().ToString('o')
Coord "CLAIM $ts $lane gen=44f480fe (opus5 chip, <user>, apple-m3-ultra-512gb) - TAKING THE BOX NOW. My ahead-list ($($ahead -join ', ')) read clear by the third-token subject rule and the rig lock plus a parfast/cargo/rustc census read free TWICE, 60 s apart. The -t6 arm at 1 MiB on the nibble class: wcomb.ps1 -Phase measure, ONE binary (8983A55A4E260BA3, the banked 16 Sep 1 MiB round's own, reused in place and hash-checked, NOT rebuilt), -Threads 4,6,12 -Reps 2 -Rungs 192,512,1024,2048 -Budget 2048 -NttBudget 12884901888 on a COPY of fix-1048576-512 in my own root <rig>\t6sep16. 72 legs, ~95 min plus a 20 GB fixture copy. I DELETE NOTHING OF ANYONE ELSE'S - wcomb-16sep and its fixtures are nibble-block-size-row-gate-16sep's. I remove only <rig>\t6sep16 and my four helpers t6{probe,probe2,probe3,probe4,coord,ctl,wait}.ps1. Kill by pid, never by pattern. Will post DONE with my lane name as the THIRD field." | Out-Null
Say "CLAIM posted; launching t6ctl.ps1"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 't6ctl.ps1') *>&1 | Tee-Object -FilePath (Join-Path $root 't6ctl.log') -Append | Out-Null
$rc = $LASTEXITCODE
Say "T6CTL rc=$rc"
$verdict = if ($rc -eq 0) { "FINISHED CLEAN, 72 legs" } else { "FAILED with rc=$rc - read <rig>\t6sep16\t6ctl.log" }
Coord "DONE $((Get-Date).ToUniversalTime().ToString('o')) $lane gen=44f480fe (opus5 chip, <user>, apple-m3-ultra-512gb) - THE BOX IS FREE AND THE RIG LOCK IS RELEASED. My round $verdict. Nothing of mine is still running on this box: no lock held, no leg, no waiter. I deleted nothing of anyone else's; <rig>\wcomb-16sep and its four fixtures are untouched and still belong to nibble-block-size-row-gate-16sep. My own root <rig>\t6sep16 (about 20 GB of copied fixture plus logs) I leave until my logs are copied off and then remove - delete it by name if you need the space before then, it is a copy and reproducible. Whoever is next: the box is yours." | Out-Null
Say "T6WAIT done rc=$rc"
exit $rc
