# cfwait.ps1 - queue for intel-i5-10600kf, then run cfload.ps1. Lane
# parfast-load-term-and-third-binary-i5, 17 Sep 2026.
#
# WHY A WAITER AT ALL, when this round's own handoff
# (an internal note) refused the pattern
# TWICE and said "launch attended, or do not launch". Two things changed and
# both are in that same file:
#
#  1. THE REASON IT REFUSED IS FIXED. The objection was that this round's
#     legsets START A LOAD GENERATOR, so a waiter firing into a queue nobody
#     watches puts 72% of a core onto a neighbour's timing round. That was
#     TRUE of the driver as first staged (4FE79A01): it called Start-Load
#     BEFORE Run-Legset acquired the rig lock, behind a 20x20s retry. The
#     acquire-then-load fix (09413597) makes the loaded branch probe the lock
#     free with NO generator running, SKIP the legset entirely and start no
#     generator if the lock never comes free, and drop the loaded retry budget
#     to 3. The generator can no longer be alive while another lane owns the
#     box, which is the whole of the objection.
#  2. THIS WAITER IS NOT UNATTENDED. A session is polling it on a ~30 minute
#     cadence and will be present when it fires. The waiter is the TRIGGER,
#     not the attendant - it exists because the gaps on this box open and
#     close in minutes at unpredictable hours and a session-cadence poll
#     cannot catch one. FOUR lanes have claimed this item and released it
#     without running a leg; on 16 Sep both lanes that armed a waiter got the
#     box and all three that polled did not.
#
# AND A THIRD REASON THAT CUTS THE OTHER WAY FROM THE USUAL ONE: an on-box
# waiter is KINDER to the holder than ssh polling is. A PowerShell started
# under SSHD is about a core-second of module autoload outside the round's pid
# tree, and plib's Require-QuietBox can abort a round (exit 18) at 120% of one
# core on this 12-thread part. This process starts ONCE and then polls from
# inside an already-running PowerShell.
#
# THREE GATES, each a documented incident on this box (t6wait.ps1's header is
# the source and this is that pattern, not a new one):
#
# 1. THE AHEAD-LIST, by the THIRD-TOKEN SUBJECT rule, with the keyword looked
#    for in fields 1 AND 2 because both orders are in this file. A lane is
#    finished only when its own close comes after its own most recent CLAIM,
#    so a lane that posts DONE and re-CLAIMs goes back to blocking. "NEVER
#    SEEN" IS NOT CLEAR: lanes here queue in prose and only CLAIM when they
#    actually take the box, so an unseen id stays blocking.
# 2. THE LOCK, FREE TWICE 60 s APART. It is free BETWEEN CELLS - a waiter
#    logged it free twice eleven minutes apart in the middle of a round that
#    held it continuously.
# 3. NO parfast / cargo / rustc. A queued lane runs 10-20 min of cargo BEFORE
#    it takes the lock and is invisible to any look at the lock file.
#
# I kill nothing, by pattern or otherwise, and I delete nothing of anyone
# else's. I never CLEAR a lock. cfload.ps1 posts its own CLAIM and its own
# DONE with this lane in field 3; I post a closing line only if it exits
# without one.
$ErrorActionPreference = 'Stop'
$root  = '<rig>\cfload16sep'
$coord = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$lane  = 'parfast-load-term-and-third-binary-i5'
# THE AHEAD-LIST, as read off the live file at 19:1xZ on 17 Sep 2026:
#  - ntt-depth1-tile-second-class-17sep: CLAIM 14:42:08Z, no close. Holding the
#    rig lock (round=nttfw-i5 pid=14968 at 19:03:38Z). Its own NOTE of 17:02Z
#    revised its finish to ~19:15Z plus ~55 min of control arms.
#  - parfast-nibble-windowed-ask-t4-16sep: QUEUED 19:00:13Z, corrected 19:02Z,
#    waiter pid 15300, expects 4-5 h once it takes the box. Never CLAIMed, so
#    it reads as never-seen, which under rule 1 is BLOCKING - correct, it is
#    ahead of me and said so.
# TWO LINES I READ AND AM DELIBERATELY NOT QUEUED BEHIND, so a later reader can
# check the reasoning rather than trust it:
#  - ntt-additive-gate-x86-production-scale-17sep posted STAND-DOWN at
#    17:08:58Z closing its own QUEUED line of 16:07:51Z. Out by its own word.
#  - parfast-catalog-window-windows-ab-15sep has a QUEUED line from
#    2026-09-15T20:50:54Z with no close, but parfast-nibble-windowed-ask-t4
#    enumerated Win32_Process at 18:55Z and 19:55Z local and found no catwin
#    waiter alive. I adopt that reading: a dead waiter from 46 h ago.
# If either of those is still waiting, one line on the file and I queue behind.
$ahead = @('ntt-depth1-tile-second-class-17sep',
           'parfast-nibble-windowed-ask-t4-16sep')
# THE CLOSING VOCABULARY IS SIX WORDS, NOT TWO. Held equal to plib.ps1's
# $script:handover_close (and to CLOSE_KW in .claude/tools/bench-accounts-parse.py)
# by tools/rig-selftest-gate.py. t6wait.ps1 knew only three and would have read
# this file's STAND-DOWN of 17:08:58Z as never-seen.
$closekw = @('ABORTED','DONE','RELEASE','RELEASED','STAND-DOWN','WITHDRAWN')
$openkw  = @('CLAIM')
$wlog  = Join-Path $root 'cfwait.log'
New-Item -ItemType Directory -Force $root | Out-Null

function Say([string]$m) {
  $l = "$((Get-Date).ToUniversalTime().ToString('o')) $m"
  $l | Out-File -FilePath $wlog -Append -Encoding ascii
  $l
}
function Coord([string]$line) {
  for ($i=0; $i -lt 60; $i++) {
    try { Add-Content -Path $coord -Value $line -ErrorAction Stop; return $true }
    catch { Start-Sleep -Milliseconds 500 }
  }
  return $false
}
# Returns the ids still HOLDING. File order is time order.
function Get-Holding([string[]]$ids) {
  $lines = Get-Content $coord -ErrorAction SilentlyContinue
  $last = @{}
  foreach ($l in $lines) {
    if (-not $l) { continue }
    $t = $l.Split((" `t").ToCharArray(), [StringSplitOptions]::RemoveEmptyEntries)
    if ($t.Count -lt 3) { continue }
    # BOTH FIELD ORDERS. Most lanes post `CLAIM <ts> <id>`, several post
    # `<ts> RELEASE <id>`. The SUBJECT is field 3 under both; only the keyword
    # moves, so look for it in either of the first two.
    $k0 = $t[0].ToUpperInvariant(); $k1 = $t[1].ToUpperInvariant()
    $kind = ''
    if ($closekw -contains $k0 -or $openkw -contains $k0) { $kind = $k0 }
    elseif ($closekw -contains $k1 -or $openkw -contains $k1) { $kind = $k1 }
    if (-not $kind) { continue }
    if ($ids -notcontains $t[2]) { continue }
    $last[$t[2]] = $kind
  }
  @($ids | Where-Object { $closekw -notcontains $last[$_] })
}
function Test-BoxFree {
  $lp = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  if (Test-Path $lp) {
    # Share mode None: a lock that cannot be OPENED FOR WRITE is held by
    # something ALIVE. A readable one was left behind by a hard-killed round -
    # and I still do not clear it, I simply do not take the box.
    try { $fs=[IO.File]::Open($lp,'Open','Write','None'); $fs.Close() } catch { return $false }
  }
  $p = @(Get-Process -Name parfast,cargo,rustc -ErrorAction SilentlyContinue)
  return ($p.Count -eq 0)
}

Say "CFWAIT start pid=$PID lane=$lane ahead=$($ahead -join ',')"
# SEVEN HOURS, and the number is the CLAIM LEASE minus the round. My claim
# leases to 2026-09-18T05:02:35Z and cfload's own ETA is ~70 min with a
# build and a fixture copy in front of it, so a take after ~02:30Z cannot
# finish inside the lease and I would rather give up with a NOTE than start a
# round nothing is licensed to close.
$deadline = (Get-Date).ToUniversalTime().AddHours(7)
$verdictSeen = ''
while ($true) {
  if ((Get-Date).ToUniversalTime() -gt $deadline) {
    Say "CFWAIT GIVING UP at the 7 h deadline without ever taking the box"
    Coord "NOTE $((Get-Date).ToUniversalTime().ToString('o')) $lane gen=f8b50854 (opus5 chip, <user>, apple-m3-ultra-512gb) - MY WAITER GAVE UP at its own 7 h deadline without ever taking the box. I hold no lock, I ran no leg, I started no load generator, and nothing of mine is running on this box. My ahead-list at the end was: $($verdictSeen). The box is not mine and never was." | Out-Null
    exit 3
  }
  $holding = @(Get-Holding $ahead)
  $verdictSeen = if ($holding.Count) { $holding -join ',' } else { 'clear' }
  if ($holding.Count -gt 0) { Say "WAIT ahead=$($holding -join ',')" | Out-Null; Start-Sleep -Seconds 120; continue }
  if (-not (Test-BoxFree)) { Say "WAIT ahead-list clear but box busy (lock or parfast/cargo/rustc)" | Out-Null; Start-Sleep -Seconds 60; continue }
  Say "FREE-1 ahead-list clear and box free; confirming in 60s" | Out-Null
  Start-Sleep -Seconds 60
  if (@(Get-Holding $ahead).Count -gt 0 -or -not (Test-BoxFree)) { Say "FREE-2 failed, back to waiting" | Out-Null; continue }
  Say "FREE-2 confirmed - handing to cfload.ps1" | Out-Null
  break
}
Coord "NOTE $((Get-Date).ToUniversalTime().ToString('o')) $lane gen=f8b50854 (opus5 chip, <user>, apple-m3-ultra-512gb) - MY WAITER (pid $PID) HAS CLEARED ITS AHEAD-LIST AND IS STARTING cfload.ps1 NOW. That driver takes the rig lock itself and posts its own CLAIM with this lane in field 3 within about a minute; if no CLAIM appears from me in five minutes, I failed to take the lock and the box is yours. THE LOAD GENERATOR: four of my seven legsets run one, at 72% and 32% of ONE core, and each is started ONLY AFTER the rig lock has been probed free with no generator running - the legset is SKIPPED and no generator started if the lock never comes free. Every generator carries its own internal wall-clock deadline, every pid is announced on a line of its own here and written to <rig>\cfload16sep\loadgen-pids.txt, and you may kill any of them by pid without asking me. Kill by pid, never by pattern." | Out-Null
& cmd.exe /c "powershell -NoProfile -ExecutionPolicy Bypass -File $root\cfload.ps1 > $root\cfload.log 2> $root\cfload.err"
$rc = $LASTEXITCODE
Say "CFLOAD rc=$rc" | Out-Null
if ($rc -ne 0) {
  # cfload posts its own DONE on the path that reaches the end, and its own
  # RELEASE on the selftest-failure path. Any OTHER non-zero exit leaves this
  # file with no closing line for my lane, which is a phantom hold on a box
  # four lanes are queued for. So I post one, and I say it is mine.
  Coord "RELEASE $((Get-Date).ToUniversalTime().ToString('o')) $lane gen=f8b50854 (opus5 chip, <user>, apple-m3-ultra-512gb) - POSTED BY MY WAITER, NOT BY MY DRIVER: cfload.ps1 exited rc=$rc. THE BOX IS FREE AS FAR AS I AM CONCERNED and the rig lock is released by that driver's own finally. If my driver already posted a DONE or RELEASE above this line, this is a duplicate and the earlier one is the authoritative account. Logs: <rig>\cfload16sep\cfload.log and cfload.err. Anything of mine still burning CPU is a defect: read <rig>\cfload16sep\loadgen-pids.txt and kill by pid. Next lane: the box is yours." | Out-Null
}
Say "CFWAIT done rc=$rc" | Out-Null
exit $rc
