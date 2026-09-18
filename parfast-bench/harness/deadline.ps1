param([string]$untilUtc, [int]$roundPid = 0, [string]$match = '', [string]$tag = 'round',
      [string]$roundLog = '', [int]$pollSec = 60)
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
#
# A PID IS UNAMBIGUOUS AND IT IS NOT NECESSARILY THE ROUND'S, which is the
# 17 Sep 2026 defect and the reason for `-roundLog` and everything below it.
# wlaunch.ps1 resolved the round's pid by taking the FIRST powershell child of
# the cmd.exe it spawned, and on both borrowed boxes that was a TRANSIENT:
# armed on 21900 where the round was 2864, and on 1596 where it was 10028.
# Each watcher polled a process that had never been the round, saw it vanish
# within minutes, and exited printing `DEADLINE-ROUND-FINISHED on its own` -
# 32 and 36 minutes before those rounds actually finished. Nothing would have
# stopped either round at its deadline, and the line an operator read said the
# opposite. Full account: an internal note
# defect A.
#
# SO A PID FROM THE CALLER IS A CANDIDATE, NOT A FACT. This script now
# confirms it for itself, which is what makes the guarantee independent of
# whoever armed it:
#
#   1. `-roundLog <path>` - the round's own stdout. Its first line is
#      `RIG-LOCK-TAKEN <lock> round=<tag> pid=<n>`, written by plib's
#      Write-RigLockIdentity, and that is the round naming itself. A pid that
#      matches it is CONFIRMED; a pid that does not is CORRECTED, loudly, and
#      the watcher re-arms on the round.
#   2. the watched process's own command line mentioning the tag. A weak
#      POSITIVE only - a round's command line names the wrapper script, which
#      often does not carry the tag - so a hit confirms and a miss proves
#      nothing and is never reported as a refutation.
#
# AND AN UNCONFIRMED PID NEVER DISARMS THIS WATCHER. That is the half that
# matters, because the failure above was silent rather than loud: an early
# exit on a pid nobody vouched for is indistinguishable, in the log, from a
# round that genuinely finished. While unconfirmed, an empty sample is a
# REFUSAL to disarm and says so, and the watcher holds to its deadline. The
# house rule is that failing to find is failing, and the cost of holding is a
# watcher that outlives its round on a box that was going to be handed back
# anyway; the cost of the other choice is measured above.
#
# THE ONE THING THAT CAN STILL RETIRE AN UNCONFIRMED WATCHER EARLY is the
# round's log saying the round is over - `ALL DONE` or `RIG-LOCK-RELEASED`.
# That is evidence rather than an absence, it names what it read, and it is
# the same file the pid came from.
# WHAT A ROUND'S PROCESS IS CALLED. `powershell` is Windows PowerShell, which
# is what wlaunch.ps1 starts and what every round on this fleet runs under.
# `pwsh` is PowerShell 7 and is accepted for two reasons: a round started by
# hand under it is watchable rather than invisible, and it is what this file's
# selftest runs under on a macOS runner - a guard nothing can drive is a guard
# nobody has tested. NOT a wildcard: the point of the filter is that a RECYCLED
# pid held by some unrelated program is not mistaken for the round.
$roundProcNames = @('powershell', 'pwsh')
# $pollSec IS THE SAMPLE INTERVAL AND NOT THE DEADLINE. The three-empty-samples
# rule below is calibrated on 60 s - a minute apart is what makes three in a
# row impossible to produce with a transient WMI reading - so lowering this
# weakens that rule and is for the selftest, which cannot spend three minutes
# per case. It never moves $untilUtc, which is the guarantee.
$armedAt = (Get-Date).ToUniversalTime()
# plib.ps1 lives BESIDE this script and owns the RIG-LOCK-TAKEN parse, because
# it owns the line's format (Write-RigLockIdentity). Dot-sourced rather than
# copied - one rule, one copy. A MISSING plib is not fatal here and must never
# become fatal: this is the safety mechanism for a borrowed machine, so it
# degrades to "cannot confirm", which by the rule above means it holds to the
# deadline instead of disarming. It says so, once, in its own log.
#
# THE ORDER OF THE NEXT TWO STATEMENTS IS LOAD-BEARING. plib.ps1's top level
# sets $ErrorActionPreference = 'Stop', and a dot-source runs in THIS scope, so
# dot-sourcing it silently replaces this file's deliberate 'Continue' - under
# which a single CIM hiccup in the poll loop below would kill the watcher
# outright. Restore it after, never before.
$haveFacts = $false
$plibPath = Join-Path $PSScriptRoot 'plib.ps1'
if (Test-Path $plibPath) { . $plibPath; $haveFacts = $true }
$ErrorActionPreference = 'Continue'
$deadline = [datetime]::Parse($untilUtc).ToUniversalTime()
if ($roundPid -le 0 -and -not $match) {
  "DEADLINE-FAIL give -roundPid (preferred) or -match; refusing to watch nothing"
  exit 2
}
$empties = 0
# A PATTERN WATCHER IS UNCONFIRMABLE BY CONSTRUCTION and is left exactly as it
# was. It matches whatever matches, its early exit is usually unreachable
# anyway (it finds its own command line), and there is no pid to check against
# the log. `$confirmed` is therefore a question asked only of the pid arm.
$confirmed = $false
$confirmedBy = ''
$how = if ($roundPid -gt 0) { "pid=$roundPid" } else { "match='$match' (FALLBACK - a pattern can match another lane's round)" }
"DEADLINE-ARMED tag=$tag watching=$how until=$($deadline.ToString('o')) now=$($armedAt.ToString('o'))"

function Get-Facts {
  if (-not $haveFacts -or -not $roundLog) { return $null }
  try { return Get-RoundLogFacts $roundLog } catch { return $null }
}

# Confirms, corrects or stays quiet. Never prints on a "not yet" - the round
# may simply not have taken the rig lock, which happens on every launch and is
# not news. Sets $script:roundPid when it corrects.
function Update-Confirmation {
  if ($script:confirmed -or $script:roundPid -le 0) { return }
  $f = Get-Facts
  if ($f -and $f.Pid -gt 0) {
    if ($f.Pid -eq $script:roundPid) {
      $script:confirmed = $true
      $script:confirmedBy = "RIG-LOCK-TAKEN round=$($f.Round)"
      "DEADLINE-PID-CONFIRMED pid=$($script:roundPid) is the round - $($f.Why) in $script:roundLog"
    } else {
      "DEADLINE-PID-CORRECTED armed=$($script:roundPid) round=$($f.Pid) - THE PID THIS WATCHER WAS GIVEN WAS NOT THE ROUND. $script:roundLog says $($f.Why). Re-arming on the round's own pid."
      $script:roundPid = $f.Pid
      $script:confirmed = $true
      $script:confirmedBy = "RIG-LOCK-TAKEN round=$($f.Round) (corrected)"
    }
    return
  }
  # Weak positive: does the process we are watching carry the tag in its own
  # command line? The Name filter is used rather than a ProcessId one for the
  # reason the poll loop below documents at length - a ProcessId filter answers
  # EMPTY from inside this watcher.
  try {
    $me = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA 0 |
            Where-Object { $_.ProcessId -eq $script:roundPid })
    if ($me.Count -and $me[0].CommandLine -and
        $me[0].CommandLine -match [regex]::Escape($script:tag)) {
      $script:confirmed = $true
      $script:confirmedBy = 'command line carries the tag'
      "DEADLINE-PID-CONFIRMED pid=$($script:roundPid) is the round - its command line carries tag=$script:tag"
    }
  } catch { }
}

Update-Confirmation
if ($roundPid -gt 0 -and -not $confirmed) {
  $why = if ($roundLog) { (Get-Facts).Why } elseif (-not $haveFacts) { "plib.ps1 is not beside this script at $plibPath, so the RIG-LOCK-TAKEN line cannot be parsed" } else { 'no -roundLog was given, so there is nothing to check the pid against' }
  "DEADLINE-PID-UNCONFIRMED pid=$roundPid has NOT been confirmed as the round - $why. This watcher will keep trying, and until it succeeds it will NOT disarm on empty samples: an early exit on an unverified pid is the 17 Sep 2026 failure, and it reads like success."
}
while ((Get-Date).ToUniversalTime() -lt $deadline) {
  # Every poll, until it succeeds: the round takes the rig lock when it is
  # ready to, which on a driver that builds first can be a minute after this
  # watcher armed. A watcher that only asked once would hold to the deadline
  # over a round it could have confirmed.
  Update-Confirmation
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
    @(Get-Process -Id $roundPid -EA SilentlyContinue | Where-Object { $roundProcNames -contains $_.ProcessName })
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
    # AN EMPTY SAMPLE ON AN UNCONFIRMED PID MEANS NOTHING, so it cannot retire
    # the guard. Three empty samples say "the process we are watching is gone";
    # they say the ROUND is gone only if that process was ever the round, and on
    # 17 Sep 2026 it was not, on both boxes, and the watcher said
    # DEADLINE-ROUND-FINISHED anyway. The round's own log is the one thing that
    # can still end this early, because it is evidence rather than an absence.
    if (-not $confirmed -and $roundPid -gt 0) {
      $f = Get-Facts
      if ($f -and $f.Finished) {
        "DEADLINE-ROUND-FINISHED-BY-LOG $roundLog says the round is over ($($f.Why)) $((Get-Date).ToUniversalTime().ToString('o'))"
        exit 0
      }
      "DEADLINE-UNCONFIRMED-EMPTY-SAMPLE $empties - REFUSING to disarm: pid=$roundPid was never confirmed as the round, so its absence is not evidence the round finished. HOLDING to $($deadline.ToString('o')). $((Get-Date).ToUniversalTime().ToString('o'))"
    } elseif ($empties -ge 3) {
      "DEADLINE-ROUND-FINISHED on its own after $empties consecutive empty samples $((Get-Date).ToUniversalTime().ToString('o'))"
      exit 0
    } else {
      "DEADLINE-EMPTY-SAMPLE $empties of 3 - not disarming on one reading $((Get-Date).ToUniversalTime().ToString('o'))"
    }
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
  Start-Sleep -Seconds $pollSec
}
# One last look at the log before acting: a round that took its lock late is
# confirmable now, and a correction here still points the kill at the right
# process.
Update-Confirmation
$live = if ($roundPid -gt 0) {
  @(Get-Process -Id $roundPid -EA SilentlyContinue | Where-Object { $roundProcNames -contains $_.ProcessName })
} else {
  @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA 0 | Where-Object { $_.CommandLine -match $match })
}
if (-not $live.Count) {
  # WHY THIS IS TWO OUTCOMES AND NOT ONE. With a confirmed pid, nothing running
  # is the good ending. With a pid this watcher could never vouch for, nothing
  # running says only that THAT process is gone - the round may have been
  # somewhere else all along, still running, on a box somebody wants back. The
  # log settles it when it can, and when it cannot this exits NONZERO and says
  # a human has to look, rather than printing a line that reads like success.
  if ($confirmed) { "DEADLINE-REACHED and the round had already finished"; exit 0 }
  if ($roundPid -gt 0) {
    $f = Get-Facts
    if ($f -and $f.Finished) {
      "DEADLINE-REACHED and $roundLog says the round finished ($($f.Why))"
      exit 0
    }
    "DEADLINE-REACHED-UNCONFIRMED nothing is running as pid=$roundPid, and that pid was NEVER confirmed as the round - this watcher cannot say the round finished. CHECK THE BOX BY HAND: the round may still be running. $((Get-Date).ToUniversalTime().ToString('o'))"
    exit 3
  }
  "DEADLINE-REACHED and the round had already finished"
  exit 0
}
# A PID CAN BE REUSED, and an unconfirmed one is the case where that matters:
# the round always starts BEFORE this watcher arms, so a process on that pid
# whose own start time is LATER than $armedAt cannot be it. Killing whatever
# happens to hold the number now would be the pattern-kill mistake by another
# route, so it is refused, loudly.
if ($roundPid -gt 0 -and -not $confirmed) {
  $started = $null
  try { $started = $live[0].StartTime.ToUniversalTime() } catch { $started = $null }
  if ($started -and $started -gt $armedAt) {
    "DEADLINE-REFUSING-KILL pid=$roundPid is a process that STARTED at $($started.ToString('o')), after this watcher armed at $($armedAt.ToString('o')) - it cannot be the round, and the round's pid was never confirmed. Killing nothing. CHECK THE BOX BY HAND."
    exit 3
  }
  "DEADLINE-KILL-UNCONFIRMED pid=$roundPid was never confirmed as the round; killing it anyway because the deadline is the guarantee and it is the only candidate this watcher has. Read $roundLog to see what actually ran."
}
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
# Unlike plib.ps1's Release-RigLock, THIS process never held $lk open, so it
# has no handle-based guarantee that the file it is about to delete still
# belongs to the round it just killed - a DIFFERENT round could have taken
# the lock in the 4s window above (or between Test-Path and Remove-Item
# here). Best available check without one: refuse to remove unless the
# content still names the pid we killed, mirroring the inode check
# pdrv.RigLock and pmcmp.sh now do for the POSIX side of this same class of
# bug (an internal note).
#
# AND WITHOUT A PID THERE IS NOTHING TO ATTRIBUTE IT TO, so it is left alone.
# The `-match` fallback branch above kills every powershell whose command line
# matches a pattern, which its own header says can be another lane's round; it
# then arrived here and removed the lock UNCONDITIONALLY, which is the same
# clobber this check exists to prevent, reached by the one path that cannot
# check. Leaving it is cheap: since 16 Sep 2026 every taker in the harness
# clears a lock it can PROVE is nobody's, so an orphan we decline to touch
# costs the next round one RIG-LOCK-ORPHAN line rather than its box.
if (Test-Path $lk) {
  $held = ''
  try { $held = (Get-Content $lk -Raw -EA Stop).Trim() } catch { $held = '(unreadable)' }
  if ($roundPid -le 0) {
    "DEADLINE-LOCK-UNATTRIBUTABLE $held - leaving it (armed with -match, so there is no pid to compare). A taker will clear it if it is an orphan."
  } elseif ($held -notmatch "pid=$roundPid(\s|$)") {
    "DEADLINE-LOCK-NOT-OURS $held - leaving it (does not name pid=$roundPid)"
  } else {
    "DEADLINE-LOCK-RELEASED $held"
    Remove-Item $lk -Force -EA SilentlyContinue
  }
}
"DEADLINE-DONE $((Get-Date).ToUniversalTime().ToString('o')) - the box is handed back"
