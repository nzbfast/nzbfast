param(
  [Parameter(Mandatory=$true)][string]$Root,     # the wcomb rig root (src\, fix\ beneath it)
  [Parameter(Mandatory=$true)][string]$Tag,      # the queued round's tag
  [Parameter(Mandatory=$true)][string]$UntilUtc, # give up waiting past this, e.g. 2026-09-15T08:00:00Z
  [string]$Phase = 'validate',                   # wcomb.ps1 -Phase
  [string]$AltBin = '',                          # wcomb.ps1 -AltBin
  [switch]$NoBuild                               # wcomb.ps1 -NoBuild
)
# wcombq.ps1 - wait for a Windows rig box to come free, then run ONE wcomb.ps1 round.
#
# wlaunch.ps1 refuses outright while another round holds the box's rig lock,
# which is right for a round and useless for a lane that has to queue behind a
# multi-hour sweep it does not own. This waits instead, and never takes or
# clears anybody's lock itself: the round it starts takes the lock through
# plib's Take-RigLock, exactly as a wlaunch start would, so a third lane that
# wins the race in the gap is refused by the lock and this exits 17 with it.
#
# FREE means BOTH: no ~\.parfast-rig.lock AND no parfast process, twice, a
# minute apart. The lock alone is not enough - a round's lock is released a
# beat before its last child exits, and a round that takes no lock at all is
# still load - and one quiet sample is not enough either, because a queue
# runner steps from one round to the next in under a second.
#
# EXPLICIT PARAMETERS, NOT A PASS-THROUGH STRING. The first cut took
# `-RoundArgs "-Phase validate -AltBin ..."` and forwarded it, and through
# `cmd /c powershell -File` a quoted value that begins with `-` did not
# arrive: on 14 Sep 2026 the queued round started with NO arguments, fell back
# to wcomb.ps1's defaults and ran a whole measure phase in place of the
# validate it was queued for. Every forwarded knob is named here instead, and
# the round's own ROUND line (`phase=...`) is the thing to read to confirm it.
#
# Start it DETACHED (Win32_Process::Create), for the job-object reason in
# wlaunch.ps1's header. It writes the round's log itself, to $Root\$Tag.log.
$ErrorActionPreference = 'Stop'
# BUSY IS A HOLDER, NOT A FILE. `Test-Path $lk` was the whole lock half of this
# predicate until 16 Sep 2026, so an ORPHAN - a lock left by a round that died
# between creating the file and writing its identity - parked a queued round
# here until its own deadline and exited 5 having run nothing. That is the
# apple-m3-ultra shape (an internal note), in
# the one place where its cost is silent: the queue simply never starts, and
# the log says only that the box never came free.
#
# Test-RigLockHeld puts the question to the holder's own pid. BOTH OTHER HALVES
# OF THIS PREDICATE ARE DELIBERATE AND STAY: the `Get-Process parfast` test
# catches a round that never took the lock at all, which the lock cannot see;
# and the caller's twice-60s-apart double check below is an anti-race, not
# redundancy - a round that has just released the lock may not have exited yet.
. (Join-Path $PSScriptRoot 'plib.ps1')
$lk = Get-RigLockPath
$deadline = [datetime]::Parse($UntilUtc).ToUniversalTime()
function Test-Busy { (Test-RigLockHeld) -or [bool](Get-Process parfast -ErrorAction SilentlyContinue) }
function Get-Ts { (Get-Date).ToUniversalTime().ToString('o') }
$fwd = "-Phase $Phase"
if ($AltBin) { $fwd += " -AltBin $AltBin" }
if ($NoBuild) { $fwd += ' -NoBuild' }
"WCOMBQ-WAIT tag=$Tag until=$UntilUtc forward='$fwd' pid=$PID ts=$(Get-Ts)"
while ($true) {
  if (-not (Test-Busy)) {
    Start-Sleep -Seconds 60
    if (-not (Test-Busy)) { break }
  }
  if ((Get-Date).ToUniversalTime() -gt $deadline) { "WCOMBQ-DEADLINE the box never came free ts=$(Get-Ts)"; exit 5 }
  Start-Sleep -Seconds 60
}
"WCOMBQ-FREE ts=$(Get-Ts)"
$h = Join-Path $Root 'src\research\harness'
$log = Join-Path $Root "$Tag.log"
cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File $h\wcomb.ps1 -Root $Root -Tag $Tag $fwd > `"$log`" 2>&1"
"WCOMBQ-DONE rc=$LASTEXITCODE log=$log ts=$(Get-Ts)"
