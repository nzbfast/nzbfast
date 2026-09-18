# Sequential round runner. Waits for the per-box rig lock to clear, then runs
# each round in turn, one at a time, logging to its own file.
#
# It waits on the LOCK and never on a marker line in another round's log: a log
# renamed when it is banked silently disarms every round waiting on it, which
# cost four minutes of silence and could have cost a night.
# ONE string, split here. `powershell -File script.ps1 -rounds a b` does not
# reliably bind successive tokens into a [string[]] under Windows PowerShell
# 5.1, and `-rounds a,b` binds the literal "a,b" as a single element. The first
# attempt asked for a round named "zfull,zswp", reported it MISSING and exited
# zero - which reads exactly like a queue that finished its work.
param([string]$root)
# The round list comes from a FILE, one name per line, not from a parameter.
# Two attempts at passing it as an argument both failed silently and in ways
# that read like success: `-rounds a,b` reached the script as one element named
# "a,b" and the queue reported it MISSING and exited zero; `-rounds a b` bound
# only "a". powershell.exe -File's own argument parser is between us and the
# param block and it rewrites commas. A file has no parser in the way.
$listfile = Join-Path $root 'queue3.rounds'
$rounds = @(Get-Content $listfile -EA SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
if (-not $rounds) { "QUEUE3-NOROUNDS $listfile is missing or empty"; exit 20 }
# The lock moved to an absolute per-box path today, so a round that STARTED
# before that change still holds a legacy `<round>.lock` or `RIG.lock` beside
# its own log and knows nothing about the new one. Waiting only on the new path
# would read FREE while a round is plainly running, which is the exact
# collision the absolute path was introduced to prevent. Wait on both until the
# last legacy round has drained.
# A LOCK IS ONLY MEANINGFUL WHILE ITS HOLDER IS ALIVE, and until 16 Sep 2026
# this function applied that rule to the LEGACY locks and not to the new one -
# the legacy arm below parsed `pid=` and asked whether that process was still
# running, while the box lock two lines above it was held by merely EXISTING.
# So the arm written for locks that were on their way out was right and the arm
# for the one every round now takes was wrong, in the direction that wedges a
# QUEUE: an orphaned box lock made this runner report busy on every poll and
# the whole rounds list simply never started, saying only that the box was
# never free. That is the apple-m3-ultra shape
# (an internal note), amplified - one
# orphan holds up every round behind it rather than one.
#
# Spelled INLINE rather than imported, and deliberately: this runner
# dot-sources no plib.ps1 today and giving it one would add a deployment
# dependency to a script that is launched standalone on every rig. The
# canonical statement of the rule is plib.ps1's Get-RigLockHolder (and
# riglock_state.py on unix); the unix shell takers made the same call for the
# same reason, so a reader who has seen one recognises this. It is ONE local
# helper used by both arms rather than a second copy inside this file - which
# is how the two arms came to disagree in the first place.
#
# LIVENESS COMES FROM THE HOLDER, NEVER FROM THE CLOCK: no age bound here, and
# none may be added. A legitimate round holds a box for hours.
function Test-LockHolderAlive([string]$path) {
  try {
    # FileShare ReadWrite: a HELD lock is readable since Take-RigLock moved to
    # FileShare::Read, but only to a reader that also permits the holder's
    # WRITE - ReadAllText does not, and would report every live holder as
    # unreadable.
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try { $txt = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Close() }
  } catch { return $true }   # unreadable for any other reason means open, means held
  if ($txt -match 'pid=(\d+)') {
    return [bool](Get-Process -Id ([int]$Matches[1]) -EA SilentlyContinue)
  }
  return $false             # names nobody - zero bytes or no pid - so it is nobody's
}
function Test-AnyLock([string]$root) {
  $new = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  if ((Test-Path $new) -and (Test-LockHolderAlive $new)) { return $new }
  foreach ($f in @(Get-ChildItem (Join-Path $root '*.lock') -EA 0)) {
    if (Test-LockHolderAlive $f.FullName) { return $f.FullName }
  }
  # And a lock only excludes rounds that TOOK one. memfloor.ps1 took none at
  # all, so on 11 Sep 2026 this queue read the box as free and started a
  # create of a 23 GiB set while a repair was still running on it. A tool
  # binary from our own bin directory is running iff a round is in progress,
  # whatever any script remembered to do, so that is the check that does not
  # depend on every script being correct.
  foreach ($t in @('parfast','par2turbo','par2j64','phpar2','parpar','par2')) {
    $q = Get-Process -Name $t -EA SilentlyContinue
    if ($q) { return ("tool " + $t + " pid=" + ($q | ForEach-Object { $_.Id }) -join ',') }
  }
  return $null
}

$ErrorActionPreference = 'Continue'
"QUEUE3-START $((Get-Date).ToUniversalTime().ToString('o')) rounds=$($rounds -join ',') count=$($rounds.Count)"
$waited = 0
while ($held = Test-AnyLock $root) {
  if ($waited % 600 -eq 0) { "QUEUE3-WAIT held by $held ($([int]($waited/60))m)" }
  Start-Sleep -Seconds 60; $waited += 60
  if ($waited -gt 86400) { "QUEUE3-TIMEOUT $held still held after 24h"; exit 19 }
}
foreach ($r in $rounds) {
  $script = Join-Path $root "$r.ps1"
  if (-not (Test-Path $script)) { "QUEUE3-MISSING $script"; continue }
  "QUEUE3-BEGIN $r $((Get-Date).ToUniversalTime().ToString('o'))"
  & powershell -NoProfile -ExecutionPolicy Bypass -File $script *>&1 |
      Out-File -FilePath (Join-Path $root "$r.log") -Encoding utf8
  "QUEUE3-END $r rc=$LASTEXITCODE $((Get-Date).ToUniversalTime().ToString('o'))"
}
"QUEUE3-DONE $((Get-Date).ToUniversalTime().ToString('o'))"
