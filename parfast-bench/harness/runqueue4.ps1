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
param([string]$root, [string]$list = 'queue3.rounds')
# runqueue4 is runqueue3 with the rounds FILE as a parameter and the tool
# census widened to the suffixed binaries. Deployed under a new name rather
# than over runqueue3: a queue runner is typically LIVE with a multi-hour round
# under it when the next one is written, and overwriting the file a running
# process was parsed from is a risk with no upside.
# The round list comes from a FILE, one name per line, not from a parameter.
# Two attempts at passing it as an argument both failed silently and in ways
# that read like success: `-rounds a,b` reached the script as one element named
# "a,b" and the queue reported it MISSING and exited zero; `-rounds a b` bound
# only "a". powershell.exe -File's own argument parser is between us and the
# param block and it rewrites commas. A file has no parser in the way.
$listfile = Join-Path $root $list
$rounds = @(Get-Content $listfile -EA SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
if (-not $rounds) { "QUEUE3-NOROUNDS $listfile is missing or empty"; exit 20 }
# The lock moved to an absolute per-box path today, so a round that STARTED
# before that change still holds a legacy `<round>.lock` or `RIG.lock` beside
# its own log and knows nothing about the new one. Waiting only on the new path
# would read FREE while a round is plainly running, which is the exact
# collision the absolute path was introduced to prevent. Wait on both until the
# last legacy round has drained.
function Test-AnyLock([string]$root) {
  $new = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  if (Test-Path $new) { return $new }
  foreach ($f in @(Get-ChildItem (Join-Path $root '*.lock') -EA 0)) {
    # a legacy lock is only meaningful while its holder is alive
    try {
      $txt = [IO.File]::ReadAllText($f.FullName)
      if ($txt -match 'pid=(\d+)') {
        if (Get-Process -Id ([int]$Matches[1]) -EA SilentlyContinue) { return $f.FullName }
      }
    } catch { return $f.FullName }   # unreadable means open, means held
  }
  # And a lock only excludes rounds that TOOK one. memfloor.ps1 took none at
  # all, so on 11 Sep 2026 this queue read the box as free and started a
  # create of a 23 GiB set while a repair was still running on it. A tool
  # binary from our own bin directory is running iff a round is in progress,
  # whatever any script remembered to do, so that is the check that does not
  # depend on every script being correct.
  foreach ($t in @('parfast','parfast-jx','parfast-joint','par2turbo','par2j64','phpar2','parpar','par2')) {
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
