# A/A protocol probe (Windows half) - the twin of aa-protocol.sh, and the two
# must stay in step: same arms, same rounds, same shapes, same flags.
#
# Races ONE binary against a BYTE-IDENTICAL COPY of itself over the short
# stored shapes under each candidate harness protocol, so "is a two-arm race
# on this box separable at all" is measured rather than assumed. Read
# bench/component/aa-position.py's docstring for what flat means.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File aa-protocol.ps1 `
#       -Sr $env:USERPROFILE\shapes-round -Bin $env:USERPROFILE\blk2\prodrar-base.exe
#
# SHIP IT AS A FILE. The default shell over ssh to these boxes is cmd, and
# quoting this through `powershell -Command` costs more attempts than the
# copy does.
param(
  [string]$Sr      = "$env:USERPROFILE\shapes-round",
  [string]$Bin     = "$env:USERPROFILE\blk2\prodrar-base.exe",
  # Arm 2. Left empty this is an A/A - a byte-identical copy of $Bin, which
  # is the control. Point it at a DIFFERENT build and the same script runs
  # the real comparison under the same protocol, which is the only way the
  # two readings are comparable.
  [string]$Bin2    = "",
  # Which protocol arms to run, comma-separated, from the names below.
  [string]$Protocols = "p0-rotate,p1-mirror,p2-rotate-settle,p3-mirror-settle",
  [string]$Out     = "",
  [string]$Shoot   = "",
  [string]$Shapes  = "storev,encstore,encstorep",
  [int]$Rounds     = 6,
  [int]$Settle     = 3000,
  [string]$Tag     = "aa"
)
$ErrorActionPreference = "Stop"
if ($Out   -eq "") { $Out   = "$Sr\log" }
if ($Shoot -eq "") { $Shoot = "$Sr\bin\shootout.exe" }
# A box that already has an OLD shootout under that name will run the whole
# probe against a harness that does not know --layout and panics on it, and
# the arms that happen not to use the flag come back looking fine. Refuse
# up front instead: the banner line carries the protocol from this version on.
New-Item -ItemType Directory -Force -Path $Out, "$Sr\work\aa" | Out-Null

# The two arms are the same bytes. Copy rather than hardlink: a hardlink is
# one file to the cache and the loader, which would hide exactly what this
# probe measures.
$a1 = "$Sr\bin\$Tag-arm1.exe"
$a2 = "$Sr\bin\$Tag-arm2.exe"
Copy-Item -Force $Bin $a1
Copy-Item -Force (&{ if ($Bin2 -eq "") { $Bin } else { $Bin2 } }) $a2
$same = (Get-FileHash $a1).Hash -eq (Get-FileHash $a2).Hash
if ($Bin2 -eq "" -and -not $same) { throw "A/A arms differ - $Bin was copied twice and the copies do not match" }
Write-Host ("mode: " + $(if ($same) { "A/A (identical arms) - this is the control" } else { "A/B - arm2 is $Bin2" }))

function Race($name, $rounds, $extra) {
  Write-Host "=== $name $($extra -join ' ') ==="
  # A native command writing ANYTHING to stderr is a terminating error under
  # $ErrorActionPreference = "Stop", which would abandon the round rather
  # than record it. Take the reading, then check the exit code.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  $argv = @("race", "--shapes", "$Sr\shapes", "--work", "$Sr\work\aa",
            "--manifest", "$Sr\manifest.txt", "--rounds", "$rounds",
            "--tools", "ours-${Tag}1,ours-${Tag}2", "--only", $Shapes,
            "--tool-bin", "ours-${Tag}1=$a1", "--tool-bin", "ours-${Tag}2=$a2") + $extra
  & $Shoot @argv *>&1 | Out-File -Encoding ascii "$Out\$Tag-$name.log"
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  if ($rc -ne 0) { throw "${name}: shootout exited $rc - see $Out\$Tag-$name.log" }
}

# One THROWAWAY round first: a freshly written .exe is scanned by Defender on
# its first execution, and that scan lands entirely on whichever arm runs
# first - which is the bias this probe exists to measure.
Race "warmup-discarded" 1 @("--layout","mirror")
if (-not (Select-String -Path "$Out\$Tag-warmup-discarded.log" -Pattern "layout=mirror" -Quiet)) {
  throw "$Shoot does not understand --layout: it is an OLD shootout. Rebuild it from bench/component/shootout.rs, or pass -Shoot <path to the rebuilt one>."
}

$want = $Protocols.Split(",")
if ($want -contains "p0-rotate")        { Race "p0-rotate"        $Rounds @() }
if ($want -contains "p1-mirror")        { Race "p1-mirror"        $Rounds @("--layout","mirror") }
if ($want -contains "p2-rotate-settle") { Race "p2-rotate-settle" $Rounds @("--settle-ms","$Settle") }
if ($want -contains "p3-mirror-settle") { Race "p3-mirror-settle" $Rounds @("--layout","mirror","--settle-ms","$Settle") }
Write-Host "logs in $Out\$Tag-p*.log"
