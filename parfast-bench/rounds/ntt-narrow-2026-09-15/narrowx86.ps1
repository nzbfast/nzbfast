param(
  [Parameter(Mandatory=$true)][string]$Root,     # holds src\ (the base tree), new\ (the overlay), and the logs
  [Parameter(Mandatory=$true)][string]$Tag,      # the wcomb round's tag; its log is $Root\$Tag.log
  [Parameter(Mandatory=$true)][string]$Rungs,    # wcomb.ps1 -Rungs, comma separated
  [Parameter(Mandatory=$true)][string]$UntilUtc  # give up waiting for a free box past this
)
# narrowx86.ps1 - build BOTH sides of a dispatcher A/B on a Windows rig box, then run it.
#
# Written 15 Sep 2026 for lane parfast-ntt-narrow-admits-unpriced-stripe-14sep
# (an internal note, section 8).
# wcomb.ps1 builds ONE binary from $Root\src and takes the other as -AltBin, and
# wcombq.ps1 forwards no -Rungs, so neither can run an A/B of an unlanded change
# over a chosen rung set by itself. This does, in order:
#
#   1. waits until the box is FREE - no ~\.parfast-rig.lock and no parfast
#      process, twice a minute apart (wcombq.ps1's rule) - or exits 5 past
#      -UntilUtc;
#   2. builds $Root\src (the BASE tree) and keeps parfast.exe as
#      $Root\parfast-base.exe;
#   3. copies every file under $Root\new over src AND RESTAMPS ITS MTIME. The
#      restamp is load-bearing: Copy-Item keeps the source's LastWriteTime,
#      the overlay files were edited before step 2's artefacts were written,
#      and cargo's fingerprint would call the tree fresh and hand back the
#      base binary a second time;
#   4. rebuilds, refuses if the two binaries hash the same, and runs
#      wcomb.ps1 -Phase validate -NoBuild -AltBin <base> -Rungs <rungs>, which
#      takes the rig lock itself (so `auto` is the change, `autoalt` the base).
#
# Launch it DETACHED through harness/wlaunch.ps1 (the job-object trap
# in that header), with a wlaunch -Tag that differs from -Tag here, or the two
# logs collide.
$ErrorActionPreference = 'Stop'
$lk = Join-Path $env:USERPROFILE '.parfast-rig.lock'
function Get-Ts { (Get-Date).ToUniversalTime().ToString('o') }
# riglock-round-dir-waiters-16sep: presence-as-hold (Test-Path, no liveness
# check) is the defect fixed for the shared harness in 49d5c9795 - see
# harness/riglock_state.py and
# an internal note. This copy is the
# RECORD of the 15 Sep ntt-narrow round as it actually ran (base/fold/force/new
# .jsonl and the driver/validate logs are banked beside this file); left
# unconverted so the record matches the binary-plus-script that produced them.
function Test-Busy { (Test-Path $lk) -or [bool](Get-Process parfast -ErrorAction SilentlyContinue) }
$deadline = [datetime]::Parse($UntilUtc).ToUniversalTime()
"NARROW-WAIT tag=$Tag rungs=$Rungs until=$UntilUtc pid=$PID ts=$(Get-Ts)"
while ($true) {
  if (-not (Test-Busy)) {
    Start-Sleep -Seconds 60
    if (-not (Test-Busy)) { break }
  }
  if ((Get-Date).ToUniversalTime() -gt $deadline) { "NARROW-DEADLINE the box never came free ts=$(Get-Ts)"; exit 5 }
  Start-Sleep -Seconds 60
}
"NARROW-FREE ts=$(Get-Ts)"
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }
$src = Join-Path $Root 'src'
$exe = Join-Path $src 'target\release\parfast.exe'
$base = Join-Path $Root 'parfast-base.exe'

function Invoke-Build([string]$label) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c for the reason wcomb.ps1 gives: cargo's stderr progress is a
  # terminating error under 'Stop' in PowerShell 5.1.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-$label.log`" 2>&1"
  $rc = $LASTEXITCODE
  Pop-Location
  "NARROW-BUILD $label rc=$rc secs=$([math]::Round($sw.Elapsed.TotalSeconds,1)) ts=$(Get-Ts)"
  if ($rc -ne 0) { "NARROW-FAIL build $label, see $Root\build-$label.log"; exit 9 }
}

Invoke-Build 'base'
Copy-Item $exe $base -Force
$newRoot = (Resolve-Path (Join-Path $Root 'new')).Path
foreach ($f in Get-ChildItem $newRoot -Recurse -File) {
  $rel = $f.FullName.Substring($newRoot.Length + 1)
  $dst = Join-Path $src $rel
  Copy-Item $f.FullName $dst -Force
  (Get-Item $dst).LastWriteTime = Get-Date
  "NARROW-OVERLAY $rel"
}
Invoke-Build 'new'
$hb = (Get-FileHash $base).Hash
$hn = (Get-FileHash $exe).Hash
"NARROW-BINS base=$hb new=$hn"
if ($hb -eq $hn) { "NARROW-FAIL the overlay did not change the binary"; exit 9 }
$h = Join-Path $src 'research\harness'
cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File $h\wcomb.ps1 -Root $Root -Phase validate -NoBuild -AltBin $base -Tag $Tag -Rungs $Rungs > `"$Root\$Tag.log`" 2>&1"
"NARROW-DONE rc=$LASTEXITCODE log=$Root\$Tag.log ts=$(Get-Ts)"
