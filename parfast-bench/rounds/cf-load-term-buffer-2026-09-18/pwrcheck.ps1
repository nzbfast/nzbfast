# pwrcheck.ps1 - validate the per-leg frequency and thermal fields item 3 adds
# to wcomb.ps1, ON THE BOX, because a field that parses on a Mac and reads
# empty on Windows is exactly the failure a harness edit has to exclude.
#
# IT RUNS AFTER PHASE A AND PHASE B AND NEVER BESIDE THEM. Those legs are
# measured on the instrument pinned at 07a24a959 so they can be read against
# the banked corpus; these run on the NEW harness, which is a different
# instrument. Mixing the two silently is the one thing the round must not do,
# so this is a separate root, a separate tag, and it is launched by hand once
# the driver has posted its DONE.
#
# SIX LEGS, not a ladder. The question is "do the fields appear, are they
# plausible, and does every existing reducer still parse the line" - two rungs
# at one pool answers all three, and nothing here is a measurement of c_f.
$ErrorActionPreference = 'Stop'
$root    = '<rig>\cfpwr18sep'
$harness = Join-Path $root 'harness'
$bin     = '<rig>\cfbuf18sep\parfast.exe'
$fixsrc  = '<rig>\cfbuf18sep\fix'
$fix     = Join-Path $root 'fix'
. (Join-Path $harness 'plib.ps1')
function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" }

Say "PWRCHECK start root=$root"
foreach ($f in @((Join-Path $harness 'plib.ps1'), (Join-Path $harness 'wcomb.ps1'))) {
  Say "HARNESS $([IO.Path]::GetFileName($f)) sha256=$((Get-FileHash $f -Algorithm SHA256).Hash.Substring(0,16))"
}
# The bare function first, so a broken counter query is diagnosed here rather
# than as an empty column in a leg line.
$p = Get-PowerState
Say "POWERSTATE freq_mhz=$($p.FreqMhz) perf_pct=$($p.PerfPct) temp_c=$($p.TempC) throttle_pct=$($p.ThrottlePct) pkg_w=$($p.PkgW)"
$sw = [Diagnostics.Stopwatch]::StartNew(); $null = Get-PowerState
Say "POWERSTATE cost_ms=$([math]::Round($sw.Elapsed.TotalMilliseconds,0)) (warm; it is paid OUTSIDE the timed window)"

$got = $false
for ($t = 1; $t -le 15 -and -not $got; $t++) {
  Try-TakeRigLock 'pwrcheck'
  $got = $script:riglock_taken
  if (-not $got) { Say "RIG-LOCK busy, retry $t in 20s"; Start-Sleep -Seconds 20 }
}
if (-not $got) { Say "PWRCHECK-FAIL could not take the rig lock"; exit 17 }
try {
  if (-not (Test-Path (Join-Path $fix 'gold.txt'))) {
    Say "FIXTURE copying $fixsrc -> $fix"
    Copy-Item $fixsrc $fix -Recurse -Force
  }
  cmd /c "attrib +I `"$root\*`" /S /D" | Out-Null
} finally { Release-RigLock 'pwrcheck' }

$out = Join-Path $root 'pwr.log'
cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $harness 'wcomb.ps1')`" -Root `"$root`" -Phase measure -Tag pwr -Bin `"$bin`" -NoBuild -Reps 1 -Threads 12 -Rungs 192,512 > `"$out`" 2>`"$root\pwr.err`""
$rc = $LASTEXITCODE
$legs = @(Select-String -Path $out -Pattern '^LEG ').Count
Say "PWRCHECK rc=$rc legs=$legs log=$out"
Say "PWRCHECK DONE"
