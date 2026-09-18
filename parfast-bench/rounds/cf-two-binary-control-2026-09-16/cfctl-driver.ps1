# cfctl.ps1 - the two-binary c_f control on intel-i5-10600kf, lane
# parfast-cf-two-binary-control-16sep.
#
# ONE sitting, ONE fixture, TWO release binaries built on this box:
#   A = 87ee76638 (14 Sep, the round that published c_f = 4.251e-6 / k = 312)
#   B = a current origin/main tip
# and `wcomb.ps1 -Phase measure` at 64 KiB run INTERLEAVED A-B-B-A at
# -Threads 4,6,12, one rep per invocation, so each binary gets two reps and
# neither one always runs first. That ABBA is the whole instrument: it
# separates "the fold got dearer at high m between those two commits" (the
# divergence follows the BINARY) from "the c_f slope fit is unstable" (it
# follows neither).
#
# The -t6 arm is new and is not a spare: 6 = one thread per PHYSICAL core on a
# 6c/12t part, so it sits between -t4 (under the core count) and -t12 (two
# siblings per core). If c_w at -t6 tracks -t4 and only -t12 misbehaves, the
# full-pool c_w rise between 64 KiB and 1 MiB is SMT; if -t6 already shows it,
# it is the block.
#
# THE LOCK. wcomb.ps1 takes and releases the per-box rig lock itself, so four
# invocations means four holds. They run BACK TO BACK, sub-second apart, which
# cannot be sampled as the "free twice, 60 s apart" every waiter on this box
# requires - see .claude/MACHINES.md, THE PARFAST RIG PROTOCOL ON THIS BOX.
# This driver holds the lock itself across the two BUILDS, because a cargo
# release build is ~2 min of all twelve threads and would land on whoever
# holds the box otherwise.
$ErrorActionPreference = 'Stop'
$root    = '<rig>\cfctl16sep'
$srcA    = Join-Path $root 'A\src'
$srcB    = Join-Path $root 'B\src'
$binA    = Join-Path $srcA 'target\release\parfast.exe'
$binB    = Join-Path $srcB 'target\release\parfast.exe'
$fixsrc  = '<rig>\wcomb-16sep\fix'
$harness = Join-Path $srcB 'research\harness'
$lock    = Join-Path $env:USERPROFILE '.parfast-rig.lock'
. (Join-Path $harness 'plib.ps1')

function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" }

Say "CFCTL start root=$root harnessSrc=$srcB"
Take-RigLock $lock
$builtOk = $false
try {
  # THE FIXTURE IS COPIED, NOT SHARED AND NOT REBUILT. It is the 64 KiB
  # n = 16,384 -c4096 corpus the 14 and 16 Sep rounds both ran, and reusing it
  # is what makes the second binary cost a build rather than a corpus. It is
  # COPIED out of another lane's root rather than pointed at, because the legs
  # write into fix\work\ and that root is nibble-block-size-row-gate-16sep's.
  $fix = Join-Path $root 'fix'
  if (-not (Test-Path (Join-Path $fix 'gold.txt'))) {
    Say "FIXTURE copying $fixsrc -> $fix"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Copy-Item $fixsrc $fix -Recurse -Force
    Say "FIXTURE copied secs=$([math]::Round($sw.Elapsed.TotalSeconds,1))"
  } else { Say "FIXTURE reused $fix" }
  cmd /c "attrib +I `"$root\*`" /S /D" | Out-Null

  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  foreach ($p in @(@('A', $srcA, $binA), @('B', $srcB, $binB))) {
    if (Test-Path $p[2]) { Say "BUILD $($p[0]) skipped, binary present"; continue }
    $bw = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $p[1]
    cmd /c "cargo build --release -p parfast --locked > `"$root\build-$($p[0]).log`" 2>&1"
    $brc = $LASTEXITCODE
    Pop-Location
    Say "BUILD $($p[0]) rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$root\build-$($p[0]).log"
    if ($brc -ne 0) { Say "CFCTL-FAIL build $($p[0])"; exit 9 }
  }
  $hA = (Get-FileHash $binA -Algorithm SHA256).Hash
  $hB = (Get-FileHash $binB -Algorithm SHA256).Hash
  Say "BIN A sha256=$hA $binA"
  Say "BIN B sha256=$hB $binB"
  # TWO IDENTICAL BINARIES WOULD MAKE THIS ROUND AN A/A AND NOBODY WOULD SEE
  # IT. An extract that silently landed the same tree twice, or a build that
  # skipped, reads exactly like a clean control that found no difference.
  if ($hA -eq $hB) { Say "CFCTL-FAIL the two binaries are byte-identical - this is an A/A, not a control"; exit 9 }
  $builtOk = $true
} finally {
  Release-RigLock $lock
}
if (-not $builtOk) { exit 9 }

# A-B-B-A. Tag per invocation so the four logs stay separable; the reducer is
# a MINIMUM over reps, so A1+A2 reduce to one cell and B1+B2 to the other.
$plan = @(
  @('cfA1', $binA), @('cfB1', $binB), @('cfB2', $binB), @('cfA2', $binA)
)
$wcomb = Join-Path $harness 'wcomb.ps1'
foreach ($step in $plan) {
  $tag = $step[0]; $bin = $step[1]
  $out = Join-Path $root "$tag.log"
  $rc = 17
  for ($try = 1; $try -le 20 -and $rc -eq 17; $try++) {
    if ($try -gt 1) { Say "LEGSET $tag lock busy, retry $try in 20s"; Start-Sleep -Seconds 20 }
    cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$root`" -Phase measure -Tag $tag -Bin `"$bin`" -NoBuild -Reps 1 -Threads 4,6,12 > `"$out`" 2>`"$root\$tag.err`""
    $rc = $LASTEXITCODE
  }
  $legs = 0
  if (Test-Path $out) { $legs = @(Select-String -Path $out -Pattern '^LEG ' -SimpleMatch:$false).Count }
  Say "LEGSET $tag rc=$rc legs=$legs log=$out"
  if ($rc -ne 0) { Say "CFCTL-FAIL $tag rc=$rc"; exit 9 }
}
Say "CFCTL ALL DONE"
