# PAR2 CREATE legs, Windows: the twin of par2-create-legs.sh.
#
#   powershell -File par2-create-legs.ps1 -Tag I5 [-Reps 2] [-Pct 10]
#
# ParPar publishes no Windows build on the fleet's boxes, so the default
# arms are ours and par2cmdline-turbo; pass -Parpar to add it.
# Results: research/PAR2-PERF-AUDIT-2026-09-02.md section 14.
param(
  [string]$Tag    = "WIN",
  [string]$Root   = "$env:USERPROFILE\paraudit",
  [string]$Ours   = "$env:USERPROFILE\paraudit\bin\par2_create_bench.exe",
  [string]$Turbo  = "$env:USERPROFILE\paraudit\bin\turbo150\par2.exe",
  [string]$Parpar = "",
  # The PRODUCT arm, added 4 Sep 2026: `ours` is the par2_create_bench
  # harness and measures the ENGINE, `parfast` is the binary a user runs.
  [string]$Parfast = "$env:USERPROFILE\paraudit\bin\parfast.exe",
  # Arm ORDER is a protocol knob, not a cosmetic one. This script used a
  # fixed order, and memory nzbfast-par2-perf-audit-2026-09-02 records a
  # fixed order on a laptop manufacturing a 4/4 sweep for whichever arm
  # ran first, off ~35 pct drift per round. Pass the arms in one order,
  # then again reversed, and compare.
  [string]$Tools  = "",
  [int]$Reps      = 2,
  [int]$Pct       = 10,
  [int[]]$Sizes   = @(1048576, 65536)
)
$src = "$Root\rig\pristine"; $out = "$Root\out"
Get-ChildItem "$src\*" -File | ? { $_.Name -notlike "*.par2" } | % { $null = [System.IO.File]::ReadAllBytes($_.FullName) }
"BIN ours $((Get-FileHash $Ours).Hash) turbo $(& $Turbo --version 2>&1 | select -First 1)"
$files = Get-ChildItem "$src\*" -File | ? { $_.Name -notlike "*.par2" } | % FullName
if ($Tools) { $arms = $Tools.Split(",") } else { $arms = @("ours","turbo16"); if ($Parpar) { $arms += "parpar" } }
foreach ($r in 1..$Reps) { foreach ($bs in $Sizes) { foreach ($tool in $arms) {
  if (Test-Path $out) { Remove-Item -Recurse -Force $out }; New-Item -ItemType Directory $out | Out-Null
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  switch ($tool) {
    "ours"    { & $Ours $src $out $Pct $bs *> $null }
    "parfast" { & $Parfast c -q "-s$bs" "-r$Pct" "-B$src" "$out\bench.par2" @files *> $null }
    "turbo"   { & $Turbo c -q "-s$bs" "-r$Pct" "-B$src" "$out\bench.par2" @files *> $null }
    "turbo16" { & $Turbo c -q "-s$bs" "-r$Pct" -T16 "-B$src" "$out\bench.par2" @files *> $null }
    "parpar"  { Push-Location $src; & $Parpar -q -s "${bs}b" -r "$Pct%" -o "$out\bench.par2" @files *> $null; Pop-Location }
  }
  $sw.Stop()
  "CREATE-$Tag r=$r bs=$bs tool=$tool wall=$([math]::Round($sw.Elapsed.TotalSeconds,3)) files=$((Get-ChildItem $out | measure).Count)"
} } }
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
