# Corrupt N distinct blocks of a rig's payload, seeded and spread across
# its files - the Windows twin of par2-mkdamage.py, and it damages the
# SAME blocks for the same seed, so a crossover sweep is comparable
# between boxes.
#
#   powershell -File par2-mkdamage.ps1 -N 256 [-Seed 20260902] [-Bs 65536]
#
# Results: research/PAR2-PERF-AUDIT-2026-09-02.md section 7.
param(
  [string]$Root = "$env:USERPROFILE\paraudit\rig",
  [int]$N       = 256,
  [int]$Seed    = 20260902,
  [int]$Bs      = 65536
)
$src = "$Root\pristine-heavy"; $dst = "$Root\damaged-m$N"
if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
Copy-Item -Recurse $src $dst
$blocks = @()
foreach ($f in (Get-ChildItem "$dst\*" -File | ? { $_.Name -notlike "*.par2" } | Sort-Object Name)) {
  $nb = [math]::Ceiling($f.Length / $Bs)
  for ($i = 0; $i -lt $nb; $i++) { $blocks += ,@($f.FullName, $i) }
}
if ($N -gt $blocks.Count) { throw "$N blocks asked of a $($blocks.Count)-block corpus" }
# Partial Fisher-Yates over a seeded .NET RNG: the first N picks are the
# sample, and Python's random.sample over the same seed is a different
# sequence - so compare a sweep against ITS OWN box's other arms, and
# across boxes only leg for leg at the same N.
$rng = New-Object System.Random($Seed)
$idx = 0..($blocks.Count - 1)
for ($k = 0; $k -lt $N; $k++) {
  $j = $k + $rng.Next($blocks.Count - $k)
  $t = $idx[$k]; $idx[$k] = $idx[$j]; $idx[$j] = $t
}
$pat = [byte[]](@(0xA5, 0x5A, 0xC3, 0x3C) * 1024)
for ($k = 0; $k -lt $N; $k++) {
  $b = $blocks[$idx[$k]]
  $fs = [System.IO.File]::Open($b[0], 'Open', 'Write')
  $fs.Seek([int64]($b[1] * $Bs + 17), 'Begin') | Out-Null
  $fs.Write($pat, 0, $pat.Length); $fs.Close()
}
"damaged-m$N`: $N blocks over $((Get-ChildItem "$dst\*" -File | ? { $_.Name -notlike '*.par2' }).Count) files (seed $Seed, bs $Bs)"
