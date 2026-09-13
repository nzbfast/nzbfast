# Build the ten SCENARIO fixtures on Windows - the twin of
# par2-scenarios-build.sh, and the same shapes byte-for-byte where the box
# has `rar`.
#
#   par2-scenarios-build.ps1 -Root D:\parscen -Par2 C:\bin\par2.exe
#                            [-Corpusgen ...\corpusgen.exe] [-Rar ...\rar.exe]
#                            [-SkipDamaged] [-Skip row5m]
#
# Every payload is a prefix of the ONE fixed-seed stream corpusgen writes
# (`corpusgen rand <file> <bytes>`), so a fixture here is the same bytes as
# the Macs' as long as `rar` is present. Without `rar` the members are SPLIT
# from the payload under the same names and sizes: a store-mode RAR volume is
# a thin header over the payload and PAR2 does not care, but the bytes are
# then not the Macs' and a number from this box is read within this box only.
#
# Two Windows-specific reasons this is not just the .sh under a shell:
#
# - NTFS HAS NO CHEAP CLONE. On APFS the eight damaged trees cost the blocks
#   they damage; here they are eight real copies of a 10 GiB fixture. So
#   -SkipDamaged is the DEFAULT here, and round2.ps1 cuts each row's map into
#   its work copy instead.
# - The set is created by the RIVAL (par2cmdline-turbo), same as the Macs, and
#   turbo refuses a member outside its base path with a message that reads
#   like an argument mistake: pass an ABSOLUTE -B and absolute member paths.
param(
  [string]$Root = "$env:USERPROFILE\parscen",
  [string]$Par2 = "$env:USERPROFILE\paraudit\bin\turbo150\par2.exe",
  [string]$Corpusgen = "",
  [string]$Rar = "",
  [switch]$KeepDamaged,
  [string[]]$Skip = @()
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $PSCommandPath
if (-not $Corpusgen) { $Corpusgen = "$Root\bin\corpusgen.exe" }
if (-not (Test-Path $Corpusgen)) { throw "no corpusgen at $Corpusgen - build it with rustc -O --edition 2021 corpusgen.rs" }
if ($Rar -and -not (Test-Path $Rar)) { throw "no rar at $Rar" }
New-Item -ItemType Directory -Force "$Root\payload" | Out-Null

function Gen($path, $bytes) {
  if ((Test-Path $path) -and ((Get-Item $path).Length -eq $bytes)) { return }
  & $Corpusgen rand $path $bytes
}
function CreateSet($dir, $name, $slice, $pct, $glob) {
  # `@(...)` is load-bearing: a glob that matches ONE file yields a bare
  # string, splatting it passes no member list, and turbo then says "You must
  # specify a list of files when creating" - which reads like an argument
  # mistake and is a PowerShell typing one. It cost the first i5 run its
  # single-member rows (5, 8 and 10).
  $files = @(Get-ChildItem "$dir\$glob" | ForEach-Object { $_.FullName })
  if ($files.Count -eq 0) { throw "no members matching $glob in $dir" }
  $argv = @("c", "-q", "-s$slice", "-r$pct", "-B$dir", "$dir\$name") + $files
  & $Par2 @argv | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "par2 create failed in $dir ($LASTEXITCODE)" }
}
# rar volumes, or the split fallback under the same names and sizes.
function Volumes($payload, $out, $stem, $vsizeMiB) {
  New-Item -ItemType Directory -Force $out | Out-Null
  if ($Rar) {
    Push-Location (Split-Path -Parent $payload)
    & $Rar a -idq -ep -m0 -tsm- -tsc- -tsa- "-v${vsizeMiB}m" "$out\$stem.rar" (Split-Path -Leaf $payload) | Out-Null
    Pop-Location
    return
  }
  $n = $vsizeMiB * 1MB
  $src = [System.IO.File]::OpenRead($payload)
  $buf = New-Object byte[] $n
  $i = 0
  while (($read = $src.Read($buf, 0, $n)) -gt 0) {
    $i++
    $dst = [System.IO.File]::Create(("{0}\{1}.part{2:d2}.rar" -f $out, $stem, $i))
    $dst.Write($buf, 0, $read); $dst.Close()
  }
  $src.Close()
  Write-Host "   $i split member(s), no rar on this box"
}
function Want($row) { return -not ($Skip -contains $row) }

# Row 1: a TV episode. 1.5 GiB in 21 volumes, 10% at 1 MiB.
if ((Want "row1") -and -not (Test-Path "$Root\tv")) {
  Write-Host "== row 1: TV episode, 1.5 GiB / 21 volumes"
  Gen "$Root\payload\tv.bin" (1536MB)
  Volumes "$Root\payload\tv.bin" "$Root\tv" "episode" 75
  CreateSet "$Root\tv" "episode.par2" 1048576 10 "*.rar"
}
# Rows 2, 3, 4 and 6: one 10 GiB fixture, four damage shapes over it.
if ((Want "row2") -and -not (Test-Path "$Root\movie")) {
  Write-Host "== rows 2-4, 6: movie, 10 GiB / 21 volumes"
  Gen "$Root\payload\movie.bin" (10240MB)
  Volumes "$Root\payload\movie.bin" "$Root\movie" "feature" 500
  CreateSet "$Root\movie" "feature.par2" 1048576 10 "*.rar"
}
# Row 5: the pars ARE the download, at 100% and 110%.
# The multi shape is ~40 GB of recovery on top of the movie and is the first
# thing to -Skip on a box that is short of disk.
foreach ($pct in 100, 110) {
  if ((Want "row5s") -and -not (Test-Path "$Root\pars-single-$pct")) {
    Write-Host "== row 5: pars-only single member, $pct%"
    Gen "$Root\payload\feature.mkv" (1024MB)
    New-Item -ItemType Directory -Force "$Root\pars-single-$pct" | Out-Null
    Copy-Item "$Root\payload\feature.mkv" "$Root\pars-single-$pct\"
    CreateSet "$Root\pars-single-$pct" "feature.par2" 1048576 $pct "feature.mkv"
  }
}
foreach ($pct in 100, 110) {
  if ((Want "row5m") -and -not (Test-Path "$Root\pars-multi-$pct")) {
    Write-Host "== row 5: pars-only 21 members, $pct% (slow: 10k x 10k rows)"
    New-Item -ItemType Directory -Force "$Root\pars-multi-$pct" | Out-Null
    Copy-Item "$Root\movie\*.rar" "$Root\pars-multi-$pct\"
    CreateSet "$Root\pars-multi-$pct" "feature.par2" 1048576 $pct "*.rar"
  }
}
# Row 7: the poster's side. 10 x 1 GiB members; creating IS the leg.
if ((Want "row7") -and -not (Test-Path "$Root\create")) {
  Write-Host "== row 7: create corpus, 10 x 1 GiB"
  New-Item -ItemType Directory -Force "$Root\create" | Out-Null
  foreach ($i in 1..10) { Gen ("{0}\create\part{1:d2}.bin" -f $Root, $i) (1024MB) }
}
# Row 8: an album. One 600 MiB RAR, 5% at 512 KiB.
if ((Want "row8") -and -not (Test-Path "$Root\album")) {
  Write-Host "== row 8: album, 600 MiB single RAR"
  Gen "$Root\payload\album.bin" (600MB)
  New-Item -ItemType Directory -Force "$Root\album" | Out-Null
  if ($Rar) {
    Push-Location "$Root\payload"
    & $Rar a -idq -ep -m0 -tsm- -tsc- -tsa- "$Root\album\album.rar" "album.bin" | Out-Null
    Pop-Location
  } else { Copy-Item "$Root\payload\album.bin" "$Root\album\album.rar" }
  CreateSet "$Root\album" "album.par2" 524288 5 "album.rar"
}
# Row 9: the heavy leg, 1 GiB in 21 volumes at 64 KiB blocks.
if ((Want "row9") -and -not (Test-Path "$Root\heavy")) {
  Write-Host "== row 9: heavy, 1 GiB / 21 volumes at 64 KiB"
  Gen "$Root\payload\rand.bin" (1024MB)
  Volumes "$Root\payload\rand.bin" "$Root\heavy" "set" 50
  CreateSet "$Root\heavy" "heavy.par2" 65536 10 "*.rar"
}
# Row 10: a sports broadcast. One obfuscated mp4 under a 32-character random
# name, NO RAR, and a release-named 2% set with par2cmdline's .vol-NN naming -
# 2,000 data blocks of 1,202,100 bytes, the geometry of the 6 Sep sample.
$obf = "8f3c1a90d47b62e5c0193ae7bd48f215"
$rel = "Motorsport.2026.Round12.UNCUT.HDTV.H264-RIG"
if ((Want "row10") -and -not (Test-Path "$Root\sports")) {
  Write-Host "== row 10: sports broadcast, one obfuscated 2.4 GB mp4"
  New-Item -ItemType Directory -Force "$Root\sports" | Out-Null
  Gen "$Root\sports\$obf.mp4" (2000 * 1202100)
  CreateSet "$Root\sports" "$rel.par2" 1202100 2 "$obf.mp4"
  $n = 0
  Get-ChildItem "$Root\sports\$rel.vol*.par2" | Sort-Object Name | ForEach-Object {
    Rename-Item $_.FullName ("{0}.vol-{1:d2}.par2" -f $rel, $n); $n++
  }
  Write-Host "   $n volume(s) renamed to .vol-NN.par2"
}

# The pristine references every repair is gated against.
Write-Host "== sha references"
function Sha($dir, $glob, $out) {
  if (-not (Test-Path $dir)) { return }
  Get-ChildItem "$dir\$glob" | ForEach-Object {
    "{0}  ./{1}" -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower(), $_.Name
  } | Set-Content -Encoding ascii $out
}
Sha "$Root\tv" "*.rar" "$Root\tv.sha"
Sha "$Root\movie" "*.rar" "$Root\movie.sha"
Sha "$Root\album" "*.rar" "$Root\album.sha"
Sha "$Root\heavy" "*.rar" "$Root\heavy.sha"
Sha "$Root\sports" "*.mp4" "$Root\sports.sha"
Sha "$Root\pars-single-100" "*.mkv" "$Root\pars-single.sha"
Sha "$Root\pars-multi-100" "*.rar" "$Root\pars-multi.sha"

if ($KeepDamaged) {
  Write-Host "== damage (standing copies; NTFS pays a full copy each)"
  $maps = @{
    "row1-tv-2articles"      = @("tv", "amap-row1-tv.txt", 1048576)
    "row2-movie-12articles"  = @("movie", "amap-row2-movie.txt", 1048576)
    "row3-movie-gap"         = @("movie", "amap-row3-movie-gap.txt", 1048576)
    "row3-movie-volgone"     = @("movie", "amap-row3-movie-most.txt", 1048576)
    "row4-movie-deleted"     = @("movie", "amap-row4-movie.txt", 1048576)
    "row8-album-1article"    = @("album", "amap-row8-album.txt", 524288)
    "row9-heavy-1500blocks"  = @("heavy", "map-heavy-1500.txt", 65536)
    "row10-sports-1article"  = @("sports", "amap-row10-sports.txt", 1202100)
  }
  foreach ($dst in $maps.Keys) {
    $src, $map, $bs = $maps[$dst]
    if (Test-Path "$Root\$src") {
      # round2.ps1 carries the PowerShell twin of apply-damage.py; this box
      # has no Python, so a standing damaged tree is cut by round2.ps1's
      # SApplyDamage rather than by the .py.
      Write-Host "   $dst : run round2.ps1 -Leg <row> instead; standing copies need the .py"
    }
  }
} else {
  Write-Host "== damage SKIPPED (round2.ps1 cuts each row's map into its work copy)"
}
Write-Host "== done"
Get-ChildItem $Root -Directory | ForEach-Object {
  $mb = [math]::Round((Get-ChildItem $_.FullName -File | Measure-Object Length -Sum).Sum / 1MB)
  "{0,-22} {1,8} MB" -f $_.Name, $mb
}
