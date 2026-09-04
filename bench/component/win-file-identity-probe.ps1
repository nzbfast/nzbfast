# Windows file-identity probe: can a delete-and-recreate under the same
# name be told apart from the original by metadata alone?
#
# WHY THIS EXISTS. `nzbkit-base`'s headpeek memo keys a file by an
# `Ident`. On unix that carries the inode, so a replaced file is always a
# different key. On Windows there is no stable inode available on stable
# Rust (`MetadataExt::file_index` and `volume_serial_number` are both
# behind the unstable `windows_by_handle` feature), so the key is size +
# last_write_time + creation_time + attributes. That key can ALIAS, and a
# test that assumed it could not went red on a Windows CI shard on
# 3 Sep 2026. This probe measures, on real hardware, exactly how reachable
# the aliasing shape is - so the module's doc comment states a measured
# window rather than an assumed one, and so the number can be
# re-established if it is ever questioned.
#
#   powershell -ExecutionPolicy Bypass -File win-file-identity-probe.ps1
#
# It reports two things:
#
#  1. THE REAL RESOLUTION OF LastWriteTime. 100 ns is FILETIME's UNIT, not
#     its resolution - the stamp comes from the system clock, which is far
#     coarser. Measured by writing one path 200 times and counting
#     distinct stamps.
#  2. HOW OFTEN THE FULL KEY COLLIDES on the delete-and-recreate shape,
#     with all four components compared, 40 trials.
#
# MEASURED 3 Sep 2026, two real Win11 NTFS volumes:
#
#   | part                      | resolution | full key collides |
#   |---------------------------|-----------:|------------------:|
#   | Core Ultra 9 386H, laptop |    7.30 ms |            4 / 40 |
#   | i5-10600KF, desktop       |    1.09 ms |           12 / 40 |
#
# Creation time was preserved 40/40 on BOTH parts for an immediate
# recreate, and at a 1 s delay, and NOT at 16 s - NTFS file tunneling,
# and its documented ~15 s window, confirmed. So the creation-time half
# NEVER separates the two files; what separates them, when anything does,
# is last_write_time.
#
# READ THE TWO COLUMNS TOGETHER. The desktop has the FINER clock and yet
# collides three times as often, because collision is the chance that both
# writes land in one granule - which depends on the granule AND on how
# fast the box completes a write-delete-write. The fast desktop outruns
# its finer clock. So neither number alone is the risk: state the
# resolution as a RANGE (~1-7 ms on the parts measured) and expect a
# faster machine to collide MORE often, not less.
#
# The consequence for anyone re-enabling such a test: a green Windows
# shard was never evidence the assertion held - at 4-12 in 40 it is a
# flaky test that mostly passes, and from a tight Rust loop, with less
# work between the two writes, it will collide more often than from
# PowerShell.
$ErrorActionPreference = "Continue"
$dir = "$env:TEMP\winidentprobe"; if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
New-Item -ItemType Directory $dir | Out-Null
"cpu: $((Get-CimInstance Win32_Processor).Name)"
"volume: $((Get-Item $dir).PSDrive.Name) fs=$((Get-Volume -DriveLetter ((Get-Item $dir).PSDrive.Name)).FileSystemType)"

# (1) Resolution of LastWriteTime, measured rather than assumed.
$p = "$dir\g.bin"; $ts = @()
foreach ($i in 1..200) {
  [System.IO.File]::WriteAllBytes($p, (New-Object byte[] 8))
  $ts += (Get-Item $p).LastWriteTimeUtc.Ticks
}
$d = ($ts | Select-Object -Unique)
$gaps = @(); for ($i = 1; $i -lt $d.Count; $i++) { $gaps += ($d[$i] - $d[$i-1]) }
$med = if ($gaps.Count) { ($gaps | Sort-Object)[[int]($gaps.Count / 2)] } else { 0 }
"resolution: 200 writes -> {0} distinct LastWriteTime values; median gap {1} ticks ({2:N2} ms)" -f $d.Count, $med, ($med / 10000)
Remove-Item -Force $p

# (2) The aliasing shape, all four key components compared.
$tun = 0; $tick = 0; $coll = 0
foreach ($i in 1..40) {
  $q = "$dir\probe.bin"
  [System.IO.File]::WriteAllBytes($q, (New-Object byte[] 8))
  $a = Get-Item $q
  $ac = $a.CreationTimeUtc.Ticks; $aw = $a.LastWriteTimeUtc.Ticks; $aa = [int]$a.Attributes; $al = $a.Length
  [System.IO.File]::Delete($q)
  [System.IO.File]::WriteAllBytes($q, (New-Object byte[] 8))
  $b = Get-Item $q
  if ($ac -eq $b.CreationTimeUtc.Ticks) { $tun++ }
  if ($aw -eq $b.LastWriteTimeUtc.Ticks) { $tick++ }
  if (($ac -eq $b.CreationTimeUtc.Ticks) -and ($aw -eq $b.LastWriteTimeUtc.Ticks) `
      -and ($aa -eq [int]$b.Attributes) -and ($al -eq $b.Length)) { $coll++ }
  [System.IO.File]::Delete($q)
}
"shape x40: creation preserved {0}/40, last_write identical {1}/40, ALL FOUR key components equal {2}/40" -f $tun, $tick, $coll

# (3) The tunneling window itself.
foreach ($delay in @(0, 1000, 16000)) {
  $q = "$dir\t.bin"
  [System.IO.File]::WriteAllBytes($q, (New-Object byte[] 8))
  $ac = (Get-Item $q).CreationTimeUtc.Ticks
  [System.IO.File]::Delete($q)
  if ($delay -gt 0) { Start-Sleep -Milliseconds $delay }
  [System.IO.File]::WriteAllBytes($q, (New-Object byte[] 8))
  "tunneling: delay={0,5}ms creation_preserved={1}" -f $delay, ((Get-Item $q).CreationTimeUtc.Ticks -eq $ac)
  [System.IO.File]::Delete($q)
}
Remove-Item -Recurse -Force $dir
"done"
