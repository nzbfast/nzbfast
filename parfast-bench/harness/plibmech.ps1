#!/usr/bin/env pwsh
#
# plibmech.ps1 - does the Get-ForeignCpu sampling defect's MECHANISM actually
# fire on this box?
#
#     powershell -NoProfile -ExecutionPolicy Bypass -File plibmech.ps1
#
# WHY THIS EXISTS. an internal note recorded
# `Get-ForeignCpu` reading 25-544% of a core on an IDLE intel-i5-10600kf (i5-10600KF,
# 6c/12t) against a 40 s per-process truth of 14.6%, and the fix that landed as
# 9686ac296 is built on the mechanism behind it: a pid present in the AFTER
# snapshot but absent from the BEFORE one had its whole lifetime CPU charged to
# that one second. The fix is correct arithmetic regardless. But a REading is
# not a mechanism, and on the two 16-core boxes that were free on 16 Sep the
# mechanism does not fire at all - windows-gaming-pc-b and amd-ryzen-9800x3d both measured ZERO absent
# pids across ten samples, with old and new arithmetic agreeing to 0.8%. So the
# quantity to measure on a box that is suspected of it is not the reading, it
# is the mechanism, and that is what this prints.
#
# WHAT IT PRINTS, per one second sample: the process count, how many pids are
# in the after snapshot but not the before one, and that number split three
# ways by what the pid's start time says -
#
#   born    started INSIDE the window. Its lifetime CPU genuinely was spent in
#           there, so charging it in full is CORRECT and is what the fix still
#           does. A high `born` count with a low charge is harmless churn.
#   stale   was alive BEFORE the window opened, so we simply failed to read it
#           in the first enumeration. THIS IS THE DEFECT. Its whole lifetime -
#           possibly hours - was charged to one second by the old code.
#   unknown its start time could not be read (a protected process). Treated as
#           stale by the fix, which is the conservative direction.
#
# and then the core-seconds the OLD code charged for all of them, and how much
# of that was the `stale` + `unknown` classes. THAT LAST COLUMN IS THE DEFECT,
# IN CORE-SECONDS, ON THIS BOX. A box where it is 0.00 across every sample does
# not exhibit the defect and its banked `foreign_cpu` readings were not inflated
# by it. The named processes are printed so a non-zero reading can be chased
# rather than guessed at: `!` marks a stale pid, `?` an unknown one.
#
# READ-ONLY AND CHEAP. It starts nothing, kills nothing, takes no rig lock and
# writes no file; it costs about 15 seconds of one thread. It is still CPU on a
# shared box, so post on the box's COORDINATION file first like anything else -
# and note that a round in flight will see THIS script in its own foreign_cpu.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'plib.ps1')
$mine = Get-OwnPidTree
$snap = {
  $h = @{}
  foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    if ($mine.Contains($p.Id)) { continue }
    $c = $null
    try { $c = $p.TotalProcessorTime.TotalSeconds } catch { $c = $null }
    if ($null -eq $c) { continue }
    $st = $null
    try { $st = $p.StartTime } catch { $st = $null }
    $h[$p.Id] = [pscustomobject]@{ Cpu = [double]$c; Start = $st; Name = $p.ProcessName }
  }
  return ,$h
}
"box=$env:COMPUTERNAME cores=$env:NUMBER_OF_PROCESSORS ts=$((Get-Date).ToUniversalTime().ToString('o'))"
"sample  procs  absent  born  stale  unknown   OLD_charged(core-s)   THE_DEFECT(core-s)  who"
for ($i = 0; $i -lt 10; $i++) {
  $t0 = Get-Date
  $a = & $snap
  Start-Sleep -Milliseconds 1000
  $b = & $snap
  $absent = 0; $born = 0; $stale = 0; $unk = 0; $ch = 0.0; $bad = 0.0
  $names = @()
  foreach ($k in $b.Keys) {
    if ($a.ContainsKey($k)) { continue }
    $absent++
    $ch += $b[$k].Cpu
    if ($null -eq $b[$k].Start)      { $unk++;   $bad += $b[$k].Cpu; $names += ($b[$k].Name + '?') }
    elseif ($b[$k].Start -ge $t0)    { $born++ }
    else                             { $stale++; $bad += $b[$k].Cpu; $names += ($b[$k].Name + '!') }
  }
  "{0,6}  {1,5}  {2,6}  {3,4}  {4,5}  {5,7}  {6,19:N2}  {7,19:N2}  {8}" -f `
    ($i+1), $b.Count, $absent, $born, $stale, $unk, $ch, $bad, ($names -join ' ')
  Start-Sleep -Milliseconds 400
}
