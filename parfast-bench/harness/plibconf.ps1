#!/usr/bin/env pwsh
#
# plibconf.ps1 - the END-TO-END CONFIRMATION run for the Get-ForeignCpu
# sampling defect, as ONE command that prints everything at the end.
#
#     powershell -NoProfile -ExecutionPolicy Bypass -File plibconf.ps1
#
# WHY IT IS ONE SCRIPT AND NOT THREE. Watching a Windows box over ssh is
# MEASURED CONTAMINATION of exactly the quantity being measured here: a
# PowerShell started under SSHD is outside the round's pid tree by
# construction and costs about a core-second of module autoload, and on a
# 16-core box that moved a neighbour's foreign_cpu from a median of 43.8
# undisturbed to 253.1 under an ssh poll
# (an internal note section 3). So the
# confirmation is not three interactive steps with a human between them. It is
# one process, started once, that prints at the end.
#
# WHAT IT RUNS, in order, and why each part is owed:
#
#   1. plibmech.ps1 UNCHANGED, the banked mechanism instrument. A READING is
#      not a MECHANISM and only the mechanism can be chased. Its THE_DEFECT
#      column is the answer this whole item turns on: non-zero and named means
#      the defect is real on this box and says which processes cause it; zero
#      across all ten samples means the 25-544% readings banked here have some
#      other cause, which is the larger finding.
#   2. A PAIRED old-versus-new A/B, both readings computed from the SAME two
#      snapshots so the only variable is the arithmetic. Anything else
#      compares two different seconds of a box's life and cannot separate the
#      fix from the weather. The OLD arithmetic is reproduced here verbatim -
#      absent pid charged its whole lifetime, divided by an ASSUMED 1.000 s -
#      beside Measure-ForeignDelta from the live plib.ps1.
#   3. The largest single contributors to each OLD reading, named. This is the
#      next step the handoff asks for if (1) comes back zero, and it costs
#      nothing to collect in the same pass, so it is collected unconditionally
#      rather than left for a second visit to a box that is hard to get.
#   4. A 40 s per-process attribution, the TRUTH the 1 s readings are judged
#      against. Only pids present in BOTH snapshots are summed; pids born
#      inside the 40 s are reported separately rather than folded in, because
#      folding them in is the very defect under test.
#
# It also re-states the ten NEW readings as min/median/max, which is the
# Windows quiet floor Require-QuietCore's header quotes. Note that on amd-ryzen-9800x3d
# those figures did NOT move after the fix and must not be re-labelled - that
# box's reading is real resident load. Whether this box's move is the open
# question this run exists to settle.
#
# READ-ONLY AND CHEAP. It starts no leg, takes no rig lock, kills nothing and
# writes no file. It costs about two minutes of one thread. It is still CPU on
# a shared box: post on the box's COORDINATION file first, and do NOT run it
# while somebody's QUIET-BOX round holds the box, because this script's own
# foreign CPU lands in precisely the legs such a round exists to measure.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'plib.ps1')

$cores = [int]$env:NUMBER_OF_PROCESSORS
if ($cores -lt 1) { $cores = [Environment]::ProcessorCount }
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
function Median([double[]]$v) {
  if ($v.Count -eq 0) { return 0.0 }
  $s = $v | Sort-Object
  $n = $s.Count
  if ($n % 2 -eq 1) { return [double]$s[[int](($n - 1) / 2)] }
  return [math]::Round((([double]$s[$n/2 - 1] + [double]$s[$n/2]) / 2.0), 1)
}

"=========================================================================="
"plibconf.ps1  box=$env:COMPUTERNAME cores=$cores ts=$((Get-Date).ToUniversalTime().ToString('o'))"
"plib.ps1 sha256=$((Get-FileHash (Join-Path $PSScriptRoot 'plib.ps1') -Algorithm SHA256).Hash)"
"=========================================================================="
""
"--- PART 1: the MECHANISM (plibmech.ps1, unchanged) ----------------------"
& (Join-Path $PSScriptRoot 'plibmech.ps1')
""
"--- PART 2: PAIRED old-vs-new, same two snapshots ------------------------"
"sample  procs  window_s     OLD     NEW   absent   top contributors to OLD"
$olds = New-Object 'System.Collections.Generic.List[double]'
$news = New-Object 'System.Collections.Generic.List[double]'
for ($i = 0; $i -lt 10; $i++) {
  $t0 = Get-Date
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $a = & $snap
  Start-Sleep -Milliseconds 1000
  $windowS = $sw.Elapsed.TotalSeconds
  $b = & $snap
  $sw.Stop()

  # THE OLD ARITHMETIC, VERBATIM: absent pid charged its whole lifetime CPU,
  # sum divided by an ASSUMED 1.000 s rather than the span actually measured.
  $od = 0.0
  $absent = 0
  $contrib = @()
  foreach ($k in $b.Keys) {
    $was = 0.0
    if ($a.ContainsKey($k)) { $was = [double]$a[$k].Cpu } else { $absent++ }
    $d = [double]$b[$k].Cpu - $was
    if ($d -gt 0) {
      $od += $d
      $contrib += [pscustomobject]@{ Name = $b[$k].Name; Pid = $k; D = $d; New = (-not $a.ContainsKey($k)) }
    }
  }
  $old = [math]::Round(($od / 1.0) * 100.0, 1)
  $new = Measure-ForeignDelta $a $b $windowS $t0 $cores
  $olds.Add([double]$old); $news.Add([double]$new)
  $top = ($contrib | Sort-Object -Property D -Descending | Select-Object -First 4 |
          ForEach-Object { "{0}/{1}={2:N2}{3}" -f $_.Name, $_.Pid, $_.D, $(if ($_.New) { '*' } else { '' }) }) -join ' '
  "{0,6}  {1,5}  {2,8:N3}  {3,6}  {4,6}   {5,6}   {6}" -f ($i+1), $b.Count, $windowS, $old, $new, $absent, $top
  Start-Sleep -Milliseconds 400
}
"  (* marks a pid ABSENT from the before snapshot, i.e. charged its whole life by the old code)"
""
"OLD  min {0}  median {1}  max {2}" -f ($olds | Measure-Object -Minimum).Minimum, (Median $olds.ToArray()), ($olds | Measure-Object -Maximum).Maximum
"NEW  min {0}  median {1}  max {2}" -f ($news | Measure-Object -Minimum).Minimum, (Median $news.ToArray()), ($news | Measure-Object -Maximum).Maximum
"  (the NEW row is the Windows quiet floor Require-QuietCore's header quotes, re-measured through the fixed sampler)"
""
"--- PART 3: 40 s per-process TRUTH ---------------------------------------"
$t0 = Get-Date
$sw = [Diagnostics.Stopwatch]::StartNew()
$a = & $snap
Start-Sleep -Seconds 40
$span = $sw.Elapsed.TotalSeconds
$b = & $snap
$sw.Stop()
$tot = 0.0
$rows = @()
$bornCpu = 0.0
$bornN = 0
foreach ($k in $b.Keys) {
  if ($a.ContainsKey($k) -and ($null -eq $a[$k].Start -or $null -eq $b[$k].Start -or $a[$k].Start -eq $b[$k].Start)) {
    $d = [double]$b[$k].Cpu - [double]$a[$k].Cpu
    if ($d -gt 0) { $tot += $d; $rows += [pscustomobject]@{ Name = $b[$k].Name; Pid = $k; Pct = ($d / $span) * 100.0 } }
  } else {
    # Born (or pid-reused) inside the 40 s. Reported SEPARATELY and never folded
    # into the truth: folding it in is the defect this whole item is about.
    $bornN++; $bornCpu += [double]$b[$k].Cpu
  }
}
"window {0:N2} s   procs_before {1}  procs_after {2}" -f $span, $a.Count, $b.Count
"TRUTH (pids in BOTH snapshots): {0:N1}% of one core" -f (($tot / $span) * 100.0)
"born inside the window: {0} process(es), {1:N2} core-s of lifetime CPU NOT counted above" -f $bornN, $bornCpu
"top attributors:"
$rows | Sort-Object -Property Pct -Descending | Select-Object -First 12 |
  ForEach-Object { "    {0,-28} pid {1,-8} {2,6:N1}% of one core" -f $_.Name, $_.Pid, $_.Pct }
""
"=== END plibconf.ps1  ts=$((Get-Date).ToUniversalTime().ToString('o')) ==="
