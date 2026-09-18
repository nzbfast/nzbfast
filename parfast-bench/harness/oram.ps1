param(
  [string]$Root = (Join-Path $env:USERPROFILE 'oram-15sep'),  # holds src\, fix\, logs\, harness\
  [string]$Tag = 'oram1',
  [string]$Bin = '',                             # default $Root\src\target\release\parfast.exe
  [int]$Reps = 3,
  [string]$Sizes = '12,45',                      # GiB; one under RAM, one ~1.4x RAM on a 32 GB box
  [string]$Pcts = '5,15',
  [string]$Arms = 'main,nopre,nomap',
  [string]$Par2 = '',                            # par2cmdline for the oracle verify, optional
  [string]$AfterLog = '',                        # a predecessor round's log to wait out; '' waits for nothing
  [string]$AfterPattern = '',                    # the line in that log that means it ended
  [string]$AfterScript = '',                     # its runner's script name, so a dead runner also counts as ended
  [int]$WaitHours = 14,
  [switch]$NoBuild
)
# oram.ps1 - the over-RAM single-file create knee on a WINDOWS box (TODO 345,
# an internal note).
#
# KEEP THIS FILE PURE ASCII: PowerShell 5.1 reads a BOM-less script as ANSI.
#
# One file per size, cut at 32,768 slices (-b32768), 5% and 15% recovery,
# the reporter's shape. Three arms of ONE binary, so the arms differ by the
# environment and nothing else:
#   main   nothing set
#   nopre  NZBFAST_PAR2GEN_MAP_PREFETCH=0 (skip the whole-mapping prefetch)
#   nomap  NZBFAST_PAR2GEN_MAP=0 (no mapping: the transform reads bounded
#          copied windows, stripe-first stands down)
# Every leg carries NZBFAST_REPAIR_TIMING=1 and its timing lines are copied
# into the round log. Order is mirrored rep to rep. Before every leg the
# member is read end to end (Read-Warm), so each leg starts from the same
# cache state: all of a file under RAM resident, the tail of one above it.
#
# Per leg, besides plib's wall / cpu / peak working set / foreign CPU:
# load before and after, AvailableMBytes before and after, and the deltas
# of two cumulative kernel counters - Memory\Page Reads (hard-fault read
# operations) and PhysicalDisk(_Total)\Disk Read Bytes - which separate
# "the leg paid hard faults" from "the leg read the disk" (hypothesis 1).
# The recovery set is hashed (per-file SHA-256, then a digest over the
# sorted list), so every arm and rep of one shape must print one digest.
#
# It WAITS for the box before taking the rig lock: first for the
# predecessor chain named by -AfterLog/-AfterPattern (or that script's
# process being gone), then for no HELD lock and no parfast twice a minute
# apart (wcombq's rule). A lost race for the lock goes back to waiting instead
# of exiting 17, so a round queued behind this one and this one cannot lose a
# round to each other. Launch detached (Win32_Process::Create), never
# Start-Process over ssh - wlaunch.ps1's header says why.
#
# THAT "INSTEAD OF EXITING 17" IS WHY IT CALLS Try-TakeRigLock AND NOT
# Take-RigLock. Take-RigLock ends the PROCESS on a busy box, which is right for
# a round that gives up and wrong for one that queues; so until 16 Sep 2026
# this script hand-rolled its own CreateNew open instead, and inherited the
# defect that costs the whole family its box: no orphan arm at all, plus a
# Test-Path busy test. An ORPHANED lock naming a dead pid therefore did the
# worst possible thing here - Test-BoxBusy read it as busy forever and the wait
# loop exited 19 at -WaitHours on a box that was free
# (an internal note). plib's
# Try-TakeRigLock is the same take without the exit: it clears a lock it can
# PROVE is nobody's, says so on stdout and on the coordination file, and
# reports refusal in $script:riglock_taken so this loop can go round again.
. (Join-Path $PSScriptRoot 'plib.ps1')

$src = Join-Path $Root 'src'
if (-not $Bin) { $Bin = Join-Path $src 'target\release\parfast.exe' }
$fix = Join-Path $Root 'fix'
$logs = Join-Path $Root "logs\$Tag"
$lock = Get-RigLockPath
$sizelist = @($Sizes.Split(',') | ForEach-Object { [int]$_ })
$pctlist = @($Pcts.Split(',') | ForEach-Object { [int]$_ })
$armlist = @($Arms.Split(','))

Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }

function Ts { (Get-Date).ToUniversalTime().ToString('o') }
# Test-RigLockHeld, never Test-Path: liveness comes from the HOLDER. The
# parfast arm stays - a lock only excludes rounds that agreed to take one, and
# a round that took none is still load.
function Test-BoxBusy { (Test-RigLockHeld) -or [bool](Get-Process parfast -ErrorAction SilentlyContinue) }
function Test-AfterDone {
  if (-not $AfterLog) { return $true }
  if (Select-String -Path $AfterLog -Pattern $AfterPattern -Quiet -ErrorAction SilentlyContinue) { return $true }
  $alive = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
             Where-Object { $_.CommandLine -match $AfterScript })
  return ($alive.Count -eq 0)
}

function Get-LoadPct {
  $v = -1
  try { $v = [int]((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average) } catch { }
  return $v
}

# Cumulative counters into $script: variables; emits nothing (plib's note on
# PowerShell returning every emitted line applies).
function Get-IoRaw {
  $script:io_pr = -1; $script:io_pi = -1; $script:io_dr = -1; $script:io_av = -1
  try {
    $mem = Get-CimInstance Win32_PerfRawData_PerfOS_Memory
    $dsk = Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
    $script:io_pr = [int64]$mem.PageReadsPersec
    $script:io_pi = [int64]$mem.PagesInputPersec
    $script:io_dr = [int64]$dsk.DiskReadBytesPersec
    $script:io_av = [int64]$mem.AvailableMBytes
  } catch { }
}
function Get-Delta32([int64]$a, [int64]$b) {
  if ($a -lt 0 -or $b -lt 0) { return -1 }
  $d = $b - $a
  if ($d -lt 0) { $d += 4294967296 }
  return $d
}

function Invoke-Warm([string]$name) { Read-Warm $fix @($name) }

# ---- wait for the box ----
New-Item -ItemType Directory -Force $logs, $fix | Out-Null
"ORAM-WAIT-START tag=$Tag after=$AfterLog pattern=[$AfterPattern] $(Ts)"
$until = (Get-Date).AddHours($WaitHours)
while (-not (Test-AfterDone)) {
  if ((Get-Date) -gt $until) { "ORAM-FAIL predecessor never finished $(Ts)"; exit 19 }
  Start-Sleep 60
}
"ORAM-AFTER-DONE $(Ts)"
$got = $false
while (-not $got) {
  while ($true) {
    if (-not (Test-BoxBusy)) { Start-Sleep 60; if (-not (Test-BoxBusy)) { break } }
    if ((Get-Date) -gt $until) { "ORAM-FAIL box never came free $(Ts)"; exit 19 }
    Start-Sleep 60
  }
  Try-TakeRigLock $Tag
  if ($script:riglock_taken) { $got = $true }
  else {
    "ORAM-LOCK-RACE lost at $(Ts), waiting again"
    Start-Sleep 60
  }
}

try {
  "ROUND tag=$Tag root=$Root bin=$Bin reps=$Reps sizes=$Sizes pcts=$Pcts arms=$Arms start=$(Ts)"
  Write-BoxFacts
  Write-HarnessFacts @($PSCommandPath, (Join-Path $PSScriptRoot 'plib.ps1'))

  if (-not $NoBuild) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
    $bw = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $src
    cmd /c "cargo build --release -p parfast --locked > `"$Root\build-$Tag.log`" 2>&1"
    $brc = $LASTEXITCODE
    Pop-Location
    "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-$Tag.log"
    if ($brc -ne 0) { "ORAM-FAIL build"; exit 9 }
  }
  Write-BinFacts (Split-Path $Bin -Parent) @([IO.Path]::GetFileNameWithoutExtension($Bin))

  # ---- fixtures: random bytes, written once, kept across rounds ----
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $buf = New-Object byte[] (8MB)
  foreach ($gib in $sizelist) {
    $fname = Join-Path $fix ("f{0}g.bin" -f $gib)
    $want = [int64]$gib * 1073741824
    if ((Test-Path $fname) -and ((Get-Item $fname).Length -eq $want)) { "FIXTURE-KEPT $fname bytes=$want"; continue }
    $fw = [Diagnostics.Stopwatch]::StartNew()
    $fs = [IO.File]::Create($fname)
    $left = $want
    while ($left -gt 0) {
      $rng.GetBytes($buf)
      $take = [int][math]::Min([int64]$buf.Length, $left)
      $fs.Write($buf, 0, $take)
      $left -= $take
    }
    $fs.Close()
    "FIXTURE-WROTE $fname bytes=$want secs=$([math]::Round($fw.Elapsed.TotalSeconds,1))"
  }

  $digests = @{}
  function Run-Leg([int]$gib, [int]$pcent, [string]$arm, [int]$rep) {
    $name = "f{0}g.bin" -f $gib
    $legtag = "g$gib-r$pcent-$arm-rep$rep"
    $logbase = Join-Path $logs $legtag
    Get-ChildItem $fix -Filter 'k*.par2' -ErrorAction SilentlyContinue | Remove-Item -Force
    $ww = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Warm $name
    $warm = [math]::Round($ww.Elapsed.TotalSeconds, 1)
    $envx = @{ 'NZBFAST_REPAIR_TIMING' = '1' }
    if ($arm -eq 'nopre') { $envx['NZBFAST_PAR2GEN_MAP_PREFETCH'] = '0' }
    elseif ($arm -eq 'nomap') { $envx['NZBFAST_PAR2GEN_MAP'] = '0' }
    elseif ($arm -ne 'main') { "ORAM-FAIL unknown arm $arm"; exit 9 }
    $load0 = Get-LoadPct
    Get-IoRaw
    $pr0 = $script:io_pr; $pi0 = $script:io_pi; $dr0 = $script:io_dr; $av0 = $script:io_av
    $out = @(Invoke-Leg $Bin "c -q -b32768 -r$pcent k.par2 $name" $fix $logbase $envx)
    Get-IoRaw
    $load1 = Get-LoadPct
    $res = $out | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    $out | Where-Object { $_ -is [string] }
    $pars = @(Get-ChildItem $fix -Filter 'k*.par2' | Sort-Object Name)
    $sums = foreach ($f in $pars) { "$($f.Name):$(Get-Sha256Fast $f.FullName)" }
    $hasher = [Security.Cryptography.SHA256]::Create()
    $setsha = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::ASCII.GetBytes(($sums -join "`n")))).Replace('-', '').Substring(0, 16)
    $parbytes = [int64](($pars | Measure-Object Length -Sum).Sum)
    $key = "g$gib-r$pcent"
    if (-not $digests.ContainsKey($key)) { $digests[$key] = @() }
    $digests[$key] += $setsha
    $pagereads = Get-Delta32 $pr0 $script:io_pr
    $pagesin = Get-Delta32 $pi0 $script:io_pi
    $diskgb = if ($dr0 -ge 0 -and $script:io_dr -ge 0) { [math]::Round(($script:io_dr - $dr0) / 1GB, 2) } else { -1 }
    "LEG round=$Tag gib=$gib pct=$pcent arm=$arm rep=$rep rc=$($res.rc) wall=$($res.wall) cpu=$($res.cpu) peak_mb=$($res.peakmb) gbps=$([math]::Round($gib * 1.073741824 / [math]::Max($res.wall, 0.001), 3)) set=$setsha parfiles=$($pars.Count) parbytes=$parbytes warm_s=$warm page_reads=$pagereads pages_in=$pagesin disk_read_gb=$diskgb avail_mb_before=$av0 avail_mb_after=$($script:io_av) load_before=$load0 load_after=$load1 foreign_cpu=$($res.foreign) foreign_after=$($res.foreignAfter) errlen=$($res.errlen) rig=$(Get-RigStamp) ts=$(Ts)"
    $esc = [string][char]27
    if (Test-Path "$logbase.err") {
      foreach ($ln in (Get-Content "$logbase.err" | Select-Object -First 60)) {
        $clean = ($ln -replace ($esc + '\[[0-9;]*m'), '').Trim()
        if ($clean) { "TIMING leg=$legtag $clean" }
      }
    }
    if ($res.rc -ne 0) { "ORAM-FAIL leg rc=$($res.rc) $legtag"; exit 9 }
    if ($rep -eq 1 -and $arm -eq $armlist[0]) {
      $v = @(Invoke-Leg $Bin "v -q k.par2" $fix "$logbase-verify" @{})
      $vr = $v | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
      "VERIFY tool=parfast leg=$legtag rc=$($vr.rc) wall=$($vr.wall)"
      if ($Par2 -and (Test-Path $Par2)) {
        $o = @(Invoke-Leg $Par2 "v -q k.par2" $fix "$logbase-par2" @{})
        $orr = $o | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
        "VERIFY tool=par2cmdline bin=$Par2 leg=$legtag rc=$($orr.rc) wall=$($orr.wall)"
      }
    }
    Get-ChildItem $fix -Filter 'k*.par2' -ErrorAction SilentlyContinue | Remove-Item -Force
  }

  $cells = @()
  foreach ($gib in $sizelist) { foreach ($pcent in $pctlist) { foreach ($arm in $armlist) { $cells += , @($gib, $pcent, $arm) } } }
  for ($rep = 1; $rep -le $Reps; $rep++) {
    $order = if ($rep % 2 -eq 1) { $cells } else { $cells[($cells.Count - 1)..0] }
    foreach ($c in $order) { Run-Leg $c[0] $c[1] $c[2] $rep }
  }
  foreach ($k in ($digests.Keys | Sort-Object)) {
    $u = @($digests[$k] | Select-Object -Unique)
    "SET-IDENTITY shape=$k legs=$($digests[$k].Count) distinct=$($u.Count) digests=$($u -join '/')"
  }
  "ALL DONE end=$(Ts)"
} finally {
  Release-RigLock $lock
}
