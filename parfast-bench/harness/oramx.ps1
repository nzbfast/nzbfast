param(
  [Parameter(Mandatory=$true)][string]$Root,     # holds bin\, fix\, logs\, harness\
  [Parameter(Mandatory=$true)][string]$Tag,
  [Parameter(Mandatory=$true)][string]$Plan,     # cells: gib:pct:arm:avail_gb:mem_mb:reps[:members] ; separated
  [string]$Bin = '',                             # default $Root\bin\parfast.exe
  [string]$Par2 = '',                            # par2cmdline for the oracle verify, optional
  [int]$MaxReps = 3
)
# oramx.ps1 - the over-RAM single-file create knee, on any Windows box, with
# an optional RAM LOCK per cell (TODO 345,
# an internal note).
# KEEP THIS FILE PURE ASCII: PowerShell 5.1 reads a BOM-less script as ANSI.
#
# oram.ps1 is the fixed-shape round that queues itself behind another
# lane's round; this is its generalisation for a box that is free NOW. Each
# cell of -Plan is  gib:pct:arm:avail_gb:mem_mb:reps[:members]
#   gib      the SET's size in GiB (random bytes, written once and kept)
#   pct      recovery percent at -b32768 (the reporter's granularity)
#   arm      main | nopre (NZBFAST_PAR2GEN_MAP_PREFETCH=0) | nomap (NZBFAST_PAR2GEN_MAP=0)
#            | fitoff (NZBFAST_PAR2GEN_MAP_FIT=off: a gated build mapping as before)
#            | nobands (NZBFAST_CREATE_STRIPE_BANDS=0: a band-route build taking the
#              copied windows as before, TODO 345 C)
#   avail_gb 0 = no lock; else ramlock.ps1 pins RAM until AvailableMBytes
#            falls to this, so the FILE CACHE sees a smaller machine
#   mem_mb   0 = parfast's own budget (RAM/4); else -m<mem_mb>. A lock does
#            not change what parfast reads as total RAM, so a locked cell
#            passes the budget the emulated box would derive, and a matching
#            UNLOCKED cell with the same -m separates the budget from the RAM
#   reps     how many of the $MaxReps passes include this cell
#   members  OPTIONAL, default 1: how many files the set is cut into, each
#            gib/members (the last one carries the remainder). A Usenet post
#            is dozens of rar parts and reaches the SAME over-RAM route -
#            `stripe_first::admissible` has no member-count gate and
#            `read_band` walks one (member, offset, want) plan across them -
#            so a one-member round cannot show the per-member TAIL block (the
#            pad arena on the mapped arm, the zero-fill in `read_band` on the
#            band arm) or the head scan across many files. Added 16 Sep 2026
#            for section 3.1 of
#            an internal note. A cell
#            without the field is EXACTLY the old one-member cell, fixture
#            name included, so every plan already in the record still runs.
# Pass r walks the plan forward when r is odd and backward when even
# (mirrored); consecutive cells with the same avail_gb share one lock.
#
# Per leg: plib's wall / cpu / peak working set / foreign CPU, load before and
# after, AvailableMBytes before and after, the deltas of Memory\Page Reads
# (hard-fault read operations), Memory\Pages Input and
# PhysicalDisk(_Total)\Disk Read Bytes, every timing line
# (NZBFAST_REPAIR_TIMING=1), and a digest over the recovery set's per-file
# SHA-256 - every arm, lock and rep of one (gib, pct) must print one digest.
. (Join-Path $PSScriptRoot 'plib.ps1')

if (-not $Bin) { $Bin = Join-Path $Root 'bin\parfast.exe' }
$fix = Join-Path $Root 'fix'
$logs = Join-Path $Root "logs\$Tag"
$lock = Join-Path $env:USERPROFILE '.parfast-rig.lock'
$hogscript = Join-Path $PSScriptRoot 'ramlock.ps1'
Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }

function Ts { (Get-Date).ToUniversalTime().ToString('o') }
function Get-LoadPct {
  $v = -1
  try { $v = [int]((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average) } catch { }
  return $v
}
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
function Get-Route([string]$errfile) {
  # WHICH SIDE OF THE ADMISSION GATE THIS LEG TOOK, as a FIELD on the leg line
  # rather than as free text somewhere in the timing block. An arm here is a
  # claim about a route - `main` on an over-RAM set claims the mapping was
  # refused and bands were admitted - and nothing in this log used to CHECK
  # that claim, so a leg that quietly took the mapped route would be published
  # under the band arm's name and void the round silently. Added 16 Sep 2026
  # with the member knob, after the row-gate lane made the general point: two
  # rounds sit on this one gate from opposite sides and neither driver recorded
  # which side it WANTED.
  #
  # `route=UNPARSED` is deliberately loud and must never be read as "fine". An
  # absence is exactly what a harness reports when the line it was looking for
  # moved, so treat it as a failed READING of the leg, not as a quiet leg.
  $route = 'UNPARSED'; $corpus = -1; $mapgate = 'silent'
  if (Test-Path $errfile) {
    foreach ($ln in (Get-Content $errfile)) {
      if ($ln -match 'create stripe-first admitted:.*bands of up to (\d+) B over copies') {
        $route = 'bands'; $corpus = [int64]$matches[1]
      } elseif ($ln -match 'create stripe-first admitted:') {
        $route = 'mapped'
      } elseif ($ln -match 'create stripe-first refused:') {
        $route = 'refused'
      }
      # Printed ONLY when the payload does not fit, so its absence means the
      # mapping fit OR mapping is off - never that the gate was consulted and
      # said yes. Hence 'silent' rather than 'fits'.
      if ($ln -match 'create map refused:') { $mapgate = 'refused' }
    }
  }
  return @($route, $corpus, $mapgate)
}
function Get-Delta32([int64]$a, [int64]$b) {
  if ($a -lt 0 -or $b -lt 0) { return -1 }
  $d = $b - $a
  if ($d -lt 0) { $d += 4294967296 }
  return $d
}

$script:hog = $null
$script:hogavail = 0
function Stop-Hog {
  if ($script:hog) {
    $stopf = Join-Path $Root 'hog.stop'
    [IO.File]::WriteAllText($stopf, 'stop')
    if (-not $script:hog.WaitForExit(30000)) { Stop-Process -Id $script:hog.Id -Force -ErrorAction SilentlyContinue }
    "HOG-STOPPED pid=$($script:hog.Id) ts=$(Ts)"
    $script:hog = $null
    Start-Sleep 5
  }
  $script:hogavail = 0
}
function Start-Hog([int]$availgb) {
  if ($availgb -eq $script:hogavail) { return }
  Stop-Hog
  if ($availgb -eq 0) { return }
  $ready = Join-Path $Root 'hog.ready'
  $stopf = Join-Path $Root 'hog.stop'
  Remove-Item $ready, $stopf -Force -ErrorAction SilentlyContinue
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = 'powershell.exe'
  $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$hogscript`" -TargetAvailMB $($availgb * 1024) -ReadyFile `"$ready`" -StopFile `"$stopf`" -ParentPid $PID"
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $script:hog = [Diagnostics.Process]::Start($psi)
  $t0 = Get-Date
  while (-not (Test-Path $ready)) {
    if ($script:hog.HasExited) { "ORAMX-FAIL ramlock exited before ready rc=$($script:hog.ExitCode)"; exit 9 }
    if (((Get-Date) - $t0).TotalSeconds -gt 300) { "ORAMX-FAIL ramlock never ready"; exit 9 }
    Start-Sleep 2
  }
  $info = [IO.File]::ReadAllText($ready)
  "HOG pid=$($script:hog.Id) $info ts=$(Ts)"
  if ($info -notmatch 'result=\[ok ') { "ORAMX-FAIL ramlock did not lock"; exit 9 }
  $script:hogavail = $availgb
}

New-Item -ItemType Directory -Force $logs, $fix | Out-Null
Take-RigLock $Tag   # the ROUND's name, not $lock: see plib.ps1's Take-RigLock
try {
  "ROUND tag=$Tag root=$Root bin=$Bin maxreps=$MaxReps plan=$Plan start=$(Ts)"
  Write-BoxFacts
  Write-HarnessFacts @($PSCommandPath, (Join-Path $PSScriptRoot 'plib.ps1'), $hogscript)
  Write-BinFacts (Split-Path $Bin -Parent) @([IO.Path]::GetFileNameWithoutExtension($Bin))
  "BIN sha256=$(Get-Sha256Fast $Bin)"

  $cells = @()
  foreach ($spec in $Plan.Split(';')) {
    $f = $spec.Trim().Split(':')
    if ($f.Count -lt 6 -or $f.Count -gt 7) { "ORAMX-FAIL bad cell [$spec]"; exit 9 }
    if ('main', 'nopre', 'nomap', 'fitoff', 'nobands' -notcontains $f[2]) { "ORAMX-FAIL unknown arm [$spec]"; exit 9 }
    $nmem = if ($f.Count -eq 7) { [int]$f[6] } else { 1 }
    if ($nmem -lt 1) { "ORAMX-FAIL members must be >= 1 [$spec]"; exit 9 }
    $cells += , @([int]$f[0], [int]$f[1], $f[2], [int]$f[3], [int]$f[4], [int]$f[5], $nmem)
  }

  # A shape is (gib, members). One member keeps the historical flat name, so a
  # 45g.bin written by an earlier round is reused rather than rewritten.
  #
  # The SET is exactly gib GiB whatever the member count, so gbps on the leg
  # line stays comparable across shapes. Within it, every member but the last
  # is the same whole number of MiB (rounded UP) and the LAST one is short -
  # which is the shape a rar set actually has, and it matters here: `-b32768`
  # is a block COUNT, so the slice size is derived from the total and no
  # member divides by it, giving the one PARTIAL TAIL BLOCK PER MEMBER that a
  # single-member round cannot show. 60 members of 90 GiB come out exactly
  # equal (1,536 MiB); 60 of 24 GiB are 59 x 410 MiB plus a 386 MiB tail.
  function Get-MemberSpec([int]$gib, [int]$nmem) {
    $want = [int64]$gib * 1073741824
    $per = [int64]([math]::Ceiling($want / $nmem / 1048576)) * 1048576
    if ($nmem -gt 1 -and $per * ($nmem - 1) -ge $want) { "ORAMX-FAIL members=$nmem too many for gib=$gib"; exit 9 }
    $out = @()
    for ($i = 0; $i -lt $nmem; $i++) {
      $nm = if ($nmem -eq 1) { "f{0}g.bin" -f $gib } else { "f{0}g-n{1}-{2:d3}.bin" -f $gib, $nmem, $i }
      $sz = if ($i -eq $nmem - 1) { $want - $per * ($nmem - 1) } else { $per }
      $out += , @($nm, $sz)
    }
    return , $out
  }

  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $buf = New-Object byte[] (8MB)
  foreach ($shape in @($cells | ForEach-Object { "$($_[0]):$($_[6])" } | Select-Object -Unique)) {
    $sp = $shape.Split(':')
    $gib = [int]$sp[0]; $nmem = [int]$sp[1]
    $kept = 0; $wrote = 0; $fw = [Diagnostics.Stopwatch]::StartNew()
    foreach ($m in (Get-MemberSpec $gib $nmem)) {
      $fname = Join-Path $fix $m[0]
      $want = [int64]$m[1]
      if ((Test-Path $fname) -and ((Get-Item $fname).Length -eq $want)) { $kept++; continue }
      $fs = [IO.File]::Create($fname)
      $left = $want
      while ($left -gt 0) {
        $rng.GetBytes($buf)
        $take = [int][math]::Min([int64]$buf.Length, $left)
        $fs.Write($buf, 0, $take)
        $left -= $take
      }
      $fs.Close()
      $wrote++
    }
    "FIXTURE gib=$gib members=$nmem kept=$kept wrote=$wrote bytes=$([int64]$gib * 1073741824) secs=$([math]::Round($fw.Elapsed.TotalSeconds,1))"
  }

  $digests = @{}
  $routes = @{}
  $verified = @{}
  function Run-Leg($c, [int]$rep) {
    $gib = $c[0]; $pcent = $c[1]; $arm = $c[2]; $availgb = $c[3]; $memmb = $c[4]; $nmem = $c[6]
    $names = @((Get-MemberSpec $gib $nmem) | ForEach-Object { $_[0] })
    $legtag = "g$gib-n$nmem-r$pcent-$arm-a$availgb-m$memmb-rep$rep"
    $logbase = Join-Path $logs $legtag
    Get-ChildItem $fix -Filter 'k*.par2' -ErrorAction SilentlyContinue | Remove-Item -Force
    $ww = [Diagnostics.Stopwatch]::StartNew()
    Read-Warm $fix $names
    $warm = [math]::Round($ww.Elapsed.TotalSeconds, 1)
    $envx = @{ 'NZBFAST_REPAIR_TIMING' = '1' }
    if ($arm -eq 'nopre') { $envx['NZBFAST_PAR2GEN_MAP_PREFETCH'] = '0' }
    elseif ($arm -eq 'nomap') { $envx['NZBFAST_PAR2GEN_MAP'] = '0' }
    elseif ($arm -eq 'fitoff') { $envx['NZBFAST_PAR2GEN_MAP_FIT'] = 'off' }
    elseif ($arm -eq 'nobands') { $envx['NZBFAST_CREATE_STRIPE_BANDS'] = '0' }
    $margs = if ($memmb -gt 0) { "-m$memmb " } else { '' }
    $load0 = Get-LoadPct
    Get-IoRaw
    $pr0 = $script:io_pr; $pi0 = $script:io_pi; $dr0 = $script:io_dr; $av0 = $script:io_av
    # Every member is named explicitly: these boxes have no shell glob and
    # parfast does not expand one. 60 names is ~1.2 KB of a 32 KB limit.
    $out = @(Invoke-Leg $Bin "c -q $($margs)-b32768 -r$pcent k.par2 $($names -join ' ')" $fix $logbase $envx)
    Get-IoRaw
    $load1 = Get-LoadPct
    $res = $out | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    $out | Where-Object { $_ -is [string] }
    $pars = @(Get-ChildItem $fix -Filter 'k*.par2' | Sort-Object Name)
    $sums = foreach ($f in $pars) { "$($f.Name):$(Get-Sha256Fast $f.FullName)" }
    $hasher = [Security.Cryptography.SHA256]::Create()
    $setsha = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::ASCII.GetBytes(($sums -join "`n")))).Replace('-', '').Substring(0, 16)
    $parbytes = [int64](($pars | Measure-Object Length -Sum).Sum)
    $rt = Get-Route "$logbase.err"
    $key = "g$gib-n$nmem-r$pcent"
    if (-not $digests.ContainsKey($key)) { $digests[$key] = @() }
    $digests[$key] += $setsha
    # Per shape AND arm, unlike the digest, which is per shape ACROSS arms:
    # the arms are meant to DIFFER here, and what must be constant is that
    # each arm took one route in every rep.
    $rkey = "$key-$arm"
    if (-not $routes.ContainsKey($rkey)) { $routes[$rkey] = @() }
    $routes[$rkey] += $rt[0]
    $pagereads = Get-Delta32 $pr0 $script:io_pr
    $pagesin = Get-Delta32 $pi0 $script:io_pi
    $diskgb = if ($dr0 -ge 0 -and $script:io_dr -ge 0) { [math]::Round(($script:io_dr - $dr0) / 1GB, 2) } else { -1 }
    "LEG round=$Tag gib=$gib members=$nmem pct=$pcent arm=$arm avail_gb=$availgb mem_mb=$memmb rep=$rep rc=$($res.rc) wall=$($res.wall) cpu=$($res.cpu) peak_mb=$($res.peakmb) gbps=$([math]::Round($gib * 1.073741824 / [math]::Max($res.wall, 0.001), 3)) route=$($rt[0]) corpus_b=$($rt[1]) mapgate=$($rt[2]) set=$setsha parfiles=$($pars.Count) parbytes=$parbytes warm_s=$warm page_reads=$pagereads pages_in=$pagesin disk_read_gb=$diskgb avail_mb_before=$av0 avail_mb_after=$($script:io_av) load_before=$load0 load_after=$load1 foreign_cpu=$($res.foreign) foreign_after=$($res.foreignAfter) errlen=$($res.errlen) rig=$(Get-RigStamp) ts=$(Ts)"
    if (Test-Path "$logbase.err") {
      foreach ($ln in (Get-Content "$logbase.err" | Select-Object -First 60)) {
        $clean = $ln.Trim()
        if ($clean) { "TIMING leg=$legtag $clean" }
      }
    }
    if ($res.rc -ne 0) { "ORAMX-FAIL leg rc=$($res.rc) $legtag"; exit 9 }
    if (-not $verified.ContainsKey($key)) {
      $verified[$key] = $true
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

  for ($rep = 1; $rep -le $MaxReps; $rep++) {
    $pass = @($cells | Where-Object { $_[5] -ge $rep })
    if ($pass.Count -eq 0) { continue }
    if ($rep % 2 -eq 0) { [array]::Reverse($pass) }
    foreach ($c in $pass) {
      Start-Hog $c[3]
      Run-Leg $c $rep
    }
  }
  Stop-Hog
  foreach ($k in ($routes.Keys | Sort-Object)) {
    $u = @($routes[$k] | Select-Object -Unique)
    "ROUTE-IDENTITY cell=$k legs=$($routes[$k].Count) distinct=$($u.Count) routes=$($u -join '/')"
  }
  foreach ($k in ($digests.Keys | Sort-Object)) {
    $u = @($digests[$k] | Select-Object -Unique)
    "SET-IDENTITY shape=$k legs=$($digests[$k].Count) distinct=$($u.Count) digests=$($u -join '/')"
  }
  "ALL DONE end=$(Ts)"
} finally {
  Stop-Hog
  Release-RigLock $lock
}
