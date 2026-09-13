# PAR2 bench round, Windows rig. Same protocol as round2.sh on the Macs:
#   fresh copy of the corpus -> PRE-WARM (read every byte once) -> time.
# Adds the two columns the previous round left out: classic par2cmdline and
# MultiPar's par2j.
param([string]$Leg = "verify", [int]$Rounds = 3, [string]$Tools = "ours,turboT,turboD,rarpar,classic,par2j",
      [string]$Ours = "",
      # Recovery percentage for the CREATE legs.  10 is the census mode and
      # not a bucket: of 189 random PAR2-bearing posts over 1 GB, 65 are at
      # exactly 10% and only 2 at 15%, and 10 is the modal value for ParPar,
      # MultiPar and QuickPar taken separately (par2cmdline's own default of
      # 8 is the one exception).  20 is the second real cluster, 10.6% of
      # posts.  A sweep over this parameter is a SENSITIVITY line, never a
      # second population row - see the redundancy note in the README.
      [int]$Redundancy = 10,
      # Override the row's slice size, in BYTES.  0 keeps the row's own.
      # The sizes worth sweeping are the ones posters actually use, and they
      # are NOT round numbers: most tools derive the slice from a target block
      # count.  Measured over 189 random PAR2-bearing posts over 1 GB, the
      # values that repeat are 1048576 (n=29, and the median), 768000 (n=20),
      # 716800 (n=14) and 1536000 (n=7).  4194304 appears ZERO times, which is
      # why row7b stopped being a 4 MiB leg on 7 Sep 2026.
      [int]$Slice = 0)

# ===========================================================================
# THE SCENARIO LEGS (added 6 Sep 2026), the Windows twin of round2.sh's. Same
# ten rows, same article-unit damage maps, same mirrored protocol: each round
# runs the tool order forward and then reversed, with SettleMs of idle between
# legs outside every timed region. MultiPar's par2j is a full arm here - it is
# Windows-only, and on the shapes it can do it is the strongest rival after
# turbo.
#
#   round2.ps1 -Leg row1 -Rounds 2 -Root D:\parscen -Ours C:\bin\parfast.exe
#
# Rows: row1 row2 row3a row3b row4 row5s100 row5s110 row5m100 row5m110
#       row6 row7a row7b row8 row9 row10 row10v, or "all".
# ===========================================================================
if ($Leg -like "row*" -or $Leg -eq "all") {
  $Root = if ($env:SCENROOT) { $env:SCENROOT } else { "$env:USERPROFILE\parscen" }
  $SettleMs = if ($env:SETTLE_MS) { [int]$env:SETTLE_MS } else { 1000 }
  $Threads  = if ($env:THREADS) { $env:THREADS } else { "16" }
  # Every rival is an env override, because no two Windows rigs put them in
  # the same place and a hardcoded path publishes a blank column.
  $SB       = "$env:USERPROFILE\parshoot\bin"
  $SOURS    = if ($Ours) { $Ours } elseif ($env:SCEN_PARFAST) { $env:SCEN_PARFAST } else { "$SB\parfast.exe" }
  $STURBO   = if ($env:SCEN_TURBO)   { $env:SCEN_TURBO }   else { "C:\tools\bin\par2.exe" }
  $STURBO14 = if ($env:SCEN_TURBO14) { $env:SCEN_TURBO14 } else { "" }
  $STURBO12 = if ($env:SCEN_TURBO12) { $env:SCEN_TURBO12 } else { "" }
  $SPARPAR  = if ($env:SCEN_PARPAR)  { $env:SCEN_PARPAR }  else { "$SB\parpar.cmd" }
  $SRARPAR  = if ($env:SCEN_RARPAR)  { $env:SCEN_RARPAR }  else { "$env:USERPROFILE\rarshoot\bin\rarpar.exe" }
  $SPAR2J   = if ($env:SCEN_PAR2J)   { $env:SCEN_PAR2J }   else { "C:\Program Files (x86)\MultiPar\par2j64.exe" }
  $SPHPAR2  = if ($env:SCEN_PHPAR2)  { $env:SCEN_PHPAR2 }  else { "" }
  # pesto's parmesan (added 13 Sep 2026): `cargo build --release -p
  # parmesan-par2` natively; not par2cmdline's dialect - see round2.sh's
  # header note and research/PARMESAN-COMPARE-2026-09-13.md.
  $SPARMESAN = if ($env:SCEN_PARMESAN) { $env:SCEN_PARMESAN } else { "$SB\parmesan.exe" }
  $SWORK    = "$env:TEMP\parscen-work"
  $SHERE    = Split-Path -Parent $PSCommandPath
  if (-not $PSBoundParameters.ContainsKey('Tools')) { $Tools = "parfast,turboT,parpar,par2j,rarpar" }

  # fixture, reference, kind, create-block-size, PRISTINE, MAP.
  # NTFS has no cheap clone, so this rig holds only the pristine trees and
  # each leg cuts its own damage into the work copy from the map.
  $rows = @{
    "row1"     = @("row1-tv-2articles",     "$Root\tv.sha",          "repair", 0, "tv",     "amap-row1-tv.txt")
    "row2"     = @("row2-movie-12articles", "$Root\movie.sha",       "repair", 0, "movie",  "amap-row2-movie.txt")
    "row3a"    = @("row3-movie-gap",        "$Root\movie.sha",       "repair", 0, "movie",  "amap-row3-movie-gap.txt")
    "row3b"    = @("row3-movie-volgone",    "$Root\movie.sha",       "repair", 0, "movie",  "amap-row3-movie-most.txt")
    "row4"     = @("row4-movie-deleted",    "$Root\movie.sha",       "repair", 0, "movie",  "amap-row4-movie.txt")
    "row5s100" = @("row5-single-100",       "$Root\pars-single.sha", "repair", 0, "pars-single-100", "amap-row5-single.txt")
    "row5s110" = @("row5-single-110",       "$Root\pars-single.sha", "repair", 0, "pars-single-110", "amap-row5-single.txt")
    "row5m100" = @("row5-multi-100",        "$Root\pars-multi.sha",  "repair", 0, "pars-multi-100",  "amap-row5-multi.txt")
    "row5m110" = @("row5-multi-110",        "$Root\pars-multi.sha",  "repair", 0, "pars-multi-110",  "amap-row5-multi.txt")
    "row6"     = @("movie",                 "",                       "verify", 0, "movie",  "")
    "row7a"    = @("create",                "",                       "create", 1048576, "create", "")
    "row7b"    = @("create",                "",                       "create", 1536000, "create", "")
    "row8"     = @("row8-album-1article",   "$Root\album.sha",       "repair", 0, "album",  "amap-row8-album.txt")
    "row9"     = @("row9-heavy-1500blocks", "$Root\heavy.sha",       "repair", 0, "heavy",  "map-heavy-1500.txt")
    "row10"    = @("row10-sports-1article", "$Root\sports.sha",      "repair", 0, "sports", "amap-row10-sports.txt")
    "row10v"   = @("sports",                "",                       "verify", 0, "sports", "")
  }
  if ($Leg -eq "all") {
    foreach ($r in @("row1","row2","row3a","row3b","row4","row6","row5s100","row5s110",
                     "row5m100","row5m110","row7a","row7b","row8","row9","row10","row10v")) {
      & $PSCommandPath -Leg $r -Rounds $Rounds -Tools $Tools -Ours $Ours
    }
    exit 0
  }
  if (-not $rows.ContainsKey($Leg)) { Write-Error "unknown row $Leg"; exit 2 }
  $fixture, $reference, $kind, $cbs, $pristine, $map = $rows[$Leg]
  if ($Slice -gt 0) { $cbs = $Slice }

  # apply-damage.py, in PowerShell, because this box has no Python: the
  # Windows rigs have only the Store alias stub, and a rig that needs an
  # interpreter it cannot have is a rig that publishes a blank column. Both
  # map dialects, same semantics as the .py - an ARTICLE map zero-fills whole
  # yEnc article spans and DELETEs absent members, a block map flips one byte
  # mid-block.
  function SApplyDamage($src, $dst, $mapfile) {
    Copy-Item -Recurse $src $dst
    $lines = Get-Content $mapfile | Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith("#") }
    if ($lines[0] -like "ARTICLE *") {
      $art = [int]($lines[0] -split "\s+")[1]
      foreach ($line in $lines[1..($lines.Count - 1)]) {
        $head, $rest = $line -split "\s+", 2
        if ($head -eq "DELETE") { Remove-Item (Join-Path $dst $rest.Trim()); continue }
        $first, $last = ($rest.Trim() -split "-")[0], ($rest.Trim() -split "-")[-1]
        $start = [int64]$first * $art
        $end = ([int64]$last + 1) * $art
        $path = Join-Path $dst $head
        $fs = [System.IO.File]::Open($path, "Open", "Write")
        if ($end -gt $fs.Length) { $end = $fs.Length }
        $fs.Seek($start, "Begin") | Out-Null
        $zero = New-Object byte[] (1MB)
        $left = $end - $start
        while ($left -gt 0) {
          $n = [math]::Min($left, $zero.Length)
          $fs.Write($zero, 0, $n); $left -= $n
        }
        $fs.Close()
      }
    } else {
      $bs = [int]$lines[0]
      foreach ($line in $lines[1..($lines.Count - 1)]) {
        $name, $block = $line -split "\s+", 2
        $off = [int64]$block * $bs + [int64]($bs / 2)
        $fs = [System.IO.File]::Open((Join-Path $dst $name), "Open", "ReadWrite")
        $fs.Seek($off, "Begin") | Out-Null
        $b = $fs.ReadByte()
        $fs.Seek($off, "Begin") | Out-Null
        $fs.WriteByte([byte]($b -bxor 0xFF))
        $fs.Close()
      }
    }
  }

  function SPreWarm($dir) {
    $buf = New-Object byte[] (4MB)
    foreach ($f in Get-ChildItem "$dir\*" -File) {
      $fs = [System.IO.File]::OpenRead($f.FullName)
      while ($fs.Read($buf, 0, $buf.Length) -gt 0) { }
      $fs.Close()
    }
  }
  # High priority for every arm, for the reason the older RunTimed documents:
  # Windows demotes sustained work onto E-cores and an unlifted round measures
  # the scheduler. Peak working set is read while the handle is still open -
  # it reads zero once the process object has been refreshed after exit, which
  # is why the 5 Sep round has no RSS column.
  # ONE process, started by us and held by us. `Start-Process -PassThru`
  # hands back an object whose ExitCode and TotalProcessorTime read $null or
  # throw once the process has gone - measured on the i5, where the fastest
  # arm (ours) lost both while the slower rivals kept theirs, which would have
  # published a CPU column with our own row missing from it. A
  # System.Diagnostics.Process we own keeps the exit code and the CPU time
  # valid after exit, which is what the sha gate and the CPU column need.
  # PeakWorkingSet64 still reads 0 here even so, so a Windows row carries NO
  # RSS - measured 7 Sep 2026, same as the 5 Sep round found. Do not print an
  # RSS number for this platform and do not assume the ceiling is the same as
  # the Macs': it is unmeasured here, not small.
  if (-not ("PSPMemCounters.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace PSPMemCounters {
  [StructLayout(LayoutKind.Sequential)]
  public struct MEM {
    public uint cb; public uint PageFaultCount;
    public UIntPtr PeakWorkingSetSize; public UIntPtr WorkingSetSize;
    public UIntPtr QuotaPeakPagedPoolUsage; public UIntPtr QuotaPagedPoolUsage;
    public UIntPtr QuotaPeakNonPagedPoolUsage; public UIntPtr QuotaNonPagedPoolUsage;
    public UIntPtr PagefileUsage; public UIntPtr PeakPagefileUsage;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct IO {
    public ulong ReadOperationCount; public ulong WriteOperationCount;
    public ulong OtherOperationCount; public ulong ReadTransferCount;
    public ulong WriteTransferCount; public ulong OtherTransferCount;
  }
  public static class Native {
    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool GetProcessMemoryInfo(IntPtr h, ref MEM c, int cb);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetProcessIoCounters(IntPtr h, ref IO c);
  }
}
"@
  }

  function SRunTimed($exe, $argv, $cwd) {
    if (-not (Test-Path $exe)) { return [pscustomobject]@{ wall = 0; rc = "NOEXE"; rss = 0; cpu = 0 } }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.WorkingDirectory = $cwd
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($a in $argv) { $psi.Arguments += '"' + ($a -replace '"', '\"') + '" ' }
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $null = $proc.Start()
    # The pipes must be drained or a chatty arm blocks on a full buffer and
    # the leg times a deadlock. Read them asynchronously, then wait.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    try { $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High } catch { }
    $proc.WaitForExit()
    $sw.Stop()
    $null = $outTask.Result; $null = $errTask.Result
    # PEAK RSS AND DISK I/O, OFF THE STILL-OPEN HANDLE.
    # `$proc.PeakWorkingSet64` is read here, AFTER WaitForExit, and .NET
    # refreshes it from a process that no longer exists - so it returns 0 and
    # every Windows leg in every round to 7 Sep 2026 reported `rss_mb=0`.
    # That is an unmeasured column printed as a number, the same defect shape
    # as the create gate above. The Win32 calls below read the kernel's own
    # accounting, which stays valid while the handle is open, and the same
    # call site yields the I/O counters at no extra cost.
    $mem = New-Object PSPMemCounters.MEM
    $io  = New-Object PSPMemCounters.IO
    $h   = $proc.Handle
    $mem.cb = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($mem)
    $okM = [PSPMemCounters.Native]::GetProcessMemoryInfo($h, [ref]$mem, [int]$mem.cb)
    $okI = [PSPMemCounters.Native]::GetProcessIoCounters($h, [ref]$io)
    # PeakWorkingSetSize is a UIntPtr and PowerShell cannot divide one, which
    # is why the first cut of this fix printed an empty rss_mb: convert first.
    $peakB = if ($okM) { $mem.PeakWorkingSetSize.ToUInt64() } else { 0 }
    $m = [pscustomobject]@{
      wall = [math]::Round($sw.Elapsed.TotalSeconds, 3)
      rc   = $proc.ExitCode
      rss  = if ($okM) { [int]($peakB / 1MB) } else { -1 }
      cpu  = [math]::Round($proc.TotalProcessorTime.TotalSeconds, 1)
      rd   = if ($okI) { [int]($io.ReadTransferCount / 1MB) } else { -1 }
      wr   = if ($okI) { [int]($io.WriteTransferCount / 1MB) } else { -1 }
    }
    $proc.Dispose()
    return $m
  }

  function SShaGate($dir, $ref) {
    if (-not $ref) { return "n/a" }
    # A reference that is not there is a FAILURE, never a pass. The first i5
    # run printed sha=OK for six arms over a fixture whose .sha had never been
    # written, which is the rubber stamp every gate in this repo exists to
    # refuse: failing to find is failing.
    if (-not (Test-Path $ref)) { return "NO-REFERENCE" }
    $bad = 0
    foreach ($line in Get-Content $ref) {
      # `shasum -a 256 ./x` and Get-FileHash both write "<hash>  ./<name>";
      # take the first field as the hash and strip any "./" from the rest.
      $h, $n = $line -split "\s+", 2
      $path = Join-Path $dir ($n.Trim() -replace '^\./', '')
      if (-not (Test-Path $path)) { $bad++; continue }
      if ((Get-FileHash -Algorithm SHA256 $path).Hash -ne $h.ToUpper()) { $bad++ }
    }
    if ($bad -eq 0) { "OK" } else { "MISMATCH" }
  }

  function SOne($tool, $obs) {
    $label = "$Leg-$tool-$obs"
    if ($kind -eq "create") {
      $src = "$Root\$fixture"; $out = "$SWORK\c"
      Remove-Item -Recurse -Force $SWORK -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $out | Out-Null
      SPreWarm $src
      $files = (Get-ChildItem "$src\*.bin" | ForEach-Object { $_.FullName })
      Start-Sleep -Milliseconds $SettleMs
      switch ($tool) {
        "parfast" { $m = SRunTimed $SOURS (@("c","-q","-s$cbs","-r$Redundancy","-B$src","$out\set.par2") + $files) $src }
        "turboT"  { $m = SRunTimed $STURBO (@("c","-q","-s$cbs","-r$Redundancy","-T$Threads","-B$src","$out\set.par2") + $files) $src }
        "turbo"   { $m = SRunTimed $STURBO (@("c","-q","-s$cbs","-r$Redundancy","-B$src","$out\set.par2") + $files) $src }
        "parpar"  { $m = SRunTimed $SPARPAR (@("-q","-s${cbs}b","-r","$Redundancy%","-o","$out\set.par2") + $files) $src }
        "par2j"   { $m = SRunTimed $SPAR2J (@("c","/ss$cbs","/rr$Redundancy","$out\set.par2") + $files) $src }
        "turbo140" { $m = SRunTimed $STURBO14 (@("c","-q","-s$cbs","-r$Redundancy","-T$Threads","-B$src","$out\set.par2") + $files) $src }
        "turbo120" { $m = SRunTimed $STURBO12 (@("c","-q","-s$cbs","-r$Redundancy","-T$Threads","-B$src","$out\set.par2") + $files) $src }
        "phpar2"  { $m = SRunTimed $SPHPAR2 (@("c","-q","-s$cbs","-r$Redundancy","$out\set.par2") + $files) $src }
        # parmesan names its output by directory + base name, never by path.
        "parmesan" { $m = SRunTimed $SPARMESAN (@("create","-q","-s","$cbs","-r","$Redundancy","-o",$out,"-b","set") + $files) $src }
        default   { return }
      }
      # A created set counts only if a DIFFERENT tool can read it back - and
      # the gate has to be able to FIND the payload to do it.  round2.sh
      # symlinks the members beside the set for this; Windows symlinks need a
      # privilege the rig does not have, so pass turbo the payload's base
      # directory instead.  WITHOUT -B this returns 2 ("repair not possible")
      # for every arm including turbo's own output, which is a gate that
      # cannot fail and therefore never passed: the 7 Sep 2026 three-box
      # round's i5 create legs all read turbo_verify=2 and were never gated.
      $v = SRunTimed $STURBO @("v","-q","-B$src","$out\set.par2") $src
      Write-Host ("LEG row={0} tool={1,-7} obs={2} wall={3:N2} cpu={4:N1} rss_mb={5} rc={6} turbo_verify={7} r={8} slice={9} rd_mb={10} wr_mb={11}" -f `
        $Leg, $tool, $obs, $m.wall, $m.cpu, $m.rss, $m.rc, $v.rc, $Redundancy, $cbs, $m.rd, $m.wr)
      return
    }
    Remove-Item -Recurse -Force $SWORK -ErrorAction SilentlyContinue
    if (Test-Path "$Root\$fixture") {
      Copy-Item -Recurse "$Root\$fixture" "$SWORK"
    } else {
      # No standing damaged copy: cut this row's damage into a fresh copy of
      # the pristine fixture. Same bytes, same map, outside the timed region.
      SApplyDamage "$Root\$pristine" "$SWORK" "$SHERE\$map"
    }
    SPreWarm $SWORK
    Start-Sleep -Milliseconds $SettleMs
    $par = (Get-ChildItem "$SWORK\*.par2" | Where-Object { $_.Name -notmatch "vol" } | Select-Object -First 1).FullName
    $verb = if ($kind -eq "verify") { "v" } else { "r" }
    switch ($tool) {
      "parfast" { $m = SRunTimed $SOURS @($verb,"-q",$par) $SWORK }
      # `-T` is turbo's files-hashed-in-parallel count, NOT its compute-thread
      # knob (that is lower-case `-t`, defaulting to the detected core count).
      # The arm name is kept so older numbers stay comparable - README trap.
      "turboT"  { $m = SRunTimed $STURBO @($verb,"-q","-T$Threads",$par) $SWORK }
      "turbo"   { $m = SRunTimed $STURBO @($verb,"-q",$par) $SWORK }
      # par2j returns 16 after a SUCCESSFUL repair, so its exit code is
      # recorded and the sha gate is what decides whether the run counted.
      "turbo140" { $m = SRunTimed $STURBO14 @($verb,"-q","-T$Threads",$par) $SWORK }
      "turbo120" { $m = SRunTimed $STURBO12 @($verb,"-q","-T$Threads",$par) $SWORK }
      # par2j returns 16 after a SUCCESSFUL repair; phpar2 takes par2cmdline
      # syntax. Both are recorded by exit code and decided by the sha gate.
      "par2j"   { $m = SRunTimed $SPAR2J @($verb,$par) $SWORK }
      "phpar2"  { $m = SRunTimed $SPHPAR2 @($verb,"-q",$par) $SWORK }
      # parmesan spells its verbs out and scans the index file's directory.
      "parmesan" { $m = SRunTimed $SPARMESAN @($(if ($kind -eq "verify") { "verify" } else { "repair" }),"-q",$par) $SWORK }
      "rarpar"  { $m = if ($kind -eq "verify") { SRunTimed $SRARPAR @("par","verify",$SWORK) $SWORK }
                       else { SRunTimed $SRARPAR @("par","repair","-C",$SWORK,$SWORK) $SWORK } }
      default   { return }
    }
    $sha = SShaGate $SWORK $reference
    Write-Host ("LEG row={0} tool={1,-7} obs={2} wall={3:N2} cpu={4:N1} rss_mb={5} rc={6} sha={7} rd_mb={8} wr_mb={9}" -f `
      $Leg, $tool, $obs, $m.wall, $m.cpu, $m.rss, $m.rc, $sha, $m.rd, $m.wr)
  }

  Write-Host "=== $Leg ($kind, $fixture, $Rounds round(s) mirrored, $Tools, settle ${SettleMs}ms)"
  $arms = $Tools -split ","
  $obs = 0
  for ($i = 1; $i -le $Rounds; $i++) {
    $obs++; foreach ($t in $arms) { SOne $t $obs }
    $obs++; for ($k = $arms.Count - 1; $k -ge 0; $k--) { SOne $arms[$k] $obs }
  }
  Remove-Item -Recurse -Force $SWORK -ErrorAction SilentlyContinue
  exit 0
}

$B       = "$env:USERPROFILE\parshoot"
# Default kept for older invocations; pass -Ours to race a freshly built
# driver without overwriting a binary another session may be timing.
$OURS    = if ($Ours) { $Ours } else { "$B\bin\ourpar2.exe" }
$TURBO   = "C:\tools\bin\par2.exe"
$RARPAR  = "$env:USERPROFILE\rarshoot\bin\rarpar.exe"
$CLASSIC = "$env:USERPROFILE\p2classic\x64\Release\par2.exe"
$PAR2J   = "C:\Program Files (x86)\MultiPar\par2j64.exe"
$WORK    = "$B\work-round2"

switch ($Leg) {
  "verify" { $src = "site-pristine";    $pris = "site-pristine";    $par2 = "corpus.par2"; $repair = $false }
  "rep101" { $src = "rep101-damaged";   $pris = "site-pristine";    $par2 = "corpus.par2"; $repair = $true }
  "rep3"   { $src = "rep3-damaged";     $pris = "site-pristine";    $par2 = "corpus.par2"; $repair = $true }
  "heavy"  { $src = "heavy-damaged21";  $pris = "heavy-pristine21"; $par2 = "corpus.par2"; $repair = $true }
}

function PreWarm($dir) {
  $buf = New-Object byte[] (4MB)
  foreach ($f in Get-ChildItem "$dir\*") {
    $fs = [System.IO.File]::OpenRead($f.FullName)
    while ($fs.Read($buf, 0, $buf.Length) -gt 0) { }
    $fs.Close()
  }
}

# Every tool runs at High priority. Windows demotes sustained "background"
# work onto E-cores a few seconds in, which took the heavy leg from 16.6 s to
# 58 s for our own binary and from ~250 s to 849 s for par2cmdline - i.e. the
# unmodified numbers measure the scheduler, not the tool. Our daemon opts out
# of that in-product; the others cannot, so the harness lifts all of them
# equally rather than publishing a throttled competitor.
function RunTimed($exe, $argv) {
  $p = Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $WORK `
       -NoNewWindow -PassThru -RedirectStandardOutput "$B\out.txt" -RedirectStandardError "$B\err.txt"
  try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High } catch { }
  $p.WaitForExit()
  return $p.ExitCode
}

function RunOne($tool) {
  Remove-Item -Recurse -Force $WORK -ErrorAction SilentlyContinue
  Copy-Item -Recurse "$B\$src" $WORK
  PreWarm $WORK
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  switch ($tool) {
    # The product default since e206ede6: the driver mirrors the daemon's
    # "fast par mode", so this row is what a user gets today.
    "ours"    { $code = RunTimed $OURS @($WORK) }
    # Explicit-NTT row, for older drivers and for A/B against the fold; on
    # a current driver it matches `ours`.
    "oursntt" { $env:NZBFAST_NTT = "1"; try { $code = RunTimed $OURS @($WORK) } finally { Remove-Item Env:NZBFAST_NTT } }
    # The streaming fold, i.e. fast par mode off: comparison, not shipping.
    "oursfold" { $env:NZBFAST_NTT = "0"; try { $code = RunTimed $OURS @($WORK) } finally { Remove-Item Env:NZBFAST_NTT } }
    "turboT"  { $code = if ($repair) { RunTimed $TURBO @("r","-q","-T16",$par2) } else { RunTimed $TURBO @("v","-q","-T16",$par2) } }
    "turboD"  { $code = if ($repair) { RunTimed $TURBO @("r","-q",$par2) }        else { RunTimed $TURBO @("v","-q",$par2) } }
    "rarpar"  { $code = if ($repair) { RunTimed $RARPAR @("par","repair","-C",$WORK,$WORK) } else { RunTimed $RARPAR @("par","verify",$WORK) } }
    "classic" { $code = if ($repair) { RunTimed $CLASSIC @("r","-q",$par2) }      else { RunTimed $CLASSIC @("v","-q",$par2) } }
    # par2j takes the command letter first and wants the index file by name.
    # It returns 16 after a SUCCESSFUL repair, so the exit code is recorded and
    # the output gate below is what decides whether the run counted.
    "par2j"   { $code = if ($repair) { RunTimed $PAR2J @("r",$par2) }             else { RunTimed $PAR2J @("v",$par2) } }
  }
  $sw.Stop()
  $bad = 0
  if ($repair) {
    foreach ($v in Get-ChildItem "$B\$pris\*.rar") {
      if ((Get-FileHash -Algorithm SHA256 $v.FullName).Hash -ne
          (Get-FileHash -Algorithm SHA256 "$WORK\$($v.Name)").Hash) { $bad++ }
    }
  }
  $flag = if ($bad -eq 0) { "" } else { "  !! MISMATCH $bad" }
  Write-Host ("  {0,-8} {1,8:N3}s  exit={2}{3}" -f $tool, $sw.Elapsed.TotalSeconds, $code, $flag)
}

Write-Host "=== $Leg (warm protocol, $Rounds rounds, $Tools) ==="
$list = $Tools -split ","
for ($i = 1; $i -le $Rounds; $i++) { foreach ($t in $list) { RunOne $t } }
Remove-Item -Recurse -Force $WORK -ErrorAction SilentlyContinue
