param(
  [string]$Root = '<rig>\catwin-15sep',   # holds src-main.tar, src-base.tar; everything else is made here
  [string]$MainSha = '',                            # the origin/main the main tar was cut from, for the log
  [string]$NotBeforeUtc = '2026-09-16T06:00:00Z',   # the box is promised to another round until then
  [string]$UntilUtc = '2026-09-17T18:00:00Z',       # give up waiting past this
  [int]$WarmReps = 5,
  [int]$ColdReps = 3,
  [switch]$KeepFixture
)
# catwin.ps1 - the Windows A/B of the windowed PAR2 catalog scan (TODO 344,
# an internal note section A,
# claim parfast-catalog-window-windows-ab-15sep). Written 15 Sep 2026.
#
# THREE ARMS, TWO BINARIES:
#   base   parfast from 1dd22f7fe (window, no pool, 16 MiB warmer buffers)
#   win    parfast from origin/main (window + WindowPool + 1 MiB warmer)
#   whole  the origin/main binary with NZBFAST_PAR2_CATALOG_WINDOWED=0
# so win-vs-whole is the one-binary knob A/B the brief asks for, and
# base-vs-win is the pool and the warmer, which no knob reaches.
#
# ORDER: wait for a free box (no HELD rig lock, no parfast/cargo/rustc, twice a
# minute apart, and past -NotBeforeUtc), take the rig lock, extract both trees
# into their OWN directories and build each with its OWN CARGO_TARGET_DIR,
# refuse unless the main binary contains NZBFAST_PAR2_CATALOG_WINDOWED and the
# two sha256s differ, build the 64 KiB and 1 MiB fixtures, run the warm grid,
# then the cold grid, then delete trees, fixtures and binaries (logs stay).
#
# COLD is a real standby-list purge, never a fresh copy: flush the modified
# list, trim the system file cache working set, purge the standby list
# (NtSetSystemInformation class 80, commands 3 and 4 - what RAMMap -Et does),
# with GetPerformanceInfo's SystemCache (standby + system working set) read
# before and after so each cold leg CARRIES the evidence that it was cold. If
# the privilege cannot be enabled or the purge returns non-zero, the cold grid
# is skipped and the log says COLD-NOT-MEASURED.
$ErrorActionPreference = 'Stop'
function Get-Ts { (Get-Date).ToUniversalTime().ToString('o') }
# THE LOCK IS TAKEN BEFORE THE TAR EXTRACTION, which is why plib is dot-sourced
# from BESIDE THIS SCRIPT and not from the tree. The tree does not exist yet -
# extracting it is the first thing this round does under the lock, and doing
# that on a box we have not taken is exactly what the lock is for.
#
# It used to hand-roll its own CreateNew open and its own $catlockfs handle for
# that reason, with a second, stated reason: dot-sourcing plib AGAIN after the
# extraction reset $script:lockfs and threw on its Add-Type. Both of those are
# now guarded in plib.ps1 (see its note on being dot-sourced twice), so this
# round can use the shared take and the shared release - and it should, because
# the hand-rolled copy had no orphan arm and a Test-Path busy test, so a lock
# left behind by a hard-killed round would have parked it at CATWIN-DEADLINE,
# exit 5, on a free box (an internal note).
# The later `. $mainsrc\research\harness\plib.ps1` stays exactly where it is:
# it is what brings in Invoke-Leg and the rest, and it is now harmless.
$plib = Join-Path $PSScriptRoot 'plib.ps1'
if (-not (Test-Path $plib)) {
  "CATWIN-FAIL plib.ps1 must sit beside this script ($plib) - the rig lock is taken before the tarball is extracted, so the copy inside the tree is not reachable yet. scp harness/plib.ps1 next to catwin.ps1."
  exit 9
}
. $plib
$lk = Get-RigLockPath
# Test-RigLockHeld, never Test-Path. The cargo/rustc arm stays: a lock only
# excludes rounds that agreed to take one, and a build that took none is load.
function Test-Busy {
  (Test-RigLockHeld) -or [bool](Get-Process parfast, cargo, rustc -ErrorAction SilentlyContinue)
}
$notbefore = [datetime]::Parse($NotBeforeUtc).ToUniversalTime()
$deadline = [datetime]::Parse($UntilUtc).ToUniversalTime()
"CATWIN-WAIT notbefore=$NotBeforeUtc until=$UntilUtc pid=$PID ts=$(Get-Ts)"
while ($true) {
  $nowu = (Get-Date).ToUniversalTime()
  if ($nowu -gt $deadline) { "CATWIN-DEADLINE the box never came free ts=$(Get-Ts)"; exit 5 }
  if ($nowu -ge $notbefore -and -not (Test-Busy)) {
    Start-Sleep -Seconds 60
    if (-not (Test-Busy)) {
      Try-TakeRigLock 'catwin'
      if ($script:riglock_taken) { break }
      "CATWIN-LOST-RACE ts=$(Get-Ts)"
    }
  }
  Start-Sleep -Seconds 60
}
"CATWIN-FREE ts=$(Get-Ts)"
try {

# Extract the main tree first: plib.ps1 comes out of it.
$mainsrc = Join-Path $Root 'main'
$basesrc = Join-Path $Root 'base'
foreach ($pair in @(@($mainsrc, 'src-main.tar'), @($basesrc, 'src-base.tar'))) {
  $dir = $pair[0]; $tarf = Join-Path $Root $pair[1]
  if (-not (Test-Path (Join-Path $dir 'Cargo.toml'))) {
    New-Item -ItemType Directory -Force $dir | Out-Null
    cmd /c "tar -xf `"$tarf`" -C `"$dir`" > `"$Root\extract-$($pair[1]).log`" 2>&1"
    "CATWIN-EXTRACT $($pair[1]) rc=$LASTEXITCODE ts=$(Get-Ts)"
    if (-not (Test-Path (Join-Path $dir 'crates\parfast\Cargo.toml'))) { "CATWIN-FAIL extract $($pair[1])"; exit 9 }
  }
}
. (Join-Path $mainsrc 'research\harness\plib.ps1')

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class CatPurge {
  [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential, Pack=1)] struct TOKPRIV { public uint Count; public LUID Luid; public uint Attr; }
  [StructLayout(LayoutKind.Sequential)] struct PERFINFO {
    public uint cb; public UIntPtr CommitTotal, CommitLimit, CommitPeak, PhysicalTotal, PhysicalAvailable,
    SystemCache, KernelTotal, KernelPaged, KernelNonpaged, PageSize; public uint HandleCount, ProcessCount, ThreadCount;
  }
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKPRIV n, uint len, IntPtr prev, IntPtr rl);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("ntdll.dll")] static extern int NtSetSystemInformation(int cls, ref int info, int len);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetSystemFileCacheSize(IntPtr min, IntPtr max, uint flags);
  [DllImport("psapi.dll", SetLastError=true)] static extern bool GetPerformanceInfo(out PERFINFO pi, uint cb);
  public static long CacheMB() {
    PERFINFO p; p.cb = (uint)Marshal.SizeOf(typeof(PERFINFO));
    if (!GetPerformanceInfo(out p, p.cb)) return -1;
    return (long)((ulong)p.SystemCache * (ulong)p.PageSize / 1048576UL);
  }
  public static string Enable(string name) {
    IntPtr tok;
    if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return "open-" + Marshal.GetLastWin32Error();
    LUID l;
    if (!LookupPrivilegeValue(null, name, out l)) return "lookup-" + Marshal.GetLastWin32Error();
    TOKPRIV tp = new TOKPRIV(); tp.Count = 1; tp.Luid = l; tp.Attr = 2;
    if (!AdjustTokenPrivileges(tok, false, ref tp, (uint)Marshal.SizeOf(typeof(TOKPRIV)), IntPtr.Zero, IntPtr.Zero)) return "adjust-" + Marshal.GetLastWin32Error();
    int e = Marshal.GetLastWin32Error();
    return e == 0 ? "ok" : "notassigned-" + e;
  }
  public static int MemCmd(int c) { int v = c; return NtSetSystemInformation(80, ref v, 4); }
  public static string TrimCache() { return SetSystemFileCacheSize(new IntPtr(-1), new IntPtr(-1), 0) ? "ok" : "err-" + Marshal.GetLastWin32Error(); }
}
"@

function Get-LoadPct {
  $v = -1
  try { $v = [int]((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average) } catch { }
  return $v
}
# `{:.2?}` Duration text to seconds (wcomb.ps1's note: the OEM code page mangles µ).
function Get-Secs([string]$num, [string]$unit) {
  $x = [double]::Parse($num, [Globalization.CultureInfo]::InvariantCulture)
  if ($unit -eq '') { return $x }
  if ($unit -eq 'm') { return $x / 1e3 }
  if ($unit -eq 'n') { return $x / 1e9 }
  return $x / 1e6
}
# A cold purge. Emits nothing; the reading comes back in $script:purge (plib's
# Require-QuietBox note on why a PowerShell function must not log AND return).
function Invoke-Purge {
  $c0 = [CatPurge]::CacheMB()
  $f = [CatPurge]::MemCmd(3)
  $t = [CatPurge]::TrimCache()
  $p = [CatPurge]::MemCmd(4)
  Start-Sleep -Milliseconds 500
  $c1 = [CatPurge]::CacheMB()
  $script:purge = "cache_before_mb=$c0 cache_after_mb=$c1 flush_st=$f trim=$t purge_st=$p"
  $script:purgeok = ($p -eq 0)
}

Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
$members = @(1..16 | ForEach-Object { 'm{0:D2}.bin' -f $_ })
$logdir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Force $logdir | Out-Null
$binmain = Join-Path $Root 'parfast-main.exe'
$binbase = Join-Path $Root 'parfast-base.exe'

  "ROUND tag=catwin main_sha=$MainSha base_sha=1dd22f7fe warm_reps=$WarmReps cold_reps=$ColdReps start=$(Get-Ts)"
  Write-BoxFacts
  # The HARNESS's own provenance, and the round-start twin of the per-leg
  # `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath is THIS driver;
  # plib.ps1 adds itself. Without it a banked log cannot be traced to the
  # harness revision that wrote it (census
  # an internal note).
  Write-HarnessFacts @($PSCommandPath)

  foreach ($pair in @(@($mainsrc, $binmain, 'main'), @($basesrc, $binbase, 'base'))) {
    $tree = $pair[0]; $dst = $pair[1]; $lbl = $pair[2]
    $env:CARGO_TARGET_DIR = Join-Path $tree 'target'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $tree
    cmd /c "cargo build --release -p parfast --locked > `"$Root\build-$lbl.log`" 2>&1"
    $brc = $LASTEXITCODE
    Pop-Location
    "CATWIN-BUILD $lbl rc=$brc secs=$([math]::Round($sw.Elapsed.TotalSeconds,1)) target=$($env:CARGO_TARGET_DIR) ts=$(Get-Ts)"
    if ($brc -ne 0) { "CATWIN-FAIL build $lbl, see $Root\build-$lbl.log"; exit 9 }
    Copy-Item (Join-Path $env:CARGO_TARGET_DIR 'release\parfast.exe') $dst -Force
    Unblock-File $dst
  }
  Remove-Item env:CARGO_TARGET_DIR
  $hm = (Get-FileHash $binmain -Algorithm SHA256).Hash
  $hb = (Get-FileHash $binbase -Algorithm SHA256).Hash
  $latin = [Text.Encoding]::GetEncoding(28591)
  $knobm = $latin.GetString([IO.File]::ReadAllBytes($binmain)).Contains('NZBFAST_PAR2_CATALOG_WINDOWED')
  $knobb = $latin.GetString([IO.File]::ReadAllBytes($binbase)).Contains('NZBFAST_PAR2_CATALOG_WINDOWED')
  "CATWIN-BINS main=$hm base=$hb knob_main=$knobm knob_base=$knobb"
  if (-not $knobm) { "CATWIN-FAIL the main binary does not carry the knob string"; exit 9 }
  if ($hm -eq $hb) { "CATWIN-FAIL the two binaries hash the same"; exit 9 }

  $sets = @(
    (New-Object psobject -Property @{ name = '64k'; slice = 65536; rec = 4096 }),
    (New-Object psobject -Property @{ name = '1m'; slice = 1048576; rec = 512 })
  )
  foreach ($st in $sets) {
    $fx = Join-Path $Root "fix-$($st.name)"
    $st | Add-Member -NotePropertyName pristine -NotePropertyValue (Join-Path $fx 'pristine')
    $st | Add-Member -NotePropertyName work -NotePropertyValue (Join-Path $fx 'work')
    New-Item -ItemType Directory -Force $st.pristine, $st.work | Out-Null
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] (8MB)
    foreach ($nm in $members) {
      $fs = [IO.File]::Create((Join-Path $st.pristine $nm))
      for ($i = 0; $i -lt 8; $i++) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }
      $fs.Close()
    }
    $cout = @(Invoke-Leg $binmain "c -q -s$($st.slice) -c$($st.rec) -t8 set.par2 $($members -join ' ')" $st.pristine (Join-Path $logdir "create-$($st.name)"))
    $cr = $cout | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    "CREATE set=$($st.name) rc=$($cr.rc) wall=$($cr.wall) cpu=$($cr.cpu) peak_mb=$($cr.peakmb)"
    if ($cr.rc -ne 0) { "CATWIN-FAIL create $($st.name)"; exit 9 }
    $gd = @{}
    foreach ($nm in $members) { $gd[$nm] = Get-Sha256Fast (Join-Path $st.pristine $nm) }
    $st | Add-Member -NotePropertyName gold -NotePropertyValue $gd
    foreach ($f in (Get-ChildItem $st.pristine -File)) { Copy-Item $f.FullName (Join-Path $st.work $f.Name) -Force }
    $st | Add-Member -NotePropertyName parfiles -NotePropertyValue @(Get-ChildItem $st.pristine -Filter *.par2 | ForEach-Object { $_.Name })
    $chk = Test-RestoredFast $st.work $members $st.gold
    if ($chk.good -ne 16) { "CATWIN-FAIL work copy of $($st.name) not pristine"; exit 9 }
    $pbytes = (($st.parfiles | ForEach-Object { (Get-Item (Join-Path $st.pristine $_)).Length }) | Measure-Object -Sum).Sum
    "FIXTURE set=$($st.name) slice=$($st.slice) recovery=$($st.rec) parfiles=$($st.parfiles.Count) par_mb=$([math]::Round($pbytes/1MB,1)) largest_par_mb=$([math]::Round((($st.parfiles | ForEach-Object { (Get-Item (Join-Path $st.pristine $_)).Length }) | Measure-Object -Maximum).Maximum/1MB,1))"
  }

  function Run-Cell($st, [string]$budget, [string]$arm, [string]$kind, [int]$rep, [int]$ord) {
    $tag = "$kind-$($st.name)-$budget-$arm-r$rep"
    $dseed = 1192
    $picks = Get-DamagePicks $st.work $members $st.slice 192 $dseed
    $wrote = Invoke-DamagePicks $st.work $members $st.slice $picks $dseed
    $exe = if ($arm -eq 'base') { $binbase } else { $binmain }
    $envx = @{ NZBFAST_REPAIR_TIMING = '1'; NZBFAST_NTT = '0'; NZBFAST_MEM_FLOOR_SERIES = '1' }
    if ($arm -eq 'whole') { $envx['NZBFAST_PAR2_CATALOG_WINDOWED'] = '0' }
    $argstr = 'r -t4 -q'
    if ($budget -ne 'none') { $argstr += " -m$budget" }
    $argstr += ' set.par2'
    $script:purge = 'warm'; $script:purgeok = $true
    if ($kind -eq 'cold') { Invoke-Purge } else { Read-Warm $st.work $st.parfiles }
    $load0 = Get-LoadPct
    $lout = @(Invoke-Leg $exe $argstr $st.work (Join-Path $logdir $tag) $envx)
    $load1 = Get-LoadPct
    foreach ($s in ($lout | Where-Object { $_ -is [string] })) { $s }
    $r = $lout | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    $post = Test-RestoredFast $st.work $members $st.gold
    $strays = Remove-Strays $st.work $members $st.parfiles
    $err = [IO.File]::ReadAllText((Join-Path $logdir "$tag.err"))

    $sm = [regex]::Match($err, 'verify targets \+ volume scan: \+([0-9.]+)(\S{0,3}?)s \(total ([0-9.]+)(\S{0,3}?)s\)')
    $scan = if ($sm.Success) { [math]::Round((Get-Secs $sm.Groups[1].Value $sm.Groups[2].Value), 4) } else { '' }
    $scanat = if ($sm.Success) { [math]::Round((Get-Secs $sm.Groups[3].Value $sm.Groups[4].Value), 4) } else { '' }
    $alltot = [regex]::Matches($err, ': \+[0-9.]+\S{0,3}?s \(total ([0-9.]+)(\S{0,3}?)s\)')
    $tot = if ($alltot.Count -gt 0) { $g = $alltot[$alltot.Count - 1]; [math]::Round((Get-Secs $g.Groups[1].Value $g.Groups[2].Value), 3) } else { '' }
    $phases = @([regex]::Matches($err, '([a-z][a-z0-9 +/_()-]+): \+([0-9.]+)(\S{0,3}?)s \(total') | ForEach-Object {
      ($_.Groups[1].Value -replace ' ', '_') + '=' + [math]::Round((Get-Secs $_.Groups[2].Value $_.Groups[3].Value), 3) }) -join ','
    $mf = @{}
    foreach ($mm in [regex]::Matches($err, 'mem-floor: (live high-water|sampled peak rss) \S{1,3} ru_maxrss (\d+) MB \S{1,3} rss (\d+) MB \S{1,3} footprint (\d+) MB \S{1,3} rss over footprint (\d+) MB \S{1,3} repair work (\d+) MB \(own peak (\d+)\) \S{1,3} scan reads (\d+) MB \(own peak (\d+)\) \S{1,3} verifier tables (\d+) MB \S{1,3} unattributed (\d+) MB')) {
      $k = if ($mm.Groups[1].Value -like 'live*') { 'live' } else { 'samp' }
      $mf[$k] = "maxrss$($mm.Groups[2].Value)/rss$($mm.Groups[3].Value)/fp$($mm.Groups[4].Value)/work$($mm.Groups[6].Value)/workpk$($mm.Groups[7].Value)/scan$($mm.Groups[8].Value)/scanpk$($mm.Groups[9].Value)/vt$($mm.Groups[10].Value)/unattr$($mm.Groups[11].Value)"
    }
    # footprint before work: the last series sample before the first one
    # carrying repair work.
    $fpbw = ''; $prev = ''; $fpmax = 0
    foreach ($sr in [regex]::Matches($err, 'mem-floor series: ([0-9.]+)s fp (\d+) MB work (\d+) MB scan (\d+) MB')) {
      $fpv = [int]$sr.Groups[2].Value
      if ($fpv -gt $fpmax) { $fpmax = $fpv }
      if ($fpbw -eq '' -and [int]$sr.Groups[3].Value -gt 0) { $fpbw = $prev }
      $prev = $fpv
    }
    $path = if ($err -match 'ntt syndromes') { 'ntt' } else { 'fold' }

    "LEG kind=$kind set=$($st.name) budget=$budget arm=$arm rep=$rep ord=$ord rc=$($r.rc) restored=$($post.good)/16 wall=$($r.wall) cpu=$($r.cpu) peak_mb=$($r.peakmb) scan_s=$scan scan_at_s=$scanat total_s=$tot fp_before_work=$fpbw series_fp_max=$fpmax path=$path mf_live=$($mf['live']) mf_samp=$($mf['samp']) phases=$phases blocks_written=$wrote strays=$strays $($script:purge) foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) load_before=$load0 load_after=$load1 errlen=$($r.errlen) ts=$(Get-Ts)"
    if ($path -ne 'fold') { "CATWIN-FAIL NZBFAST_NTT=0 leg took the transform at $tag"; exit 9 }

    Restore-Slices $st.work $st.pristine $members $st.slice $picks
    $chk = Test-RestoredFast $st.work $members $st.gold
    if ($chk.good -ne 16) {
      foreach ($nm in $chk.bad) { Copy-Item (Join-Path $st.pristine $nm) (Join-Path $st.work $nm) -Force }
      foreach ($nm in $st.parfiles) { Copy-Item (Join-Path $st.pristine $nm) (Join-Path $st.work $nm) -Force }
      $chk2 = Test-RestoredFast $st.work $members $st.gold
      "RESTORE-FALLBACK leg=$tag copied=$($chk.bad -join ',') now=$($chk2.good)/16"
      if ($chk2.good -ne 16) { "CATWIN-FAIL restore at $tag"; exit 9 }
    }
  }

  $rot = @(@('base', 'win', 'whole'), @('win', 'whole', 'base'), @('whole', 'base', 'win'))
  # Warm-up, recorded as rep 0 and not read: every arm once per set.
  foreach ($st in $sets) { $o = 0; foreach ($arm in $rot[0]) { $o++; Run-Cell $st '128' $arm 'warm' 0 $o } }
  for ($rep = 1; $rep -le $WarmReps; $rep++) {
    foreach ($st in $sets) { foreach ($budget in @('128', 'none')) {
      $o = 0; foreach ($arm in $rot[($rep - 1) % 3]) { $o++; Run-Cell $st $budget $arm 'warm' $rep $o }
    } }
  }

  $pe = [CatPurge]::Enable('SeProfileSingleProcessPrivilege')
  $qe = [CatPurge]::Enable('SeIncreaseQuotaPrivilege')
  Invoke-Purge
  "COLD-PROBE profile_priv=$pe quota_priv=$qe $($script:purge)"
  if (-not $script:purgeok) {
    "COLD-NOT-MEASURED the standby purge did not succeed on this token"
  } else {
    for ($rep = 1; $rep -le $ColdReps; $rep++) {
      foreach ($st in $sets) {
        $o = 0; foreach ($arm in $rot[($rep - 1) % 3]) { $o++; Run-Cell $st '128' $arm 'cold' $rep $o }
      }
    }
  }
  "CATWIN-DONE ts=$(Get-Ts)"
} finally {
  # Release-RigLock, not a hand-rolled Close-then-Remove. The reasoning that
  # used to sit here is now where it belongs, in plib.ps1's Release-RigLock:
  # the handle is opened CreateNew with FileShare::None, so on NTFS "the path
  # is taken" and "the file is open" are the SAME fact and there is no window
  # for the POSIX unlink race
  # (an internal note) to open in.
  Release-RigLock $lk
  if (-not $KeepFixture) {
    foreach ($d in @('fix-64k', 'fix-1m', 'main', 'base')) {
      $p = Join-Path $Root $d
      if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; "CATWIN-CLEAN $d gone=$(-not (Test-Path $p))" }
    }
    foreach ($f in @($binmain, $binbase, (Join-Path $Root 'src-main.tar'), (Join-Path $Root 'src-base.tar'))) {
      if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    "CATWIN-CLEAN binaries-and-tars ts=$(Get-Ts)"
  }
}
