# plib.ps1 - shared harness for the parfast publication rounds, intel-i5-10600kf.
#
# Every defect this library exists to prevent is recorded in
# an internal note:
#  - a refused tool must never read as a fast success  -> rc AND stderr kept per leg
#  - Start-Process -PassThru returned wall=0           -> ProcessStartInfo, streams
#                                                         drained before WaitForExit
#  - PowerShell variables are CASE-INSENSITIVE         -> every name here is distinct
#                                                         in lowercase
#  - PowerShell does not glob for native commands      -> member names are passed
#                                                         explicitly, never *.bin
#  - concurrency corrupted three rounds in one day     -> an exclusive rig LOCK,
#                                                         counted as a lock and not
#                                                         as a process
#  - numbered backups reached 157 GB                   -> stray files are removed
#                                                         after every leg
$ErrorActionPreference = 'Stop'

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class PMem {
  [StructLayout(LayoutKind.Sequential)]
  public struct PMC {
    public uint cb; public uint PageFaultCount;
    public IntPtr PeakWorkingSetSize; public IntPtr WorkingSetSize;
    public IntPtr QuotaPeakPagedPoolUsage; public IntPtr QuotaPagedPoolUsage;
    public IntPtr QuotaPeakNonPagedPoolUsage; public IntPtr QuotaNonPagedPoolUsage;
    public IntPtr PagefileUsage; public IntPtr PeakPagefileUsage;
  }
  [DllImport("psapi.dll", SetLastError=true)]
  static extern bool GetProcessMemoryInfo(IntPtr h, out PMC c, uint sz);
  public static long PeakWS(IntPtr h) {
    PMC c = new PMC();
    c.cb = (uint)Marshal.SizeOf(typeof(PMC));
    if (GetProcessMemoryInfo(h, out c, c.cb)) return (long)c.PeakWorkingSetSize;
    return -1;
  }
}
"@

$script:lockfs = $null

function Take-RigLock([string]$lockpath) {
  # THE LOCK IS PER BOX, NOT PER ROUND, and that is the whole point. Until
  # 10 Sep 2026 each script locked its OWN file - lad.lock, vfy.lock,
  # full.lock - so the lock excluded a second copy of the SAME round and did
  # nothing at all about a DIFFERENT one. Measured that day on intel-i5-10600kf:
  # lad.ps1, vfy.ps1 and full.ps1 all live at once with two rival tools
  # running, which silently contaminated an entire ladder (parfast read 36.5 s
  # at m=64 and 29.7 s at m=1,280 - not a curve, a disturbed box).
  #
  # So every round on a box now contends for ONE file in the rig root, and the
  # round's own name is written inside it, which is also what makes the holder
  # identifiable to a human. The caller still passes its own name; only the
  # path is collapsed.
  $roundname = [IO.Path]::GetFileNameWithoutExtension($lockpath)
  # ABSOLUTE, in the user profile. The first fix derived the lock from the
  # LOG's directory, which is per-DIRECTORY and not per-box: on 10 Sep 2026 a
  # lane running out of one directory and a publication round running out of
  # another took two different "per-box" locks and measured each other for ten
  # minutes at load 161. Only a fixed path outside the round's own tree is
  # actually one per machine.
  $lockpath = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  try { $script:lockfs = [IO.File]::Open($lockpath, 'CreateNew', 'Write', 'None') }
  catch {
    $who = ''
    try { $who = [IO.File]::ReadAllText($lockpath) } catch { $who = '(unreadable)' }
    "LOCK-BUSY $lockpath held by: $who"
    exit 17
  }
  $txt = "round=$roundname pid=$PID started=$((Get-Date).ToUniversalTime().ToString('o'))"
  $bytes = [Text.Encoding]::ASCII.GetBytes($txt)
  $script:lockfs.Write($bytes, 0, $bytes.Length); $script:lockfs.Flush()
  "RIG-LOCK-TAKEN $lockpath $txt"
}

function Release-RigLock([string]$lockpath) {
  $lockpath = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  if ($script:lockfs) { $script:lockfs.Close(); $script:lockfs = $null }
  Remove-Item $lockpath -Force -ErrorAction SilentlyContinue
  "RIG-LOCK-RELEASED $lockpath"
}

# Run one tool invocation and measure it. Returns rc, wall, child CPU seconds and
# peak working set; stdout and stderr are written to $logbase.out / $logbase.err
# and NEVER discarded, so a refusal cannot be recorded as a fast success.
function Get-OwnPidTree {
  # Our own driver plus everything under it. Without this the guard measures
  # the round's OWN work: Run-Rung hashes all 23 members immediately before
  # calling a leg, so a plain "total processor time" sample catches the tail of
  # our own SHA gate and would abort a clean round.
  $mine = New-Object 'System.Collections.Generic.HashSet[int]'
  $null = $mine.Add($PID)
  try {
    $all = @{}
    Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId -ErrorAction Stop |
      ForEach-Object { $all[[int]$_.ProcessId] = [int]$_.ParentProcessId }
    $grew = $true
    while ($grew) {
      $grew = $false
      foreach ($k in @($all.Keys)) {
        if (-not $mine.Contains($k) -and $mine.Contains($all[$k])) { $null = $mine.Add($k); $grew = $true }
      }
    }
  } catch { }
  # `,` on purpose. PowerShell ENUMERATES a collection on return, so a bare
  # `return $mine` hands the caller an object[] whose .Contains() does not
  # resolve - the call then throws, the catch turns it into -1, and the guard
  # silently measures nothing for the rest of the round.
  return ,$mine
}

function Get-ForeignCpu {
  # CPU seconds consumed OUTSIDE our own process tree over a one second window,
  # expressed as a percentage of one core (so 100 = one core fully busy by
  # somebody else). Returns -1 when it cannot be measured, and the caller then
  # continues rather than blocking a round on a missing counter.
  try {
    $mine = Get-OwnPidTree
    $snap = {
      $h = @{}
      foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        if ($mine.Contains($p.Id)) { continue }
        try { $h[$p.Id] = $p.TotalProcessorTime.TotalSeconds } catch { }
      }
      return ,$h
    }
    $a = & $snap
    Start-Sleep -Milliseconds 1000
    $b = & $snap
    $delta = 0.0
    foreach ($k in $b.Keys) {
      $was = if ($a.ContainsKey($k)) { $a[$k] } else { 0.0 }
      $d = $b[$k] - $was
      if ($d -gt 0) { $delta += $d }
    }
    return [math]::Round($delta * 100.0, 1)
  } catch { return -1.0 }
}

function Require-QuietBox([string]$where) {
  # A leg measured on a box carrying somebody else's work is not slow, it is
  # WRONG, and nothing downstream can tell the difference: the exit code is 0
  # and the SHA gate still passes. The rig lock cannot catch it, because a lock
  # only excludes lanes that agreed to take it. Load can be seen whoever caused
  # it. The ceiling is 10% of the whole box, floored at one core.
  # It WAITS before it gives up. A Defender pass or a Windows Update scan is
  # transient, and killing a twelve hour overnight round over thirty seconds of
  # someone else's CPU trades one kind of lost night for another. Ten retries
  # at thirty seconds, then abort.
  #
  # IT RETURNS NOTHING, AND THE READING COMES BACK IN $script:lastforeign.
  # This function LOGS to the output stream (BOX-BUSY-WAIT has to reach the
  # round log) and PowerShell makes no distinction between logging and
  # returning: a `return $pct` here hands the caller EVERY line the function
  # emitted as well, as an array. On 11 Sep 2026 that put the guard's own wait
  # line inside a LEG line -
  #   foreign_cpu=BOX-BUSY-WAIT try=1 foreign_cpu=343.8 ceiling=160 at=... 59.4
  # - so that leg's `foreign_cpu` field read as the PRE-WAIT spike the guard had
  # just waited out rather than the quiet 59.4 the leg actually ran under, and
  # every field after it on the line was displaced by one. The leg itself was
  # sound; only its record was wrong, which is the worse of the two failures
  # because nothing downstream can see it. jcross.ps1 met the same PowerShell
  # rule twice (its notes on $script:lastwall and Get-StageLabels) and answers
  # it the same way, which is why this is a $script: variable and not a
  # cleverer return.
  $cores = [int]$env:NUMBER_OF_PROCESSORS
  if ($cores -lt 1) { $cores = 1 }
  $ceiling = [math]::Max(100.0, $cores * 100.0 * 0.10)
  $pct = Get-ForeignCpu
  $script:lastforeign = $pct
  if ($pct -lt 0) { return }
  $tries = 0
  while ($pct -ge $ceiling -and $tries -lt 10) {
    $tries++
    "BOX-BUSY-WAIT try=$tries foreign_cpu=$pct ceiling=$ceiling at=$where ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    Start-Sleep -Seconds 30
    $pct = Get-ForeignCpu
    $script:lastforeign = $pct
    if ($pct -lt 0) { return }
  }
  if ($pct -ge $ceiling) {
    $mine = Get-OwnPidTree
    $top = (Get-Process -ErrorAction SilentlyContinue | Where-Object { -not $mine.Contains($_.Id) -and $_.CPU -gt 1 } |
            Sort-Object CPU -Descending | Select-Object -First 4 |
            ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join ' '
    "BOX-BUSY foreign_cpu=$pct ceiling=$ceiling cores=$cores top=[$top]"
    "ABORT-LOAD at=$where ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    exit 18
  }
  $script:lastforeign = $pct
}

function Invoke-Leg {
  # $envExtra overlays the child's environment, for the joint Forney solver
  # ("fast mode"): it ships as a CLI switch AND as NZBFAST_FORNEY_JOINT, default
  # off either way, so an A/B is two arms of the SAME binary and the arms cannot
  # differ by anything but the switch. Optional and last, so every existing
  # caller is unaffected.
  param([string]$exepath, [string]$argstr, [string]$cwd, [string]$logbase,
        [hashtable]$envExtra)
  # Sampled BEFORE the leg. That is necessary and not sufficient: a neighbour
  # that starts mid-leg is invisible to it, and on 11 Sep 2026 a round polled a
  # quiet box during another round's I/O-bound restore phase, read 89% foreign,
  # and then ran its leg alongside that round's next tool. A 19-minute leg is a
  # long window to be blind in, so the reading is taken again AFTER the leg and
  # BOTH travel on the leg line.
  # NOT `$foreign = Require-QuietBox ...`. That captures the guard's log lines
  # along with its reading - see the note in Require-QuietBox.
  Require-QuietBox ([IO.Path]::GetFileName($logbase))
  $foreign = $script:lastforeign
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $exepath
  $psi.Arguments = $argstr
  $psi.WorkingDirectory = $cwd
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  if ($envExtra) { foreach ($k in $envExtra.Keys) { $psi.EnvironmentVariables[$k] = [string]$envExtra[$k] } }
  $proc = New-Object Diagnostics.Process
  $proc.StartInfo = $psi
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $null = $proc.Start()
  $taskout = $proc.StandardOutput.ReadToEndAsync()
  $taskerr = $proc.StandardError.ReadToEndAsync()
  $proc.WaitForExit()
  $watch.Stop()
  $sout = $taskout.Result
  $serr = $taskerr.Result
  $foreignAfter = Get-ForeignCpu
  $peakbytes = [PMem]::PeakWS($proc.Handle)
  $cpusecs = $proc.TotalProcessorTime.TotalSeconds
  $rcode = $proc.ExitCode
  [IO.File]::WriteAllText("$logbase.out", $sout)
  [IO.File]::WriteAllText("$logbase.err", $serr)
  $proc.Dispose()
  New-Object psobject -Property @{
    rc      = $rcode
    wall    = [math]::Round($watch.Elapsed.TotalSeconds, 3)
    cpu     = [math]::Round($cpusecs, 3)
    peakmb  = [math]::Round($peakbytes / 1MB, 1)
    errlen  = $serr.Length
    outlen  = $sout.Length
    # Published on the leg line, not just used for the refusal: a clean leg and
    # a leg that shared the box are identical in wall, rc and the hash gate, so
    # the evidence has to travel WITH the number or a reader cannot check it.
    foreign = $foreign
    foreignAfter = $foreignAfter
  }
}

# Deterministic scattered damage. Picks $mblocks of the set's slices with a
# seeded Fisher-Yates over the GLOBAL slice index and overwrites each with
# seeded pseudo-random bytes, clamped at end of file so a partial final slice is
# not extended. Damage depends only on (dir shape, slice, mblocks, seed), so
# every tool at a rung repairs byte-identical damage.
function Invoke-Damage {
  param([string]$dir, [string[]]$members, [int]$slicesize, [int]$mblocks, [int]$dseed)
  $counts = @(); $lens = @(); $total = 0
  foreach ($nm in $members) {
    $flen = (Get-Item (Join-Path $dir $nm)).Length
    $cnt = [int][math]::Ceiling($flen / $slicesize)
    $counts += $cnt; $lens += $flen; $total += $cnt
  }
  if ($mblocks -gt $total) { throw "damage $mblocks exceeds $total slices" }
  $order = New-Object int[] $total
  for ($i = 0; $i -lt $total; $i++) { $order[$i] = $i }
  $rng = New-Object Random($dseed)
  for ($i = $total - 1; $i -gt 0; $i--) {
    $j = $rng.Next($i + 1)
    $tmp = $order[$i]; $order[$i] = $order[$j]; $order[$j] = $tmp
  }
  # group the picks by member, ascending offset, so each file opens once
  $bymember = @{}
  for ($k = 0; $k -lt $mblocks; $k++) {
    $g = $order[$k]
    $mi = 0
    while ($g -ge $counts[$mi]) { $g -= $counts[$mi]; $mi++ }
    if (-not $bymember.ContainsKey($mi)) { $bymember[$mi] = New-Object Collections.ArrayList }
    $null = $bymember[$mi].Add($g)
  }
  $fill = New-Object byte[] $slicesize
  $frng = New-Object Random($dseed + 1)
  $written = 0
  foreach ($mi in ($bymember.Keys | Sort-Object)) {
    $path = Join-Path $dir $members[$mi]
    $fs = [IO.File]::Open($path, 'Open', 'Write', 'None')
    foreach ($si in ($bymember[$mi] | Sort-Object)) {
      $off = [int64]$si * $slicesize
      $n = [int][math]::Min([int64]$slicesize, $lens[$mi] - $off)
      $frng.NextBytes($fill)
      $null = $fs.Seek($off, 'Begin')
      $fs.Write($fill, 0, $n)
      $written++
    }
    $fs.Close()
  }
  if ($written -ne $mblocks) { throw "damage wrote $written of $mblocks" }
  $written
}

# SHA-256 restoration gate. Never gate on an exit code: MultiPar returns 16 on a
# SUCCESSFUL repair.
function Test-Restored {
  param([string]$dir, [string[]]$members, [hashtable]$gold)
  $good = 0; $bad = New-Object Collections.ArrayList
  foreach ($nm in $members) {
    $h = (Get-FileHash (Join-Path $dir $nm) -Algorithm SHA256).Hash
    if ($h -eq $gold[$nm]) { $good++ } else { $null = $bad.Add($nm) }
  }
  New-Object psobject -Property @{ good = $good; bad = @($bad) }
}

# Put the work directory back to pristine: restore any member that is not
# byte-identical, and delete every file the tools left behind (numbered backups
# are what reached 157 GB in an earlier round).
function Reset-Work {
  param([string]$work, [string]$pristine, [string[]]$members, [string[]]$parfiles, [string[]]$badlist)
  foreach ($nm in $badlist) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
  $wanted = @{}
  foreach ($nm in $members)  { $wanted[$nm] = $true }
  foreach ($nm in $parfiles) { $wanted[$nm] = $true }
  foreach ($f in (Get-ChildItem $work -File)) {
    if (-not $wanted.ContainsKey($f.Name)) { Remove-Item $f.FullName -Force }
  }
  # a tool may also have altered a par2 file; restore the set unconditionally,
  # it is small next to the payload
  foreach ($nm in $parfiles) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
}

function Read-Warm {
  # $names limits the warm to those files. The gate reads every member right
  # before the tool runs, so only the recovery set actually needs warming, and
  # warming the whole work dir instead costs 11.5 GB of reads per leg.
  param([string]$dir, [string[]]$names)
  $buf = New-Object byte[] (8MB)
  $list = if ($names) { $names | ForEach-Object { Join-Path $dir $_ } }
          else { (Get-ChildItem $dir -File) | ForEach-Object { $_.FullName } }
  foreach ($f in $list) {
    if (-not (Test-Path $f)) { continue }
    $fs = New-Object IO.FileStream($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, 1048576, [IO.FileOptions]::SequentialScan)
    while ($fs.Read($buf, 0, $buf.Length) -gt 0) { }
    $fs.Close()
  }
}

function Write-BoxFacts {
  $cpu = Get-CimInstance Win32_Processor
  $os  = Get-CimInstance Win32_OperatingSystem
  $cs  = Get-CimInstance Win32_ComputerSystem
  # Name the drive rather than assume D:. The first Windows box added after
  # intel-i5-10600kf had no D: at all and the round died on its own preflight line,
  # which is a silly way to lose a box.
  $drv = @('D','C') | ForEach-Object { Get-PSDrive -Name $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
  $ram = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
  $free = if ($drv) { "$($drv.Name)free_gb=$([math]::Round($drv.Free/1GB,1))" } else { "free_gb=?" }
  "BOX host=$env:COMPUTERNAME cpu=$($cpu.Name) caption=$($cpu.Caption) cores=$($cpu.NumberOfCores) threads=$($cpu.NumberOfLogicalProcessors) ram_gb=$ram os=$($os.Caption) build=$($os.Version) $free"
}

function Write-BinFacts([string]$bindir, [string[]]$tools) {
  foreach ($nm in $tools) {
    $p = Join-Path $bindir "$nm.exe"
    if (-not (Test-Path $p)) { "PREFLIGHT-FAIL missing $p"; exit 9 }
    # -VV carries parfast's build stamp on the second line. A log that cannot
    # name the source of its own binary is the defect that voided 10 Sep.
    #
    # WRAPPED, and this is not defensive padding: `-VV` is parfast's and turbo's
    # spelling, NOT a universal one. phpar2 answers "Not enough command line
    # arguments" on stderr, which under this file's $ErrorActionPreference =
    # 'Stop' is a TERMINATING error - so adding this stamp line silently killed
    # the seven-tool field round and the verify ladder at the phpar2 entry, two
    # seconds in, while the three-tool ladders were unaffected. A probe for a
    # nicety must not be able to end a round.
    $vv = @()
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $vv = @(& $p -VV 2>&1) } catch { $vv = @() }
    $ErrorActionPreference = $prevEap
    if (-not $vv -or $vv.Count -eq 0) { $vv = @('(no -VV)') }
    $stamp = ($vv | Where-Object { $_ -like 'built from *' } | Select-Object -First 1)
    if (-not $stamp) { $stamp = 'built from ?' }
    "BIN $nm sha256=$((Get-FileHash $p -Algorithm SHA256).Hash.ToLower()) bytes=$((Get-Item $p).Length) version=$($vv[0]) $stamp"
  }
}

# ---------------------------------------------------------------------------
# WHICH CUT OF THE HARNESS PRODUCED THIS ROUND, AND THIS LEG?
# ---------------------------------------------------------------------------
# Until 11 Sep 2026 this file stamped `BIN` and nothing whatsoever about
# ITSELF, so every Windows parfast round - intel-i5-10600kf, intel-core-ultra-9-386h, windows-gaming-pc-b,
# amd-ryzen-9800x3d, which is the largest share of the fleet's parfast rounds - banked
# a log with zero harness provenance in it. `Write-BinFacts` answers "which
# build did this round measure"; nothing answered "which harness measured it".
#
# Two questions, two mechanisms, and neither answers the other.
# `Write-HarnessFacts` is the ROUND-START half: every file the round sources,
# hashed once, in the log the round writes. `Get-RigStamp` is the PER-LEG half,
# ported from the bench rig library's `rig_gen` (TODO 236 item 1, 23 Aug
# 2026), and it exists because a hash taken once at round start CANNOT SEE A
# FILE THAT CHANGES AT LEG 40. That is not hypothetical and it is why this
# landed: on 11 Sep 2026 the deployed harness on intel-i5-10600kf diverged from
# origin/main for about twenty minutes and came back, because a queue owner
# added a refusal gate to the box before it landed in the repo
# (an internal note). **A DRIFT THAT REVERTS
# IS INVISIBLE TO EVERY CHECK THAT RUNS AT A POINT IN TIME** -
# `tools/bench-deploy-check.py` covers every rig box on both platforms since
# 11 Sep, and it still cannot see that, because it runs BEFORE the round. So
# the identity has to travel on the LINE, which is what the throughput farm
# has done since 23 Aug and what cost `funny-lalande-5ab050` four columns
# before it did.
#
# ONE SHA PER FILE, NOT A DIRECTORY DIGEST. The point is to name what RAN, and
# a round sources two files - this library and its driver. A digest over
# `<rig>` would move whenever any of the twenty unrelated scripts beside them
# moved, which is a token nobody would keep reading.
#
# SORTED BY BASENAME, so the value is stable across legs and identical in shape
# to `pdrv.py`'s `rig_stamp` on the unix half: a reader comparing two legs is
# comparing ONE string, which is what lets `jsum.py` and `s2sum.py` refuse a
# fold whose legs came from two different harnesses. Resolve a token with one
# command and no box access:
#
#     git show origin/main:harness/plib.ps1 | shasum -a 256 | cut -c1-16
#
# NO CACHE, DELIBERATELY, and this is the one place the port differs from
# rig-lib.sh (which memoises into `_RIG_GEN`). There a leg is a fresh
# `bench2.sh` process, so a per-process cache is still per-leg; here the driver
# is ONE PowerShell process for the whole round, and a cache would silently
# turn this back into the round-start stamp it exists to complement. Two ~20 KB
# hashes against a leg measured in minutes.

# CAPTURED HERE, AT DOT-SOURCE TIME, and not inside the function: this is the
# one instant at which the automatic variables certainly describe THIS file,
# and a driver is free to change directory afterwards.
$script:harnessfiles = @()
# PLAIN STATEMENTS, not `$x = if (...) {...} elseif (...)`. The expression form
# is legal PowerShell and it is also the form whose parse this Mac cannot check
# - there is no pwsh on the dev box - and a PARSE error here does not degrade a
# round, it kills every Windows round at dot-source time. Nothing clever above
# the level of an assignment belongs at this file's top level.
$script:pliblibpath = $PSCommandPath
if (-not $script:pliblibpath) {
  try { $script:pliblibpath = $MyInvocation.MyCommand.Path } catch { }
}
if ($script:pliblibpath -and
    ([IO.Path]::GetFileName($script:pliblibpath) -ne 'plib.ps1')) {
  # A dot-sourced file shares the caller's scope, and if either automatic
  # variable resolved to the CALLING script rather than to this one the token
  # would still be TRUE - it names whatever it hashed, under that file's own
  # basename, which is rig-lib.sh's honesty rule - but this library itself
  # would go unhashed. Prefer a sibling plib.ps1 when one is actually on disk.
  # That is a Test-Path and not a guess; when it is absent, keep what we have
  # rather than inventing a path, because a confidently wrong generation is
  # worse than a differently-labelled true one.
  $sibling = Join-Path (Split-Path $script:pliblibpath -Parent) 'plib.ps1'
  if (Test-Path -LiteralPath $sibling) { $script:pliblibpath = $sibling }
}

function Get-RigStamp {
  # `<basename>:<sha16>` per harness file, `+`-joined. RE-READ ON EVERY CALL.
  #
  # IT RETURNS ONE STRING AND EMITS NOTHING ELSE, and that is load-bearing
  # rather than style. PowerShell makes no distinction between logging and
  # returning, so a single stray unassigned statement in here would be
  # CONCATENATED INTO THE LEG LINE at the call site and displace every field
  # after `rig=` - which is precisely the defect `Require-QuietBox` above
  # carries a sixteen-line note about, and the one `jcross.ps1` met twice.
  # Every statement below is an assignment, a loop, or consumed by `if`.
  # Nothing here writes to the output stream. Keep it that way.
  #
  # AND IT NEVER THROWS. `$ErrorActionPreference = 'Stop'` at the top of this
  # file makes an unreadable file a TERMINATING error, and a probe for a
  # nicety must not be able to end a round - `Write-BinFacts` learned that the
  # expensive way, by killing the seven-tool field round two seconds in. An
  # unreadable file is STAMPED `unreadable` rather than left off: "this leg
  # could not establish its harness" is a fact a reader wants, and an absent
  # token is indistinguishable from a harness older than this block, which
  # never had one.
  $files = $script:harnessfiles
  if (-not $files -or @($files).Count -eq 0) {
    if ($script:pliblibpath) { $files = @($script:pliblibpath) } else { $files = @() }
  }
  if (-not $files -or @($files).Count -eq 0) { return 'unknown' }
  $parts = @()
  foreach ($f in $files) {
    $nm = 'unknown'
    $sha = 'unreadable'
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
      $nm = [IO.Path]::GetFileName($f)
      $h = Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop
      if ($h -and $h.Hash -and $h.Hash.Length -ge 16) {
        $sha = $h.Hash.ToLower().Substring(0, 16)
      }
    } catch {
      $sha = 'unreadable'
    }
    $ErrorActionPreference = $prevEap
    if (-not $nm) { $nm = 'unknown' }
    # THE FORMAT OPERATOR, NOT "$nm`:$sha". `$name:` is PowerShell's
    # scope-qualified variable syntax ($env:, $script:), so a colon directly
    # after a variable reference inside a double-quoted string does not mean
    # what it reads like.
    $parts += ('{0}:{1}' -f $nm, $sha)
  }
  return ($parts -join '+')
}

function Write-HarnessFacts([string[]]$paths) {
  # Round start. REGISTERS the set as well as printing it, so every LEG line's
  # `Get-RigStamp` re-reads exactly the files these HARNESS lines named. This
  # library adds ITSELF; the caller passes its own `$PSCommandPath` (and
  # anything else it sources).
  $all = @()
  if ($script:pliblibpath) { $all += $script:pliblibpath }
  foreach ($p in $paths) { if ($p) { $all += $p } }
  $seen = @{}
  $uniq = @()
  foreach ($p in $all) {
    $full = $p
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $full = (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { $full = $p }
    $ErrorActionPreference = $prevEap
    if (-not $seen.ContainsKey($full)) { $seen[$full] = $true; $uniq += $full }
  }
  # ONE sort key, built as a string, so the order cannot depend on how this
  # PowerShell version handles a multi-scriptblock Sort-Object.
  $script:harnessfiles = @($uniq | Sort-Object { [IO.Path]::GetFileName($_) + '|' + $_ })
  foreach ($p in $script:harnessfiles) {
    if (-not (Test-Path -LiteralPath $p)) { "PREFLIGHT-FAIL missing $p"; exit 9 }
    $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()
    $len = (Get-Item -LiteralPath $p).Length
    "HARNESS $([IO.Path]::GetFileName($p)) sha256=$h bytes=$len"
  }
  # The token the legs will carry, printed once at round start as well, so a
  # reader who greps the head of a log sees the same string the legs carry
  # instead of composing it from the HARNESS lines by hand.
  "HARNESS-RIG $(Get-RigStamp)"
}

# ---------------------------------------------------------------------------
# Parallel SHA-256 over the members. The serial gate costs ~25 s per leg on this
# box (Comet Lake has no SHA-NI), which is most of a short leg's own wall; six
# runspaces bring it under 6 s. The gate is NOT optional - MultiPar returns exit
# 16 on a successful repair, so an exit code can never stand in for it.
function Test-RestoredFast {
  param([string]$dir, [string[]]$members, [hashtable]$gold, [int]$lanes = 6)
  $pool = [RunspaceFactory]::CreateRunspacePool(1, $lanes)
  $pool.Open()
  $jobs = @()
  foreach ($nm in $members) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript({
      param($p, $n)
      # An 8 MB TransformBlock loop, NOT ComputeHash($stream). ComputeHash reads
      # a stream in 4 KB chunks, so a 10 GiB gate becomes ~2.6 million tiny
      # reads: measured at ~300 s of overhead PER LEG on this box, against
      # ~5 s here. It does not touch a published timing, but it was going to
      # cost this round about seven hours of wall.
      $sha = [Security.Cryptography.SHA256]::Create()
      $fs = New-Object IO.FileStream($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, 1048576, [IO.FileOptions]::SequentialScan)
      $buf = New-Object byte[] (8MB)
      while (($cnt = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $null = $sha.TransformBlock($buf, 0, $cnt, $null, 0) }
      $fs.Close()
      $null = $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
      New-Object psobject -Property @{ name = $n; hash = ([BitConverter]::ToString($sha.Hash).Replace('-','')) }
    }).AddArgument((Join-Path $dir $nm)).AddArgument($nm)
    $jobs += New-Object psobject -Property @{ ps = $ps; handle = $ps.BeginInvoke() }
  }
  $good = 0; $bad = New-Object Collections.ArrayList
  foreach ($j in $jobs) {
    $res = $j.ps.EndInvoke($j.handle)
    $j.ps.Dispose()
    foreach ($r in $res) {
      if ($gold[$r.name] -eq $r.hash) { $good++ } else { $null = $bad.Add($r.name) }
    }
  }
  $pool.Close(); $pool.Dispose()
  New-Object psobject -Property @{ good = $good; bad = @($bad) }
}

# Same loop, single file, for the one-off gold hashes.
function Get-Sha256Fast([string]$path) {
  $sha = [Security.Cryptography.SHA256]::Create()
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, 1048576, [IO.FileOptions]::SequentialScan)
  $buf = New-Object byte[] (8MB)
  while (($cnt = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $null = $sha.TransformBlock($buf, 0, $cnt, $null, 0) }
  $fs.Close()
  $null = $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
  [BitConverter]::ToString($sha.Hash).Replace('-','')
}

# The damage pick list, as data, so a leg can be undone by writing back exactly
# the slices it changed instead of re-copying 10 GiB.
function Get-DamagePicks {
  param([string]$dir, [string[]]$members, [int]$slicesize, [int]$mblocks, [int]$dseed)
  $counts = @(); $lens = @(); $total = 0
  foreach ($nm in $members) {
    $flen = (Get-Item (Join-Path $dir $nm)).Length
    $cnt = [int][math]::Ceiling($flen / $slicesize)
    $counts += $cnt; $lens += $flen; $total += $cnt
  }
  if ($mblocks -gt $total) { throw "damage $mblocks exceeds $total slices" }
  $order = New-Object int[] $total
  for ($i = 0; $i -lt $total; $i++) { $order[$i] = $i }
  $rng = New-Object Random($dseed)
  for ($i = $total - 1; $i -gt 0; $i--) {
    $j = $rng.Next($i + 1)
    $tmp = $order[$i]; $order[$i] = $order[$j]; $order[$j] = $tmp
  }
  $bymember = @{}
  for ($k = 0; $k -lt $mblocks; $k++) {
    $g = $order[$k]; $mi = 0
    while ($g -ge $counts[$mi]) { $g -= $counts[$mi]; $mi++ }
    if (-not $bymember.ContainsKey($mi)) { $bymember[$mi] = New-Object Collections.ArrayList }
    $null = $bymember[$mi].Add($g)
  }
  New-Object psobject -Property @{ bymember = $bymember; lens = $lens; total = $total }
}

function Invoke-DamagePicks {
  param([string]$dir, [string[]]$members, [int]$slicesize, $picks, [int]$dseed)
  $fill = New-Object byte[] $slicesize
  $frng = New-Object Random($dseed + 1)
  $written = 0
  foreach ($mi in ($picks.bymember.Keys | Sort-Object)) {
    $fs = [IO.File]::Open((Join-Path $dir $members[$mi]), 'Open', 'Write', 'None')
    foreach ($si in ($picks.bymember[$mi] | Sort-Object)) {
      $off = [int64]$si * $slicesize
      $n = [int][math]::Min([int64]$slicesize, $picks.lens[$mi] - $off)
      $frng.NextBytes($fill)
      $null = $fs.Seek($off, 'Begin')
      $fs.Write($fill, 0, $n)
      $written++
    }
    $fs.Close()
  }
  $fs = $null
  $written
}

# Write the damaged slices back from pristine. Cheap where a full member copy is
# not: at m=1 this moves 750 KiB where a copy moves 1 GiB. The caller MUST
# re-gate afterwards and fall back to a full copy for anything still wrong -
# a tool is free to have touched something the pick list does not name.
function Restore-Slices {
  param([string]$work, [string]$pristine, [string[]]$members, [int]$slicesize, $picks)
  $buf = New-Object byte[] $slicesize
  foreach ($mi in ($picks.bymember.Keys | Sort-Object)) {
    $nm = $members[$mi]
    $src = [IO.File]::OpenRead((Join-Path $pristine $nm))
    $dst = [IO.File]::Open((Join-Path $work $nm), 'Open', 'Write', 'None')
    foreach ($si in ($picks.bymember[$mi] | Sort-Object)) {
      $off = [int64]$si * $slicesize
      $n = [int][math]::Min([int64]$slicesize, $picks.lens[$mi] - $off)
      $null = $src.Seek($off, 'Begin')
      $got = 0; while ($got -lt $n) { $r = $src.Read($buf, $got, $n - $got); if ($r -le 0) { break }; $got += $r }
      $null = $dst.Seek($off, 'Begin')
      $dst.Write($buf, 0, $got)
    }
    $src.Close(); $dst.Close()
  }
}

function Remove-Strays {
  param([string]$work, [string[]]$members, [string[]]$parfiles)
  $wanted = @{}
  foreach ($nm in $members)  { $wanted[$nm] = $true }
  foreach ($nm in $parfiles) { $wanted[$nm] = $true }
  $n = 0
  foreach ($f in (Get-ChildItem $work -File)) {
    if (-not $wanted.ContainsKey($f.Name)) { Remove-Item $f.FullName -Force; $n++ }
  }
  $n
}
