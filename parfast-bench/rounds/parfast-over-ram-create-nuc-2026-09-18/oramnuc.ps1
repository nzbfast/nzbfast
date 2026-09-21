param(
  [string]$Root    = 'D:\oramnuc-18sep',
  [string]$Tag     = 'oramnuc1',
  [Parameter(Mandatory=$true)][string]$Plan,   # cells: gib:pct:arm:reps ; separated
  [int]$MaxReps    = 2,
  [string]$ParPar  = '<rig>\bin\parpar.exe',
  [switch]$SkipBuild
)
# oramnuc.ps1 - TODO 345, the over-RAM single-file PAR2 CREATE regime on
# intel-i5-10600kf (i5-10600KF, 6c/12t, 63.9 GB, D: Corsair MP400 NVMe), claim
# parfast-over-ram-create-nuc-18sep-r2.
# KEEP THIS FILE PURE ASCII: PowerShell 5.1 reads a BOM-less script as ANSI.
#
# WHY THIS RATHER THAN oramx.ps1. oramx runs FOUR ARMS OF ONE BINARY
# (main/nopre/nomap/fitoff/nobands) and answers "which route is faster". The
# Reddit report this round answers is a COMPETITIVE and CROSS-VERSION
# question - did the fixes that landed for TODO 345 close a gap against
# ParPar - so the arms here are three DIFFERENT parfast builds plus an
# external tool:
#   b3   parfast 1.5.0-beta.3  (506fbc9f7) - has NEITHER the over-RAM
#        map-fit gate (84f5291bf) NOR the band route (1950ec232)
#   b4   parfast 1.5.0-beta.4  (b4971a66e) - has BOTH
#   tip  current origin/main            - beta.4 plus everything since
#   pp   ParPar 0.4.6, the box's existing <rig>\bin\parpar.exe
# b3 is the arm the report's complaint applies to; b4 and tip are what
# shipped after; pp is the comparator. No environment arm is set on any
# parfast leg beyond NZBFAST_REPAIR_TIMING=1: each build takes whatever
# route IT ships, which is the question, and `route=` on the leg line
# records which one it took rather than assuming.
#
# ARM ORDER IS MIRRORED BY REP AND THE REALISED ORDER IS PRINTED, because
# b4 and tip are expected to be CLOSE and that is exactly the case a fixed
# order fabricates a delta in (an internal note
# section 0: a fixed order produced a +4.29% delta between identical arms).
# Pass r walks the plan forward when r is odd and backward when even, and
# an ARM-ORDER line per pass names the sequence that actually ran, which
# that audit's section 6 asks every driver for and almost none do.
#
# WALL IS THE DECIDING METRIC and cpu-seconds travel beside it, per
# memory topic nzbfast-wall-time-is-the-deciding-metric. Load is sampled
# BEFORE and AFTER every leg (load_before/load_after, foreign_cpu/
# foreign_after) because a 15-minute over-RAM leg is a long window to be
# blind in.
$ErrorActionPreference = 'Stop'

$stage = Join-Path $Root 'stage'
$bin   = Join-Path $Root 'bin'
$fix   = Join-Path $Root 'fix'
$logs  = Join-Path $Root "logs\$Tag"
$coord = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$claim = 'parfast-over-ram-create-nuc-18sep-r2'
$gen   = 'ac5bc738'
# plib comes from the TIP tree: the harness is origin/main's, whatever the
# arm's binary is.
$harness = Join-Path $stage 'tip\src\research\harness'
. (Join-Path $harness 'plib.ps1')

$ARMS = @('b3','b4','tip','pp')
$lock = Join-Path $env:USERPROFILE '.parfast-rig.lock'
Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }

function Ts { (Get-Date).ToUniversalTime().ToString('o') }
function Say([string]$m) { "$(Ts) $m" }
function Coord([string]$line) {
  try { Add-Content -Path $coord -Value $line -Encoding UTF8 } catch { Say "COORD-WRITE-FAILED $_" }
}
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
function Get-Delta32([int64]$a, [int64]$b) {
  if ($a -lt 0 -or $b -lt 0) { return -1 }
  $d = $b - $a
  if ($d -lt 0) { $d += 4294967296 }
  return $d
}
function Get-Route([string]$errfile) {
  # WHICH SIDE OF THE ADMISSION GATE THIS LEG TOOK, as a FIELD, copied from
  # oramx.ps1's reader for the same reason: an arm here is a claim about a
  # BUILD, and `route=` is the only thing in the log that checks the build
  # actually behaved as its version implies. route=UNPARSED is loud on
  # purpose and must never be read as "fine" - for the pp arm it is expected
  # (ParPar prints none of these lines) and for a parfast arm it is a failed
  # READING of the leg.
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
      if ($ln -match 'create map refused:') { $mapgate = 'refused' }
    }
  }
  return @($route, $corpus, $mapgate)
}

New-Item -ItemType Directory -Force $logs, $fix, $bin | Out-Null
Set-PlibLog (Join-Path $Root "$Tag.roundlog")

Take-RigLock 'oramnuc'
$claimed = $false
try {
  Coord "CLAIM $(Ts) $claim gen=$gen (opus5 chip, <user>, apple-m3-ultra-512gb worktree sleepy-herschel-34b905) ACCOUNTS=none - TOOK THE BOX, pid=$PID root=$Root. I queued at 16:06:58Z behind codex-parfast-repair-proof4-18sep, which posted DONE at 16:05:57Z; the rig lock was free, no parfast/cargo/rustc process was up and box CPU read 5% when I took it. THE ROUND: TODO 345 over-RAM single-file PAR2 CREATE, a 90 GiB member (1.45x this box's 63.9 GB RAM) at 5% and 15% recovery plus a 24 GiB under-RAM control, FOUR arms - parfast 1.5.0-beta.3 (506fbc9f7, NEITHER the over-RAM map-fit gate NOR the band route), 1.5.0-beta.4 (b4971a66e, both), current origin/main tip, and the box's existing ParPar 0.4.6 - in MIRRORED arm order with the realised order printed per pass. Wall AND cpu-seconds per leg, load and AvailableMBytes either side of every leg. Expect 2.5-3.5 hours including three native cargo release builds (all twelve threads, ~5 min each) and a 96 GB fixture write. I work only under $Root and <rig>\$Tag.log, BUILD only my own trees there, INSTALL nothing, STOP nothing (Adobe Creative Cloud stays as I find it), move NO engine constant, and touch nobody else's root - <rig>\bin\parpar.exe and every fixture outside my root are READ ONLY to me. Kill by pid, never by pattern: my driver is pid=$PID. I will post DONE and release."
  $claimed = $true
  "ROUND tag=$Tag root=$Root claim=$claim gen=$gen maxreps=$MaxReps plan=$Plan start=$(Ts) driver_pid=$PID"
  Write-BoxFacts
  Write-HarnessFacts @($PSCommandPath, (Join-Path $harness 'plib.ps1'))

  # ---- 1. stage and build the three parfast trees -------------------------
  $exe = @{}
  foreach ($a in @('b3','b4','tip')) {
    $src = Join-Path $stage "$a\src"
    $exe[$a] = Join-Path $src 'target\release\parfast.exe'
    if (-not (Test-Path $src)) {
      $tgz = Join-Path $stage "$a.tgz"
      if (-not (Test-Path $tgz)) { Say "ORAMNUC-FAIL no tarball $tgz"; exit 9 }
      $sw = [Diagnostics.Stopwatch]::StartNew()
      New-Item -ItemType Directory -Force (Join-Path $stage $a) | Out-Null
      Push-Location (Join-Path $stage $a)
      cmd /c "tar xzf `"$tgz`"" | Out-Null
      $trc = $LASTEXITCODE
      Pop-Location
      Say "EXTRACT $a rc=$trc secs=$([math]::Round($sw.Elapsed.TotalSeconds,1))"
      if ($trc -ne 0) { Say "ORAMNUC-FAIL extract $a"; exit 9 }
    } else { Say "EXTRACT $a reused $src" }
  }
  # Windows Defender over a cargo target dir is foreign CPU the leg guard
  # would see and cannot attribute. +I marks the tree not-content-indexed;
  # the other lanes on this box do the same.
  cmd /c "attrib +I `"$Root\*`" /S /D" 2>&1 | Out-Null
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  # C: HAS 1.4 GB FREE ON THIS BOX. Every build artefact and every temp file
  # goes to D: for that reason; CARGO_HOME is deliberately LEFT on C: so the
  # already-populated registry cache is reused rather than re-downloaded.
  $env:TMP = Join-Path $Root 'tmp'; $env:TEMP = $env:TMP
  New-Item -ItemType Directory -Force $env:TMP | Out-Null
  if (-not $SkipBuild) {
    foreach ($a in @('b3','b4','tip')) {
      if (Test-Path $exe[$a]) { Say "BUILD $a skipped, binary present"; continue }
      $src = Join-Path $stage "$a\src"
      $bw = [Diagnostics.Stopwatch]::StartNew()
      Push-Location $src
      cmd /c "cargo build --release -p parfast --locked > `"$Root\build-$a.log`" 2>&1"
      $brc = $LASTEXITCODE
      Pop-Location
      Say "BUILD $a rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-$a.log"
      if ($brc -ne 0) { Say "ORAMNUC-FAIL build $a - see $Root\build-$a.log"; exit 9 }
    }
  }
  $exe['pp'] = $ParPar
  foreach ($a in $ARMS) {
    if (-not (Test-Path $exe[$a])) { Say "ORAMNUC-FAIL missing binary for arm $a at $($exe[$a])"; exit 9 }
  }
  $sha = @{}
  foreach ($a in $ARMS) {
    $sha[$a] = (Get-FileHash $exe[$a] -Algorithm SHA256).Hash
    Say "BIN arm=$a sha256=$($sha[$a]) path=$($exe[$a]) len=$((Get-Item $exe[$a]).Length)"
  }
  # THREE IDENTICAL PARFAST BINARIES WOULD MAKE THIS AN A/A AND NOBODY WOULD
  # SEE IT (cfctl-driver.ps1's guard, generalised to three): an extract that
  # landed the same tree twice, or a build that skipped onto a stale artefact,
  # reads exactly like a clean result that found no difference between the
  # versions - which is the headline this round reports.
  foreach ($p in @(@('b3','b4'), @('b3','tip'), @('b4','tip'))) {
    if ($sha[$p[0]] -eq $sha[$p[1]]) {
      Say "ORAMNUC-FAIL arms $($p[0]) and $($p[1]) are byte-identical - this is an A/A, not a cross-version round"; exit 9
    }
  }
  foreach ($a in @('b3','b4','tip')) { Write-BinFacts (Split-Path $exe[$a] -Parent) @('parfast') }
  $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { (& $ParPar --version 2>&1) | ForEach-Object { Say "PARPAR-VERSION $_" } } catch { }
  $ErrorActionPreference = $prevEap

  # ---- 2. parse the plan --------------------------------------------------
  $cells = @()
  foreach ($spec in $Plan.Split(';')) {
    if (-not $spec.Trim()) { continue }
    $f = $spec.Trim().Split(':')
    if ($f.Count -ne 4) { Say "ORAMNUC-FAIL bad cell [$spec] - want gib:pct:arm:reps"; exit 9 }
    if ($ARMS -notcontains $f[2]) { Say "ORAMNUC-FAIL unknown arm [$spec]"; exit 9 }
    $cells += , @([int]$f[0], [int]$f[1], $f[2], [int]$f[3])
  }

  # ---- 3. fixtures --------------------------------------------------------
  # One member per shape, random bytes, written once and KEPT. Random rather
  # than zeros because a compressible payload changes what the disk and the
  # page cache do, which is the whole subject.
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $fbuf = New-Object byte[] (8MB)
  foreach ($gib in @($cells | ForEach-Object { $_[0] } | Select-Object -Unique)) {
    $fname = Join-Path $fix ("f{0}g.bin" -f $gib)
    $want = [int64]$gib * 1073741824
    if ((Test-Path $fname) -and ((Get-Item $fname).Length -eq $want)) {
      Say "FIXTURE gib=$gib reused bytes=$want"
      continue
    }
    $fw = [Diagnostics.Stopwatch]::StartNew()
    $fs = [IO.File]::Create($fname)
    $left = $want
    while ($left -gt 0) {
      $rng.GetBytes($fbuf)
      $take = [int][math]::Min([int64]$fbuf.Length, $left)
      $fs.Write($fbuf, 0, $take)
      $left -= $take
    }
    $fs.Close()
    $secs = [math]::Round($fw.Elapsed.TotalSeconds, 1)
    Say "FIXTURE gib=$gib wrote bytes=$want secs=$secs mbps=$([math]::Round($want/1MB/[math]::Max($secs,0.001),0))"
  }
  # The fixture write is ~96 GB of dirty pages on a QLC drive. Let the box
  # settle before the first timed leg rather than measuring the flush.
  Wait-FixtureSettle

  # ---- 4. the legs --------------------------------------------------------
  $digests = @{}
  $routes  = @{}
  $verified = @{}
  function Run-Leg($c, [int]$rep) {
    $gib = $c[0]; $pcent = $c[1]; $arm = $c[2]
    $names = @(("f{0}g.bin" -f $gib))
    $legtag = "g$gib-r$pcent-$arm-rep$rep"
    $logbase = Join-Path $logs $legtag
    Get-ChildItem $fix -Filter 'k*.par2' -ErrorAction SilentlyContinue | Remove-Item -Force
    $ww = [Diagnostics.Stopwatch]::StartNew()
    Read-Warm $fix $names
    $warm = [math]::Round($ww.Elapsed.TotalSeconds, 1)
    $envx = @{}
    if ($arm -ne 'pp') { $envx['NZBFAST_REPAIR_TIMING'] = '1' }
    # ParPar 0.4.6: -s<n> is an input SLICE COUNT, the same quantity
    # parfast's -b<n> is, and -r<n>% is recovery percent. Memory is left at
    # ParPar's own default on purpose: the report this round answers is a
    # user running both tools as they come.
    $argstr = if ($arm -eq 'pp') { "-s32768 -r$pcent% -o k.par2 $($names -join ' ')" }
              else { "c -q -b32768 -r$pcent k.par2 $($names -join ' ')" }
    $load0 = Get-LoadPct
    Get-IoRaw
    $pr0 = $script:io_pr; $pi0 = $script:io_pi; $dr0 = $script:io_dr; $av0 = $script:io_av
    $out = @(Invoke-Leg $exe[$arm] $argstr $fix $logbase $envx)
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
    # THE DIGEST KEY IS PER SHAPE AND PER TOOL FAMILY, not per shape alone.
    # The three parfast arms must agree byte for byte - that is the identity
    # check every round in this campaign carries. ParPar's set legitimately
    # differs (different creator packet, different volume sizing), so
    # folding it into the same key would report a false identity failure and
    # hide a real one. What ties the two families together is the
    # CROSS-VERIFY below, which proves each family's set describes the same
    # payload, and that is a stronger statement than a hash comparison that
    # was never going to hold.
    $fam = if ($arm -eq 'pp') { 'parpar' } else { 'parfast' }
    $key = "g$gib-r$pcent-$fam"
    if (-not $digests.ContainsKey($key)) { $digests[$key] = @() }
    $digests[$key] += $setsha
    $rkey = "g$gib-r$pcent-$arm"
    if (-not $routes.ContainsKey($rkey)) { $routes[$rkey] = @() }
    $routes[$rkey] += $rt[0]
    $pagereads = Get-Delta32 $pr0 $script:io_pr
    $pagesin = Get-Delta32 $pi0 $script:io_pi
    $diskgb = if ($dr0 -ge 0 -and $script:io_dr -ge 0) { [math]::Round(($script:io_dr - $dr0) / 1GB, 2) } else { -1 }
    "LEG round=$Tag gib=$gib pct=$pcent arm=$arm rep=$rep rc=$($res.rc) wall=$($res.wall) cpu=$($res.cpu) peak_mb=$($res.peakmb) gbps=$([math]::Round($gib * 1.073741824 / [math]::Max($res.wall, 0.001), 3)) route=$($rt[0]) corpus_b=$($rt[1]) mapgate=$($rt[2]) set=$setsha parfiles=$($pars.Count) parbytes=$parbytes warm_s=$warm page_reads=$pagereads pages_in=$pagesin disk_read_gb=$diskgb avail_mb_before=$av0 avail_mb_after=$($script:io_av) load_before=$load0 load_after=$load1 foreign_cpu=$($res.foreign) foreign_after=$($res.foreignAfter) errlen=$($res.errlen) bin_sha=$($sha[$arm].Substring(0,8)) rig=$(Get-RigStamp) ts=$(Ts)"
    if (Test-Path "$logbase.err") {
      # ParPar prints a progress percentage per refresh, thousands of lines on
      # a 90 GiB member, and `-First 60` over that is sixty copies of
      # "Calculating : 0.01%" and none of the lines worth reading. Dropped by
      # SHAPE rather than by arm so a parfast line is never filtered: the
      # pattern is a trailing bare percentage, which no parfast timing line
      # ends in.
      foreach ($ln in (Get-Content "$logbase.err" | Where-Object { $_ -notmatch ':\s+\d+(\.\d+)?%\s*$' } | Select-Object -First 60)) {
        $clean = $ln.Trim()
        if ($clean) { "TIMING leg=$legtag $clean" }
      }
      foreach ($ln in (Get-Content "$logbase.out" -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch ':\s+\d+(\.\d+)?%\s*$' } | Select-Object -Last 12)) {
        $clean = $ln.Trim()
        if ($clean) { "TOOLOUT leg=$legtag $clean" }
      }
    }
    # A NON-ZERO rc FROM ParPar IS A FINDING AND MUST NOT END THE ROUND.
    # The oramx convention this driver copies exits 9 on any rc != 0, which is
    # right when every arm is our own binary: there a refusal recorded as a
    # fast success is the worst outcome. Here the pp arm is a THIRD-PARTY tool
    # on a payload 1.4x the box's RAM, and "ParPar cannot do this shape" is
    # one of the answers the round is for. Exiting on it would throw away
    # every parfast leg queued behind it - at 90 GiB that is cell 12 of 16,
    # so pass 2 and both mirrored reps would go with it. So a pp refusal is
    # logged loudly, the leg keeps its LEG line with its real rc, and the
    # round goes on; a parfast refusal still ends it.
    if ($res.rc -ne 0) {
      if ($arm -eq 'pp') {
        Say "PP-REFUSED leg=$legtag rc=$($res.rc) - RECORDED, round continues; read $logbase.err"
        Get-ChildItem $fix -Filter 'k*.par2' -ErrorAction SilentlyContinue | Remove-Item -Force
        return
      }
      Say "ORAMNUC-FAIL leg rc=$($res.rc) $legtag"; exit 9
    }
    # CROSS-VERIFY, once per (shape, arm): the TIP parfast reads the set this
    # leg just wrote, whichever tool wrote it. For a pp leg that is the only
    # thing in the round that says ParPar's output is a valid PAR2 set over
    # this payload - without it the pp arm is an unchecked wall figure, and a
    # tool that wrote a broken set fast would publish as a win.
    $vkey = "g$gib-r$pcent-$arm"
    if (-not $verified.ContainsKey($vkey)) {
      $verified[$vkey] = $true
      $v = @(Invoke-Leg $exe['tip'] "v -q k.par2" $fix "$logbase-verify" @{})
      $vr = $v | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
      "VERIFY tool=parfast-tip wrote_by=$arm leg=$legtag rc=$($vr.rc) wall=$($vr.wall)"
      if ($vr.rc -ne 0) { Say "ORAMNUC-FAIL cross-verify rc=$($vr.rc) $legtag"; exit 9 }
    }
    Get-ChildItem $fix -Filter 'k*.par2' -ErrorAction SilentlyContinue | Remove-Item -Force
  }

  for ($rep = 1; $rep -le $MaxReps; $rep++) {
    $pass = @($cells | Where-Object { $_[3] -ge $rep })
    if ($pass.Count -eq 0) { continue }
    if ($rep % 2 -eq 0) { [array]::Reverse($pass) }
    # THE REALISED ORDER, PRINTED. an internal note
    # section 0's second finding is that a banked log usually cannot be
    # audited for this defect at all, because the order is a property of the
    # driver and not of the log. This line is that audit's one-line fix.
    "ARM-ORDER rep=$rep arm_order=mirrored-by-rep sequence=$(($pass | ForEach-Object { "g$($_[0])r$($_[1])$($_[2])" }) -join ',')"
    foreach ($c in $pass) { Run-Leg $c $rep }
  }

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
  Release-RigLock $lock
  if ($claimed) {
    Coord "DONE $(Ts) $claim gen=$gen (opus5 chip, <user>, apple-m3-ultra-512gb worktree sleepy-herschel-34b905) - THE BOX IS FREE AND THE RIG LOCK IS RELEASED. Driver pid=$PID has exited; read <rig>\$Tag.log for the verdict and whether every leg finished. NOTHING OF MINE IS LEFT RUNNING: no rig lock, no parfast, no cargo, no load generator (I start none). I BUILT only my own three trees under $Root and INSTALLED nothing; I STOPPED nothing and Adobe Creative Cloud is as I found it; I moved NO engine constant. My root is $Root, about 100 GB of it a fixture, and it goes when the numbers are banked - say so here if you need the space sooner. <rig>\bin\parpar.exe and every other lane's root were READ ONLY to me. Next lane: the box is yours."
  }
}
