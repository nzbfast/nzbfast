# cfbuf.ps1 - does a co-tenant's CACHE AND MEMORY FOOTPRINT move `c_f`, at a
# CPU level held fixed? Lane cf-load-term-buffer-and-placement-18sep, on
# intel-i5-10600kf (i5-10600KF, 6c/12t, AVX2 no GFNI = the nibble class).
#
# TWO PHASES IN ONE SITTING, and phase A runs FIRST because it is the decisive
# one and a sitting that dies halfway should die with phase A banked.
#
# PHASE A - THE BUFFER SWEEP (item 1). `harness/../rounds/
# cf-load-term-2026-09-16/loadgen.ps1` defaults to -BufKiB 4096, chosen at the
# site as "a third of" this part's 12 MiB L3 - so the banked +20.0% load
# coefficient was measured against a co-runner that NEVER LEAVES CACHE and is
# close to a pure-ALU spin. The 16 Sep co-tenant that produced the excursion
# this whole campaign is chasing was Adobe's updater, which does file I/O and
# touches far more memory AT THE SAME CPU COST. So the hypothesis under test is
# not "load matters" (measured, +20.0%) but "`foreign_cpu` IS THE WRONG
# INDEPENDENT VARIABLE": it counts a co-tenant's CPU and says nothing about its
# footprint, and the two co-tenants being compared differ in footprint by
# construction.
#
# THE ONLY THING THAT MOVES BETWEEN THE LOADED ARMS IS -BufKiB. Same target
# percent (72), same generator, same access pattern, same everything. 4096 is
# the CONTROL and it is the banked default; 24576 is 2x L3; 98304 is 8x L3.
# Three points rather than one because A MONOTONE RESPONSE IN BUFFER SIZE AT
# FIXED CPU IS MUCH STRONGER EVIDENCE THAN A SINGLE POINT, and it is the same
# legset cost each time. The access pattern is NOT touched - changing stride or
# randomising the walk would move two things at once and break the comparison
# with the banked 4 MiB coefficient, and -BufKiB is precisely the parameter the
# drift census's own check names.
#
# ARM ORDER q1 b4a b24a b96a qm b96b b24b b4b q2 - A MIRROR, and it is
# load-bearing rather than tidy. The two-binary sitting drifted MONOTONICALLY
# 7.6% CPU / 8.2% wall across 40 minutes with nothing changed, and its A-B-B-A
# order is the only reason its result survived; run as two blocks the same legs
# would have reported a 7% difference that did not exist. A mirror cancels a
# linear drift in the MEAN of each buffer's pair. Quiet legsets at BOTH ENDS
# (q1, q2) plus one in the MIDDLE (qm): the load lane's whole -t4 arm was
# withdrawn because its single closing quiet legset did not land back on its
# opening one and it could not then tell drift from effect, and three points
# give a drift CURVE where two give only a gap. qm costs two extra generator
# toggles and is worth them.
#
# PHASE B - PINNED AGAINST UNPINNED AT A NARROW POOL (item 2). The drift census
# found spread falling monotonically as the pool fills the box: 0.0-1.5% at
# -t12 on 12 logical, 0.1-2.6% at -t16 on 24, and 0.3-25.7% at -t4/-t6, with
# all three of its rep counterexamples at -t4. Candidate 2 is that four threads
# on 6c/12t land differently run to run. This box's topology was READ, not
# assumed (GetLogicalProcessorInformation): cores pair as (0,1) (2,3) (4,5)
# (6,7) (8,9) (10,11), so 0x55 is four DISTINCT physical cores and 0xF is four
# threads sharing TWO cores as SMT siblings. Those two masks BRACKET whatever
# an unpinned pool happens to get, which is why both are run rather than one.
#
# COMPARE THE SPREADS, NOT THE LEVELS. Pinning changes the level too - a
# P-core second and an SMT-sibling second buy different work, which is
# wcomb.ps1's own documented rule - and the level is not the question. The
# question is whether an UNPINNED -t4 pool is less REPEATABLE than a pinned
# one. So the unpinned arm runs at the SAME CADENCE inside the SAME block
# (u1 p55a pFa pFb p55b u2), because a spread measured over a 60-minute span
# is not comparable with one measured over 15 minutes, and -Reps 2 gives every
# legset a rep-level spread as well as a legset-level one.
#
# NO CONSTANT MOVES. Not NTT_WINDOW_COMBINE_X86, not any NTT_MIN_MISSING*.
# crates/ is untouched by both phases whatever they find.
#
# THE INSTRUMENT IS PINNED AT 07a24a959 and both hashes were verified against
# the banked round's before staging: plib.ps1 20CB3299332113BD, wcomb.ps1
# 60DED61D70BC4ABD, loadgen.ps1 9698D5DEB71A399D (byte-identical to the banked
# copy). The binary is wcomb-16sep's 8983A55A..., which is origin/main
# 4fedd8b33 - THE SAME SOURCE COMMIT the banked load round built from - so no
# build is paid and no instrument is crossed. Item 3 edits wcomb.ps1 and is
# therefore deliberately NOT in this driver: it runs after these legs, on a new
# instrument, so nothing here is measured on it.
$ErrorActionPreference = 'Stop'
$root    = '<rig>\cfbuf18sep'
$harness = Join-Path $root 'harness'
$gen     = Join-Path $root 'loadgen.ps1'
$genlog  = Join-Path $root 'loadgen.log'
$pidfile = Join-Path $root 'loadgen-pids.txt'
$binsrc  = '<rig>\wcomb-16sep\src\target\release\parfast.exe'
$bin     = Join-Path $root 'parfast.exe'
$binwant = '8983A55A4E260BA395B42D252EC1A421B1F35AB8B789CD3F3191E2E01E8E2C84'
$fixsrc  = '<rig>\wcomb-16sep\fix'
$fix     = Join-Path $root 'fix'
$coord   = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$lane    = 'cf-load-term-buffer-and-placement-18sep'
. (Join-Path $harness 'plib.ps1')

function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" }
function Now() { (Get-Date).ToUniversalTime().ToString('o') }
function Coord([string]$m) {
  try { Add-Content -Path $coord -Value $m -ErrorAction Stop } catch { Say "COORD-WRITE-FAILED $($_.Exception.Message)" }
}

# A CENSUS WIDER THAN Test-BoxFree's, logged before every legset. Claim
# riglock-waiter-blind-to-late-arrivals is open about THIS BOX: a waiter's
# ahead-list is fixed at arm time and the census names parfast, cargo and rustc
# only, so a lane arriving after we start - or any non-cargo tool, an ISCC
# compile, a dotnet build - is invisible twice over, and on 18 Sep a driver
# took this lock INSIDE another lane's claimed window. This cannot PREVENT
# that. What it does is make it VISIBLE AFTERWARDS in my own log, so a cell
# taken under a neighbour is identifiable rather than merely wrong, and it
# names the lock holder so "the lock is free" and "the box is quiet" are two
# separate readings rather than one assumed from the other.
function Census([string]$tag) {
  $h = Get-RigLockHolder
  Say "CENSUS $tag lock_exists=$($h.Exists) lock_held=$($h.Held) lock_text=$($h.Text)"
  $mine = Get-OwnPidTree
  $top = (Get-Process -ErrorAction SilentlyContinue |
          Where-Object { -not $mine.Contains($_.Id) -and $_.CPU -gt 1 } |
          Sort-Object CPU -Descending | Select-Object -First 6 |
          ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join ' '
  Say "CENSUS $tag foreign_cpu=$(Get-ForeignCpu) top=[$top]"
}

Say "CFBUF start root=$root lane=$lane"
foreach ($f in @((Join-Path $harness 'plib.ps1'), (Join-Path $harness 'wcomb.ps1'), $gen)) {
  Say "HARNESS $([IO.Path]::GetFileName($f)) sha256=$((Get-FileHash $f -Algorithm SHA256).Hash.Substring(0,16))"
}

# ---------------------------------------------------------------- setup stage
# The lock covers the binary copy, the fixture copy and the generator selftest.
# All three are box-wide work and none may land on whoever holds the box.
$got = $false
for ($t = 1; $t -le 20 -and -not $got; $t++) {
  Try-TakeRigLock 'cfbuf'
  $got = $script:riglock_taken
  if (-not $got) { Say "RIG-LOCK busy, retry $t in 20s"; Start-Sleep -Seconds 20 }
}
if (-not $got) { Say "CFBUF-FAIL could not take the rig lock"; exit 17 }
$ready = $false
try {
  Coord "CLAIM $(Now) $lane gen=4ddfcf76 (opus5 chip, <user>, apple-m3-ultra-512gb) - TOOK THE BOX for about 2h30. Does a co-tenant's CACHE FOOTPRINT move c_f at a FIXED CPU level? Fifteen legsets on the 64 KiB measure ladder. PHASE A, nine legsets: a SYNTHETIC LOAD I START AND KILL BY PID at a fixed 72 percent of one core, swept over buffer sizes 4 MiB (the banked default, a third of this part's 12 MiB L3), 24 MiB and 96 MiB, mirrored, with quiet legsets at both ends AND in the middle. PHASE B, six legsets, NO load at all: -t4 pinned to 0x55 (four distinct cores) and 0xF (four SMT siblings on two cores) against unpinned, to compare SPREADS. EVERY LOAD GENERATOR CARRIES ITS OWN INTERNAL WALL-CLOCK DEADLINE and stops itself on that instant whether or not my session, shell or ssh still exists; every pid is written to $pidfile AND announced on a line of its own here the moment it starts. Expect total foreign_cpu near 90 percent during the six loaded legsets of phase A and ~18 percent everywhere else - if you see sustained foreign CPU on this box after my DONE line, it is a defect and I want to know. I BUILD NOTHING, INSTALL NOTHING AND STOP NOTHING: Adobe Creative Cloud is already down and I leave it exactly as I found it. I write to no root but <rig>\cfbuf18sep and I delete nothing of anyone else's - wcomb-16sep is NOT mine, I only READ its binary and fixture. Kill by pid, never by pattern."

  Census 'setup'

  if (-not (Test-Path $bin)) {
    Say "BIN copying $binsrc -> $bin"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Copy-Item $binsrc $bin -Force
  }
  $bh = (Get-FileHash $bin -Algorithm SHA256).Hash
  Say "BIN sha256=$bh $bin"
  # HASH-GATED, and a mismatch is fatal rather than a warning: the whole point
  # of reusing wcomb-16sep's binary is that it is 4fedd8b33, the banked round's
  # own source commit. A different binary silently substituted would make every
  # cross-reference in the write-up false while every leg still passed.
  if ($bh -ne $binwant) { Say "CFBUF-FAIL binary hash $bh != $binwant"; exit 9 }

  if (-not (Test-Path (Join-Path $fix 'gold.txt'))) {
    # COPIED, never shared: the legs damage and restore slices under fix\work\,
    # and $fixsrc is another lane's root that three rounds now read. Fixtures go
    # on C: (TLC), never D: (QLC) - MACHINES.md, THE PARFAST RIG PROTOCOL.
    Say "FIXTURE copying $fixsrc -> $fix"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Copy-Item $fixsrc $fix -Recurse -Force
    Say "FIXTURE copied secs=$([math]::Round($sw.Elapsed.TotalSeconds,1))"
  } else { Say "FIXTURE reused $fix" }
  # Windows Search walked a freshly built fixture through half of another
  # lane's round on 16 Sep at ~87% of one core. Excluded by attribute here.
  cmd /c "attrib +I `"$root\*`" /S /D" | Out-Null

  # ------------------------------------------------------- generator selftest
  # AN UNTESTED LOAD GENERATOR IS THE LAST THING THAT SHOULD MEET A SHARED
  # TIMING BOX. This one is byte-identical to the banked round's, which is an
  # argument and not a test: it proves the two things that matter on THIS boot
  # and nothing else - that the closed-loop level control ACHIEVES what it asks
  # (a fixed duty cycle would not; Windows' timer granularity is ~15.6 ms and
  # would silently deliver half), and that the internal deadline KILLS THE
  # PROCESS with nobody helping it. It is run AT THE LARGEST BUFFER, 96 MiB,
  # because that is the untried configuration: a 98,304 KiB allocation that
  # threw would take the phase-A arm this round exists to measure.
  Say "GEN-SELFTEST start buf_kib=98304"
  $tdl = (Get-Date).ToUniversalTime().AddSeconds(45).ToString('o')
  $tp = Start-Process -FilePath 'powershell' -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File', $gen,
        '-TargetPct','50','-DeadlineUtc',$tdl,'-MaxSeconds','90','-BufKiB','98304','-Log',$genlog)
  Add-Content -Path $pidfile -Value "$(Now) GEN-SELFTEST-START pid=$($tp.Id) target_pct=50 buf_kib=98304 deadline=$tdl"
  Start-Sleep -Seconds 20
  Say "GEN-SELFTEST foreign_cpu_with_generator=$(Get-ForeignCpu) (box idles near 18; this 1 s sampler overstates a BIRTH sample by 2-5x on purpose-built evidence, so read it as alive/not-alive)"
  $waited = 0
  while ($waited -lt 60) { Start-Sleep -Seconds 5; $waited += 5; if ($tp.HasExited) { break } }
  $tp.Refresh()
  if (-not $tp.HasExited) {
    Say "GEN-SELFTEST-FAIL pid=$($tp.Id) OUTLIVED ITS OWN DEADLINE - killing it and standing down"
    try { Stop-Process -Id $tp.Id -Force } catch { }
    Coord "RELEASE $(Now) $lane - STANDING DOWN AND RELEASING THE BOX WITHOUT MEASURING. My load generator failed its own selftest at the 96 MiB buffer: it did not die on its internal deadline, and a generator that cannot be trusted to stop itself must not run on a shared timing box. Killed by pid, box is free, no legs ran."
    exit 12
  }
  Say "GEN-SELFTEST ok pid=$($tp.Id) died on its own deadline after $waited s of nobody helping it"
  Add-Content -Path $pidfile -Value "$(Now) GEN-SELFTEST-OK pid=$($tp.Id) self-terminated"
  # The achieved level is the selftest's real product; read it out of the log.
  foreach ($l in (Get-Content $genlog -ErrorAction SilentlyContinue | Select-Object -Last 3)) { Say "GEN-SELFTEST-LOG $l" }
  $ready = $true
} finally { Release-RigLock 'cfbuf' }
if (-not $ready) { exit 9 }

# ------------------------------------------------------------- load generator
function Start-Load([int]$pct, [int]$bufkib, [int]$budgetSecs) {
  # Cleared FIRST. If Start-Process throws, $script:genpid must not still hold
  # the PREVIOUS legset's pid - Windows recycles pids, and a Stop-Process on a
  # stale one is a pattern kill with extra steps.
  $script:genpid = 0
  $deadline = (Get-Date).ToUniversalTime().AddSeconds($budgetSecs).ToString('o')
  $p = Start-Process -FilePath 'powershell' -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File', $gen,
        '-TargetPct', $pct, '-DeadlineUtc', $deadline,
        '-MaxSeconds', ([int]($budgetSecs + 120)), '-BufKiB', $bufkib, '-Log', $genlog)
  Add-Content -Path $pidfile -Value "$(Now) GEN-START pid=$($p.Id) target_pct=$pct buf_kib=$bufkib deadline=$deadline"
  Coord "NOTE $(Now) $lane - LOAD GENERATOR STARTED, pid=$($p.Id), target $pct% of ONE core, buffer $bufkib KiB, INTERNAL HARD DEADLINE $deadline. It stops itself on that instant with nobody helping it; the kill I do afterwards is the belt, that deadline is the braces. KILL IT BY PID if it is in your way: powershell -Command `"Stop-Process -Id $($p.Id) -Force`". Every pid this lane starts is also in $pidfile."
  Say "GEN-START pid=$($p.Id) target_pct=$pct buf_kib=$bufkib deadline=$deadline"
  # THE PID COMES BACK IN $script:genpid, NOT AS A RETURN VALUE. A function's
  # OUTPUT STREAM is its return value in PowerShell, and `Say` above writes to
  # it - so `return $p.Id` hands the caller an ARRAY of every line this
  # function emitted with the pid last, and `Stop-Process -Id <array>` throws.
  # The generator would then outlive the legset with nobody killing it, which
  # is exactly the 10 Sep orphan failure this whole design is built against.
  $script:genpid = $p.Id
}
function Stop-Load([int]$genpid) {
  if ($genpid -le 0) { Say "GEN-STOP skipped, no pid was recorded"; return }
  try { Stop-Process -Id $genpid -Force -ErrorAction Stop; Say "GEN-STOP pid=$genpid kill sent" }
  catch { Say "GEN-STOP pid=$genpid already gone ($($_.Exception.GetType().Name))" }
  Start-Sleep -Seconds 2
  $alive = $false
  try { $null = [Diagnostics.Process]::GetProcessById($genpid); $alive = $true } catch { }
  Add-Content -Path $pidfile -Value "$(Now) GEN-STOP pid=$genpid alive_after=$alive"
  if ($alive) {
    Say "GEN-STOP-FAIL pid=$genpid STILL ALIVE"
    Coord "NOTE $(Now) $lane - LOAD GENERATOR pid=$genpid DID NOT DIE ON A KILL. It carries an internal deadline and will stop itself, but please kill it by pid if you need this box now."
  } else { Say "GEN-STOP pid=$genpid confirmed gone" }
}

# ------------------------------------------------------- ACQUIRE THEN LOAD
# A DEFECT FIX INHERITED FROM cfload.ps1, kept verbatim in shape because the
# defect it fixes is this round's too. The driver releases its own lock after
# setup and wcomb.ps1 takes the lock per invocation, so between legsets this
# lane owns NOTHING - and a generator started before the legset acquires would
# burn 72% of a core across a neighbour's legs for as long as the retry budget
# lasts, with neither lane's logs saying why. So: probe the lock free with NO
# generator alive, release it at once, and only then start the load and go
# straight in. The residual is the sub-second gap between this release and
# wcomb's own CreateNew. IT IS NARROWED TO THAT FLOOR, NOT CLOSED.
function Wait-LockFree([string]$tag, [int]$maxTries = 60) {
  $script:lockfree = $false
  for ($t = 1; $t -le $maxTries; $t++) {
    Try-TakeRigLock 'cfbuf'
    if ($script:riglock_taken) {
      Release-RigLock 'cfbuf'
      Say "LOCKPROBE $tag lock was free on try $t - starting load now"
      $script:lockfree = $true
      return
    }
    Say "LOCKPROBE $tag lock busy, retry $t in 20s (NO generator running)"
    Start-Sleep -Seconds 20
  }
  Say "LOCKPROBE $tag lock never came free in $maxTries tries"
}

# ------------------------------------------------------------------- the plan
$wcomb = Join-Path $harness 'wcomb.ps1'
$fails = @()
function Run-Legset([string]$tag, [string]$extra, [int]$maxTries = 20) {
  # $maxTries IS LOAD-BEARING FOR A LOADED LEGSET and defaults to the quiet
  # value: a loaded legset passes 3, so a lost race costs seconds of somebody
  # else's box rather than minutes. See Wait-LockFree.
  Census $tag
  $out = Join-Path $root "$tag.log"
  $rc = 17
  for ($try = 1; $try -le $maxTries -and $rc -eq 17; $try++) {
    if ($try -gt 1) { Say "LEGSET $tag lock busy, retry $try in 20s"; Start-Sleep -Seconds 20 }
    cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$root`" -Phase measure -Tag $tag -Bin `"$bin`" -NoBuild $extra > `"$out`" 2>`"$root\$tag.err`""
    $rc = $LASTEXITCODE
  }
  $legs = 0
  if (Test-Path $out) { $legs = @(Select-String -Path $out -Pattern '^LEG ').Count }
  Say "LEGSET $tag rc=$rc legs=$legs extra=[$extra] log=$out"
  $script:legrc = $rc   # not `return $rc` - see Start-Load's note on the stream
}

# ===================================================== PHASE A: the buffer sweep
$aExtra = '-Reps 1 -Threads 4,12'
Say "PHASE-A start (buffer sweep at a FIXED 72% of one core; 4096 is the banked control)"
Run-Legset 'q1' $aExtra; if ($script:legrc -ne 0) { $fails += 'q1' }

foreach ($step in @(@('b4a',4096), @('b24a',24576), @('b96a',98304))) {
  $tag = $step[0]; $bk = [int]$step[1]
  Wait-LockFree $tag 60
  if (-not $script:lockfree) { Say "LEGSET $tag SKIPPED - lock never free, NO generator was started"; $fails += $tag; continue }
  Start-Load 72 $bk 1500
  $gp = $script:genpid
  try { Run-Legset $tag $aExtra 3; if ($script:legrc -ne 0) { $fails += $tag } } finally { Stop-Load $gp }
}

Run-Legset 'qm' $aExtra; if ($script:legrc -ne 0) { $fails += 'qm' }

foreach ($step in @(@('b96b',98304), @('b24b',24576), @('b4b',4096))) {
  $tag = $step[0]; $bk = [int]$step[1]
  Wait-LockFree $tag 60
  if (-not $script:lockfree) { Say "LEGSET $tag SKIPPED - lock never free, NO generator was started"; $fails += $tag; continue }
  Start-Load 72 $bk 1500
  $gp = $script:genpid
  try { Run-Legset $tag $aExtra 3; if ($script:legrc -ne 0) { $fails += $tag } } finally { Stop-Load $gp }
}

Run-Legset 'q2' $aExtra; if ($script:legrc -ne 0) { $fails += 'q2' }
Say "PHASE-A done fails=[$($fails -join ',')]"

# A SWEEP FOR ANYTHING OF MINE STILL ALIVE, BETWEEN THE PHASES rather than only
# at the end: phase B is a QUIET measurement and a generator that survived
# phase A would silently make every one of its cells a loaded cell. It reads
# the pid FILE, never a process name - `pkill -f`-shaped cleanup is what
# CLAUDE.md invariants 2 and 2a forbid, and on this box a name matches every
# lane's processes equally.
function Sweep-Leftovers([string]$where) {
  $left = @()
  foreach ($l in (Get-Content $pidfile -ErrorAction SilentlyContinue)) {
    if ($l -match 'GEN-(START|SELFTEST-START) pid=(\d+)') {
      $gp = [int]$Matches[2]
      try { $null = [Diagnostics.Process]::GetProcessById($gp); $left += $gp } catch { }
    }
  }
  if ($left.Count -gt 0) {
    Say "CFBUF-LEFTOVERS at=$where $($left -join ',')"
    foreach ($gp in $left) { try { Stop-Process -Id $gp -Force } catch { } }
    Start-Sleep -Seconds 3
  } else { Say "CFBUF-CLEAN at=$where no generator pid of mine is alive" }
}
Sweep-Leftovers 'between-phases'

# ============================================ PHASE B: pinned against unpinned
# -t4 ONLY and -Reps 2. The -t12 pool is not the question (its spread is
# 0.0-1.5% and the census already calls it a measuring instrument), and -Reps 2
# buys a rep-level spread inside every legset on top of the legset-level one.
# EACH MASK GETS ITS OWN -Label: rowgate.py-shaped reducers group by
# (label, threads), so two masks at one thread count would merge into one table
# and the block would be unreadable. The mask IS stamped on every LEG line, so
# a merged log is recoverable, but wcomb.ps1's header says not to rely on it.
$bExtra = '-Reps 2 -Threads 4'
Say "PHASE-B start (pinned against unpinned at -t4; 0x55 = four DISTINCT cores, 0xF = four SMT siblings on two cores, topology READ from GetLogicalProcessorInformation)"
foreach ($step in @(@('u1',''), @('p55a','0x55'), @('pFa','0xF'), @('pFb','0xF'), @('p55b','0x55'), @('u2',''))) {
  $tag = $step[0]; $mask = $step[1]
  $extra = if ($mask) { "$bExtra -Affinity $mask -Label pin$mask" } else { "$bExtra -Label unpinned" }
  Run-Legset $tag $extra
  if ($script:legrc -ne 0) { $fails += $tag }
}
Say "PHASE-B done"

Sweep-Leftovers 'final'
$back = Get-ForeignCpu
Say "CFBUF foreign_cpu_after=$back"
Census 'final'
if ($fails.Count -gt 0) { Say "CFBUF DONE WITH FAILURES: $($fails -join ',')" } else { Say "CFBUF ALL DONE" }
Coord "DONE $(Now) $lane gen=4ddfcf76 (opus5 chip, <user>, apple-m3-ultra-512gb) - THE BOX IS FREE AND THE RIG LOCK IS RELEASED. Fifteen legsets ran; failures: $(if ($fails.Count) { $fails -join ',' } else { 'none' }). EVERY LOAD GENERATOR THIS LANE STARTED IS DEAD, verified by pid against $pidfile rather than by name, and foreign_cpu reads $back% of one core as I write - the quiet-sitting baseline on this box is ~17-20%. If that number is high, read $pidfile and kill by pid. I built nothing, installed nothing and stopped nothing; Adobe Creative Cloud is as I found it. My root is <rig>\cfbuf18sep and it goes when the numbers are banked. Next lane: the box is yours."
