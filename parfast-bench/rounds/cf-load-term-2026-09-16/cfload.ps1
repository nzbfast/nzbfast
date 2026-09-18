# cfload.ps1 - the LOAD TERM on the i5 nibble `c_f`, and the third binary the
# two-binary control could not run. Lane parfast-load-term-and-third-binary-i5,
# on intel-i5-10600kf (i5-10600KF, 6c/12t, AVX2 no GFNI = the nibble class).
#
# ONE sitting, ONE binary, ONE fixture. `wcomb.ps1 -Phase measure` at 64 KiB,
# -Threads 4,12, rungs at the phase default 192,512,1024,2048,4096.
#
# THE BINARY IS 4fedd8b33 AND THAT IS NOT AN ARBITRARY PICK. The 16 Sep
# two-binary control compared 87ee76638 (A) against origin/main ffca5a7de (B)
# and found them within 2.3%, but the hypothesis it was testing named
# 87ee76638 against 4fedd8b33 - so a regression that landed BY 4fedd8b33 and
# was reverted before ffca5a7de would have passed that control unseen. That
# residual was closed by reading five diffstats, which is a good argument and
# is still an argument. This round needs a binary anyway, so it uses THAT one,
# and its quiet cells read against the banked A and B turn the argument into a
# measurement for free.
#
# THE ARM ORDER IS Q, Q, L, L, L, L, Q' AND IT IS DELIBERATELY NOT A-B-B-A.
# A-B-B-A is the right instrument when both arms are free to interleave. Here
# one arm requires a load generator to be RUNNING, and every toggle of a load
# generator is another chance to leave one alive on a shared timing box - the
# exact failure that cost this repo a whole day of numbers on 10 Sep 2026
# (memory topic `nzbfast-orphaned-load-generators-skew-a-whole-day`). So the
# loaded legsets are contiguous and the mirror lives INSIDE them (90,50,50,90),
# where it costs no extra toggles.
#
# Q' IS NOT PADDING. It is the only thing that can separate "the generator
# moved the number" from "something else moved during the sitting". If Q' does
# not land back on Q, the L cells are not interpretable and the write-up says
# so rather than quoting a ratio.
#
# THE TWO LOAD LEVELS ARE CHOSEN AGAINST THE TOTAL, NOT THE ADDITION, and that
# is the one arithmetic point in this round that is easy to get wrong. The
# quantity the three-sitting correlation is stated in is each sitting's median
# `foreign_cpu` - the WHOLE box's foreign CPU, not a generator's share - and
# those were 14% (14 Sep), 17-20% (the two-binary control) and 69% (16 Sep).
# This box idles near 18% with Adobe Creative Cloud stopped, so a generator
# asking 72% lands total foreign near 90% and one asking 32% lands it near 50%.
# The pair BRACKETS the 69% that actually needs explaining instead of aiming at
# it and missing on one side. Nothing is assumed: every leg records its own
# `foreign_cpu` and THAT is the independent variable the write-up reports.
#
# THE QUIET-BOX GUARD'S CEILING IS WHY 72 IS THE TOP LEVEL AND NOT 70-ON-TOP.
# plib.ps1's Require-QuietBox aborts a leg (exit 18) above max(100, cores*10)
# = 120% of one core on this 12-logical-CPU box, after ten 30 s waits. Total
# foreign near 90% sits under that with ~30 points of headroom for a Defender
# or Windows Search spike; 0.7 of a core added to the 16 Sep baseline would
# not have. A legset that trips it anyway is recorded and the round CONTINUES -
# see $fails below - because killing the generator and running Q' matters more
# than any single legset.
$ErrorActionPreference = 'Stop'
$root    = '<rig>\cfload16sep'
$src     = Join-Path $root 'src'
$bin     = Join-Path $src 'target\release\parfast.exe'
$tarball = Join-Path $root 'src-4fedd8b33.tar.gz'
$fixsrc  = '<rig>\wcomb-16sep\fix'
$harness = Join-Path $root 'harness'
$gen     = Join-Path $root 'loadgen.ps1'
$genlog  = Join-Path $root 'loadgen.log'
$pidfile = Join-Path $root 'loadgen-pids.txt'
$coord   = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$lane    = 'parfast-load-term-and-third-binary-i5'
# THE HARNESS IS STAGED BESIDE THE ROUND, NOT TAKEN OUT OF $src. $src is the
# 4fedd8b33 tree and its research\harness is two days stale; the measurement
# has to be made by the SAME harness the banked cells were made by, or the
# comparison is between two instruments as well as two sittings. These two
# files are origin/main's at launch and their hashes are logged below.
. (Join-Path $harness 'plib.ps1')

function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" }
function Coord([string]$m) {
  try { Add-Content -Path $coord -Value $m -ErrorAction Stop } catch { Say "COORD-WRITE-FAILED $($_.Exception.Message)" }
}
function Now() { (Get-Date).ToUniversalTime().ToString('o') }

Say "CFLOAD start root=$root lane=$lane"
foreach ($f in @((Join-Path $harness 'plib.ps1'), (Join-Path $harness 'wcomb.ps1'), $gen)) {
  Say "HARNESS $([IO.Path]::GetFileName($f)) sha256=$((Get-FileHash $f -Algorithm SHA256).Hash.Substring(0,16))"
}

# ---------------------------------------------------------------- build stage
# The lock covers the extract, the fixture copy, the build AND the generator
# selftest. All four are box-wide work and none of them may land on whoever
# holds the box otherwise. Try-TakeRigLock rather than Take-RigLock: the latter
# `exit 17`s on a busy box, and this driver is launched into a queue it may
# reach a few seconds early. Twenty tries at 20 s is ~7 minutes of patience and
# then a clean refusal that has changed nothing.
$got = $false
for ($t = 1; $t -le 20 -and -not $got; $t++) {
  Try-TakeRigLock 'cfload'
  $got = $script:riglock_taken
  if (-not $got) { Say "RIG-LOCK busy, retry $t in 20s"; Start-Sleep -Seconds 20 }
}
if (-not $got) { Say "CFLOAD-FAIL could not take the rig lock"; exit 17 }
$ready = $false
try {
  Coord "CLAIM $(Now) $lane (opus5 chip, <user>, apple-m3-ultra-512gb) - TOOK THE BOX. The load term on c_f plus the third binary 4fedd8b33 the two-binary control could not run. 64 KiB measure ladder, -Threads 4,12, SEVEN legsets: two quiet, four under a SYNTHETIC LOAD I START AND KILL BY PID, one quiet again to prove the box came back. THE LOAD GENERATOR CARRIES ITS OWN INTERNAL WALL-CLOCK DEADLINE and stops itself on that instant whether or not my session, shell or ssh still exists; every pid it runs under is written to $pidfile AND announced on a line of its own in this file the moment it starts. Expect total foreign_cpu near 90% and near 50% during the four loaded legsets and ~18% either side of them - if you see sustained foreign CPU on this box after my DONE line, it is a defect and I want to know. ETA ~70 min."

  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) {
    Say "EXTRACT $tarball -> $src"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    New-Item -ItemType Directory -Force -Path $src | Out-Null
    cmd /c "tar -xzf `"$tarball`" -C `"$src`"" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Say "CFLOAD-FAIL extract rc=$LASTEXITCODE"; exit 9 }
    Say "EXTRACT done secs=$([math]::Round($sw.Elapsed.TotalSeconds,1))"
  } else { Say "EXTRACT skipped, $src already carries a tree" }

  $fix = Join-Path $root 'fix'
  if (-not (Test-Path (Join-Path $fix 'gold.txt'))) {
    # COPIED, never shared and never rebuilt: the legs write into fix\work\ and
    # $fixsrc is nibble-block-size-row-gate-16sep's root, which three lanes are
    # now on record asking not to be disturbed. Fixtures go on C: (TLC), never
    # D: (QLC) - MACHINES.md, THE PARFAST RIG PROTOCOL ON THIS BOX: D: has 30x
    # the free space and is the wrong answer every time.
    Say "FIXTURE copying $fixsrc -> $fix"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Copy-Item $fixsrc $fix -Recurse -Force
    Say "FIXTURE copied secs=$([math]::Round($sw.Elapsed.TotalSeconds,1))"
  } else { Say "FIXTURE reused $fix" }
  # Windows Search walked a freshly built fixture through half of another
  # lane's round on 16 Sep at ~87% of one core. Excluded by attribute here.
  cmd /c "attrib +I `"$root\*`" /S /D" | Out-Null

  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  if (Test-Path $bin) { Say "BUILD skipped, binary present" }
  else {
    $bw = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $src
    cmd /c "cargo build --release -p parfast --locked > `"$root\build.log`" 2>&1"
    $brc = $LASTEXITCODE
    Pop-Location
    Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$root\build.log"
    if ($brc -ne 0) { Say "CFLOAD-FAIL build"; exit 9 }
  }
  Say "BIN sha256=$((Get-FileHash $bin -Algorithm SHA256).Hash) $bin"

  # ------------------------------------------------------- generator selftest
  # AN UNTESTED LOAD GENERATOR IS THE LAST THING THAT SHOULD MEET A SHARED
  # TIMING BOX, and there was nowhere safe to rehearse it: intel-i5-10600kf was five
  # lanes deep all afternoon and intel-core-ultra-9-386h was holding its own rig lock with
  # a live parfast, so a 60-second co-runner on either would have been the very
  # contamination this round exists to measure. Under our own lock it is free.
  # It proves the two things that matter and nothing else: that the level
  # control ACHIEVES what it asks for (a fixed duty cycle would not - Windows'
  # default timer granularity is ~15.6 ms and would silently deliver half), and
  # that the internal deadline KILLS THE PROCESS with nobody helping it.
  Say "GEN-SELFTEST start"
  $tdl = (Get-Date).ToUniversalTime().AddSeconds(45).ToString('o')
  $tp = Start-Process -FilePath 'powershell' -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File', $gen,
        '-TargetPct','50','-DeadlineUtc',$tdl,'-MaxSeconds','90','-Log',$genlog)
  Add-Content -Path $pidfile -Value "$(Now) GEN-SELFTEST-START pid=$($tp.Id) target_pct=50 deadline=$tdl"
  Start-Sleep -Seconds 20
  $seen = Get-ForeignCpu
  Say "GEN-SELFTEST foreign_cpu_with_generator=$seen (box idles near 18)"
  # 45 s deadline + up to 2 s of loop slack. Nothing kills it here ON PURPOSE.
  $waited = 0
  while ($waited -lt 60) { Start-Sleep -Seconds 5; $waited += 5; if ($tp.HasExited) { break } }
  $tp.Refresh()
  if (-not $tp.HasExited) {
    Say "GEN-SELFTEST-FAIL pid=$($tp.Id) OUTLIVED ITS OWN DEADLINE - killing it and standing down"
    try { Stop-Process -Id $tp.Id -Force } catch { }
    Coord "RELEASE $(Now) $lane (opus5 chip, <user>, apple-m3-ultra-512gb) - STANDING DOWN AND RELEASING THE BOX WITHOUT MEASURING. My load generator failed its own selftest: it did not die on its internal deadline, and a generator that cannot be trusted to stop itself must not be run on a shared timing box at all. Killed by pid, box is free, no legs ran. The quiet arm is worth running on its own and another lane may have it."
    exit 12
  }
  Say "GEN-SELFTEST ok pid=$($tp.Id) died on its own deadline after $waited s of nobody helping it"
  Add-Content -Path $pidfile -Value "$(Now) GEN-SELFTEST-OK pid=$($tp.Id) self-terminated"
  $ready = $true
} finally { Release-RigLock 'cfload' }
if (-not $ready) { exit 9 }

# ------------------------------------------------------------- load generator
function Start-Load([int]$pct, [int]$budgetSecs) {
  # Cleared FIRST. If Start-Process throws, $script:genpid must not still hold
  # the PREVIOUS legset's pid - Windows recycles pids, and a Stop-Process on a
  # stale one is a pattern kill with extra steps.
  $script:genpid = 0
  $deadline = (Get-Date).ToUniversalTime().AddSeconds($budgetSecs).ToString('o')
  $p = Start-Process -FilePath 'powershell' -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File', $gen,
        '-TargetPct', $pct, '-DeadlineUtc', $deadline,
        '-MaxSeconds', ([int]($budgetSecs + 120)), '-Log', $genlog)
  Add-Content -Path $pidfile -Value "$(Now) GEN-START pid=$($p.Id) target_pct=$pct deadline=$deadline"
  Coord "NOTE $(Now) $lane (opus5 chip, <user>, apple-m3-ultra-512gb) - LOAD GENERATOR STARTED, pid=$($p.Id), target $pct% of ONE core, INTERNAL HARD DEADLINE $deadline. It stops itself on that instant with nobody helping it; the kill I do afterwards is the belt, that deadline is the braces. KILL IT BY PID if it is in your way: powershell -Command `"Stop-Process -Id $($p.Id) -Force`". Every pid this lane starts is also in $pidfile."
  Say "GEN-START pid=$($p.Id) target_pct=$pct deadline=$deadline"
  # THE PID COMES BACK IN $script:genpid, NOT AS A RETURN VALUE, and this is
  # the same PowerShell rule plib.ps1's Require-QuietBox carries a paragraph
  # about. A function's OUTPUT STREAM is its return value: `Say` above writes
  # to that stream, so `return $p.Id` hands the caller an ARRAY of every line
  # this function emitted with the pid last. `Stop-Process -Id <array>` then
  # throws - and the generator this function just started would outlive the
  # legset with nobody killing it, which is precisely the failure mode this
  # whole round is built to avoid.
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
# WHY THIS FUNCTION EXISTS, and it is a DEFECT FIX rather than a refinement.
# As first staged, the loaded legsets called Start-Load BEFORE Run-Legset
# acquired the rig lock, and Run-Legset retried a busy lock 20 times at 20 s.
# The driver releases its own lock after the build block and wcomb.ps1 takes
# the lock per invocation, so in that window this lane owns nothing - and any
# neighbour that took the box by doing exactly what the protocol tells waiters
# to do (free twice, 60 s apart) would have had 72% of a core burned across
# its legs for up to SEVEN MINUTES, with neither lane's logs saying why.
#
# That is the 10 Sep orphan incident's failure class in a subtler dress: not a
# generator that outlives its killer, but a generator alive while this lane is
# not the box's owner. The internal deadlines do not help - the generator is
# behaving exactly as designed for 1,500 s.
#
# cfctl-driver.ps1 cannot be copied from here. Its header reasons that its four
# wcomb holds are "BACK TO BACK, sub-second apart, which cannot be sampled as
# the free twice, 60 s apart every waiter on this box requires" - true, and
# true ONLY because nothing of its own runs in the gap. This round puts a load
# generator in that gap.
#
# So: probe the lock to free with NO generator running, release it immediately,
# and only then start the load and go straight into the legset. The residual is
# the sub-second gap between this release and wcomb's own CreateNew, which is
# the same documented floor cfctl already accepts. IT IS NARROWED TO THAT
# FLOOR, NOT CLOSED, and the write-up must say so rather than claim it is safe.
function Wait-LockFree([string]$tag, [int]$maxTries = 60) {
  # Result in $script:lockfree, never a return value - the same PowerShell
  # output-stream rule Try-TakeRigLock's own header spells out at length.
  $script:lockfree = $false
  for ($t = 1; $t -le $maxTries; $t++) {
    Try-TakeRigLock 'cfload'
    if ($script:riglock_taken) {
      Release-RigLock 'cfload'
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
function Run-Legset([string]$tag, [int]$maxTries = 20) {
  # $maxTries IS LOAD-BEARING FOR THE LOADED LEGSETS and defaults to the quiet
  # value. A loaded legset passes 3: see Wait-LockFree below for why a long
  # retry here is the one thing this round must not do.
  $out = Join-Path $root "$tag.log"
  $rc = 17
  for ($try = 1; $try -le $maxTries -and $rc -eq 17; $try++) {
    if ($try -gt 1) { Say "LEGSET $tag lock busy, retry $try in 20s"; Start-Sleep -Seconds 20 }
    cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$root`" -Phase measure -Tag $tag -Bin `"$bin`" -NoBuild -Reps 1 -Threads 4,12 > `"$out`" 2>`"$root\$tag.err`""
    $rc = $LASTEXITCODE
  }
  $legs = 0
  if (Test-Path $out) { $legs = @(Select-String -Path $out -Pattern '^LEG ').Count }
  Say "LEGSET $tag rc=$rc legs=$legs log=$out"
  $script:legrc = $rc   # not `return $rc` - see Start-Load's note on the stream
}

$fails = @()
foreach ($tag in @('q1','q2')) { Run-Legset $tag; if ($script:legrc -ne 0) { $fails += $tag } }

foreach ($step in @(@('l90a',72), @('l50a',32), @('l50b',32), @('l90b',72))) {
  $tag = $step[0]; $pct = $step[1]
  # ACQUIRE THEN LOAD. The probe runs with no generator alive; only once the
  # box has answered free do we start one, and then the legset gets a SHORT
  # retry budget so a lost race costs seconds rather than minutes.
  Wait-LockFree $tag 60
  if (-not $script:lockfree) {
    Say "LEGSET $tag SKIPPED - lock never free, NO generator was started"
    $fails += $tag
    continue
  }
  Start-Load $pct 1500
  $genpid = $script:genpid
  try { Run-Legset $tag 3; if ($script:legrc -ne 0) { $fails += $tag } }
  finally { Stop-Load $genpid }
}

# Q' - the proof the box came back. It runs LAST and it runs whatever happened
# above.
Run-Legset 'qp'
if ($script:legrc -ne 0) { $fails += 'qp' }

# A final, independent sweep for anything of mine still alive. It reads the pid
# FILE, never a process name: `pkill -f`-shaped cleanup is what CLAUDE.md
# invariants 2 and 2a forbid, and on this box a name matches every lane's
# processes equally.
$leftovers = @()
foreach ($l in (Get-Content $pidfile -ErrorAction SilentlyContinue)) {
  if ($l -match 'GEN-(START|SELFTEST-START) pid=(\d+)') {
    $gp = [int]$Matches[2]
    try { $null = [Diagnostics.Process]::GetProcessById($gp); $leftovers += $gp } catch { }
  }
}
if ($leftovers.Count -gt 0) {
  Say "CFLOAD-LEFTOVERS $($leftovers -join ',')"
  foreach ($gp in $leftovers) { try { Stop-Process -Id $gp -Force } catch { } }
  Start-Sleep -Seconds 3
} else { Say "CFLOAD-CLEAN no generator pid of mine is alive" }
$back = Get-ForeignCpu
Say "CFLOAD foreign_cpu_after=$back"
if ($fails.Count -gt 0) { Say "CFLOAD DONE WITH FAILURES: $($fails -join ',')" } else { Say "CFLOAD ALL DONE" }
Coord "DONE $(Now) $lane (opus5 chip, <user>, apple-m3-ultra-512gb) - THE BOX IS FREE AND THE RIG LOCK IS RELEASED. Seven legsets ran; failures: $(if ($fails.Count) { $fails -join ',' } else { 'none' }). EVERY LOAD GENERATOR THIS LANE STARTED IS DEAD, verified by pid against $pidfile rather than by name, and foreign_cpu reads $back% of one core as I write - the quiet-sitting baseline on this box is ~17-20%. If that number is high, read $pidfile and kill by pid. Next lane: the box is yours."
