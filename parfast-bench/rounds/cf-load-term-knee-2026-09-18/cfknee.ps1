# cfknee.ps1 - WHERE IN 17-48% OF A CORE DOES THE `c_f` LOAD TERM TURN ON?
# Lane cf-load-term-knee-rung-18sep, gen cde69af2, on intel-i5-10600kf (i5-10600KF,
# 6c/12t, AVX2 no GFNI = the nibble class).
#
# THE OWED ITEM. The banked load round measured `c_f` at three total
# `foreign_cpu` levels and no more: 17% (reference), 48% (+8.7% at -t12) and
# 83% (+20.0%). Per point of foreign CPU those two steps read 0.28% and 0.30%,
# which the round reported as "close to linear" - but a straight line through
# two points that both sit ABOVE 48 cannot distinguish a response that is
# linear from the baseline from one with a THRESHOLD somewhere inside the
# 31-point gap it never sampled. The knee is BRACKETED, not located, and the
# 18 Sep buffer round left the rung owed with that wording.
#
# THE WHOLE JOB IS ONE MORE GENERATOR LEVEL. An ask of 10% of one core on a box
# idling near 18-19 lands total `foreign_cpu` near 29 - INSIDE the gap and
# roughly at its lower third, where a threshold would most plausibly sit.
# Predictions, fixed here before any leg runs:
#   LINEAR from the baseline  -> c_f at ~29 reads about +3.4% over quiet.
#   A THRESHOLD above ~29     -> it reads ~0%, inside the noise floor.
#   CONVEX / front-loaded     -> it reads well above +3.4%.
# All three are distinguishable only because the noise floor is measured in the
# same sitting rather than assumed (q1/qm/q2 below).
#
# -BufKiB 4096 ON EVERY LOADED LEGSET, AND IT IS THE POINT OF THE ROUND RATHER
# THAN A DEFAULT LEFT ALONE. The three banked points (17/48/83) were ALL taken
# with loadgen.ps1's default 4096, and the 18 Sep buffer round then found that
# a co-tenant whose working set LEAVES this part's 12 MiB L3 moves `c_f` 1.44x
# more per point of foreign CPU than one that fits inside it. So buffer size is
# a second free parameter of every one of those figures, and a new point taken
# at a different buffer is NOT ON THE SAME CURVE as the ones whose knee it is
# supposed to locate. 4096 is therefore stated, held fixed, and stated again in
# the write-up.
#
# IT IS ALSO WHY THIS RUNG MAY NOT BE BOUGHT OFF A BOX WITH A STANDING
# CO-TENANT, which is the cheap answer. amd-ryzen-9800x3d idles at `foreign_cpu` ~42-55
# from SignalRgb, squarely in the gap and free for the taking - but NOTHING IS
# KNOWN ABOUT ITS FOOTPRINT, so a knee located against it is a knee in
# SignalRgb's own coefficient wearing the load term's name. It is also a Zen 5
# part with AVX-512 and GFNI, not the nibble class, so no `c_f` from it is
# comparable with any banked cell here at all. The rung is a GENERATOR LEVEL on
# THIS box.
#
# ARM ORDER q1 g10a g72a qm g72b g10b q2 - A MIRROR, with quiet legsets at BOTH
# ENDS and one in the MIDDLE. The load lane's whole -t4 arm was WITHDRAWN
# because its single closing quiet legset did not land back on its opening one
# (+6.8%), and it could not then tell drift from effect. Three quiet points
# give a drift CURVE where two give only a gap; a mirror cancels a linear drift
# in the MEAN of each level's pair. The 18 Sep sitting passed the same check at
# +0.0% CPU and +0.3% wall; that is its result, not a property of the box, and
# this round assumes nothing from it.
#
# WHY g72 IS HERE AT ALL, when the banked round already has 83 and the buffer
# round already replicated 4 MiB at ~88. Because splicing is the failure mode
# this campaign keeps finding: the two segments 17->29 and 29->48 have to be
# compared LIKE FOR LIKE, and a segment whose endpoints come from two sittings
# with two baselines is not that. Running the high level HERE puts quiet (~19),
# ~29 and ~88 in ONE sitting against ONE baseline on ONE instrument, so the
# per-point figures are internally comparable and the 4 MiB coefficient
# replicates for a THIRD time as a by-product. It costs two legsets, ~14 min.
#
# EQUAL-n. Three quiet legsets against two per load level, and
# `wcombsum.best()` takes a MINIMUM, so a three-legset unit sits LOW for no
# reason but the extra draw and would INFLATE every ratio here. The reduction
# therefore passes EVERY LEGSET AS ITS OWN UNIT to cfdriftsum.py and compares
# MEANS of per-legset fits, which is free of the bias entirely. Do not reduce
# this round by pooling q1+qm+q2 into one baseline unit against a two-legset
# load arm.
#
# NO CONSTANT MOVES. Not NTT_WINDOW_COMBINE_X86, not any NTT_MIN_MISSING*.
# crates/ is untouched by this round whatever it finds, and no coefficient
# measured here is a correction factor for any banked cell - the buffer round's
# 1.44x is the argument for that and it applies to this round's own numbers.
#
# THE INSTRUMENT IS PINNED AT 07a24a959, hashes verified against the banked
# round's before staging: plib.ps1 20CB3299332113BD, wcomb.ps1 60DED61D70BC4ABD,
# loadgen.ps1 9698D5DEB71A399D (byte-identical to the banked copy). The binary
# is wcomb-16sep's 8983A55A..., origin/main 4fedd8b33, THE SAME SOURCE COMMIT
# the banked load round built from. origin/main's harness has since gained
# per-leg frequency and thermal fields, which makes it a DIFFERENT INSTRUMENT
# from the one every cell here is read against. `foreign_cpu` is consequently
# the PRE-9686ac296 definition: comparable with the banked cells and with
# nothing taken after that commit.
$ErrorActionPreference = 'Stop'
$root    = '<rig>\cfknee18sep'
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
$lane    = 'cf-load-term-knee-rung-18sep'
. (Join-Path $harness 'plib.ps1')

function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" }
function Now() { (Get-Date).ToUniversalTime().ToString('o') }
function Coord([string]$m) {
  try { Add-Content -Path $coord -Value $m -ErrorAction Stop } catch { Say "COORD-WRITE-FAILED $($_.Exception.Message)" }
}

# A CENSUS WIDER THAN Test-BoxFree's, logged before every legset. Claim
# riglock-waiter-blind-to-late-arrivals is open about THIS BOX: a waiter's
# ahead-list is fixed at arm time and the census names parfast, cargo and rustc
# only, so a lane arriving after we start - or any non-cargo tool - is
# invisible twice over. This cannot PREVENT that. What it does is make it
# VISIBLE AFTERWARDS in my own log, so a cell taken under a neighbour is
# identifiable rather than merely wrong, and it names the lock holder so "the
# lock is free" and "the box is quiet" are two separate readings rather than
# one assumed from the other. On a round whose whole subject is foreign CPU,
# an unnoticed neighbour would not merely add noise - it would move the
# independent variable.
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

Say "CFKNEE start root=$root lane=$lane"
foreach ($f in @((Join-Path $harness 'plib.ps1'), (Join-Path $harness 'wcomb.ps1'), $gen)) {
  Say "HARNESS $([IO.Path]::GetFileName($f)) sha256=$((Get-FileHash $f -Algorithm SHA256).Hash.Substring(0,16))"
}

# ---------------------------------------------------------------- setup stage
# The lock covers the binary copy, the fixture copy and the generator selftest.
# All three are box-wide work and none may land on whoever holds the box.
$got = $false
for ($t = 1; $t -le 20 -and -not $got; $t++) {
  Try-TakeRigLock 'cfknee'
  $got = $script:riglock_taken
  if (-not $got) { Say "RIG-LOCK busy, retry $t in 20s"; Start-Sleep -Seconds 20 }
}
if (-not $got) { Say "CFKNEE-FAIL could not take the rig lock"; exit 17 }
$ready = $false
try {
  Coord "CLAIM $(Now) $lane gen=cde69af2 (opus5 chip, <user>, apple-m3-ultra-512gb) - TOOK THE BOX for about 1h15. WHERE IN 17-48 PERCENT OF A CORE DOES THE c_f LOAD TERM TURN ON? The banked round has points at 17, 48 and 83 only, so the knee is bracketed and not located. Seven legsets on the 64 KiB measure ladder, mirrored q1 g10a g72a qm g72b g10b q2, ALL at the banked 4 MiB generator buffer. FOUR of them run A SYNTHETIC LOAD I START AND KILL BY PID: two at 10 percent of one core (total foreign_cpu near 29, which is the point of the round) and two at 72 percent (total near 88, which replicates the banked high anchor IN THIS SITTING so the two segments are comparable like for like). EVERY LOAD GENERATOR CARRIES ITS OWN INTERNAL WALL-CLOCK DEADLINE and stops itself on that instant whether or not my session, shell or ssh still exists; every pid is written to $pidfile AND announced on a line of its own here the moment it starts. Expect total foreign_cpu near 29 during two legsets, near 88 during two, and ~18 everywhere else - if you see sustained foreign CPU on this box after my DONE line, it is a defect and I want to know. I BUILD NOTHING, INSTALL NOTHING AND STOP NOTHING: Adobe Creative Cloud is already down and I leave it exactly as I found it. I write to no root but <rig>\cfknee18sep and I delete nothing of anyone else's - wcomb-16sep is NOT mine, I only READ its binary and fixture. Kill by pid, never by pattern."

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
  if ($bh -ne $binwant) { Say "CFKNEE-FAIL binary hash $bh != $binwant"; exit 9 }

  if (-not (Test-Path (Join-Path $fix 'gold.txt'))) {
    # COPIED, never shared: the legs damage and restore slices under fix\work\,
    # and $fixsrc is another lane's root that four rounds now read. Fixtures go
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
  # and nothing else - that the closed-loop level control ACHIEVES what it asks,
  # and that the internal deadline KILLS THE PROCESS with nobody helping it.
  #
  # IT IS RUN AT 10 PERCENT, WHICH IS THIS ROUND'S UNTRIED CONFIGURATION AND
  # THE ONE WITH A REASON TO MISS. The controller alternates a 2 ms burn with a
  # [Threading.Thread]::Sleep(2), and Windows' default timer granularity is
  # ~15.6 ms, so the shortest sleep it can actually take is far longer than the
  # shortest burn. At a 72 percent ask that asymmetry is harmless; at 10 it is
  # the whole control range, and a generator that silently delivered 15 or 5
  # would put this round's single new point somewhere other than where the
  # write-up says it is. The achieved figure is read out of the log below and
  # is reported in the write-up closed-loop against the generator's own
  # TotalProcessorTime, independent of the harness sampler entirely.
  Say "GEN-SELFTEST start target_pct=10 buf_kib=4096"
  $tdl = (Get-Date).ToUniversalTime().AddSeconds(45).ToString('o')
  $tp = Start-Process -FilePath 'powershell' -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File', $gen,
        '-TargetPct','10','-DeadlineUtc',$tdl,'-MaxSeconds','90','-BufKiB','4096','-Log',$genlog)
  Add-Content -Path $pidfile -Value "$(Now) GEN-SELFTEST-START pid=$($tp.Id) target_pct=10 buf_kib=4096 deadline=$tdl"
  Start-Sleep -Seconds 20
  Say "GEN-SELFTEST foreign_cpu_with_generator=$(Get-ForeignCpu) (box idles near 18; this 1 s sampler overstates a BIRTH sample by 2-5x on purpose-built evidence, so read it as alive/not-alive)"
  $waited = 0
  while ($waited -lt 60) { Start-Sleep -Seconds 5; $waited += 5; if ($tp.HasExited) { break } }
  $tp.Refresh()
  if (-not $tp.HasExited) {
    Say "GEN-SELFTEST-FAIL pid=$($tp.Id) OUTLIVED ITS OWN DEADLINE - killing it and standing down"
    try { Stop-Process -Id $tp.Id -Force } catch { }
    Coord "RELEASE $(Now) $lane - STANDING DOWN AND RELEASING THE BOX WITHOUT MEASURING. My load generator failed its own selftest: it did not die on its internal deadline, and a generator that cannot be trusted to stop itself must not run on a shared timing box. Killed by pid, box is free, no legs ran."
    exit 12
  }
  Say "GEN-SELFTEST ok pid=$($tp.Id) died on its own deadline after $waited s of nobody helping it"
  Add-Content -Path $pidfile -Value "$(Now) GEN-SELFTEST-OK pid=$($tp.Id) self-terminated"
  # The achieved level is the selftest's real product; read it out of the log.
  foreach ($l in (Get-Content $genlog -ErrorAction SilentlyContinue | Select-Object -Last 3)) { Say "GEN-SELFTEST-LOG $l" }
  $ready = $true
} finally { Release-RigLock 'cfknee' }
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
# A DEFECT FIX INHERITED FROM cfload.ps1 and cfbuf.ps1, kept verbatim in shape
# because the defect it fixes is this round's too. The driver releases its own
# lock after setup and wcomb.ps1 takes the lock per invocation, so between
# legsets this lane owns NOTHING - and a generator started before the legset
# acquires would burn a core's worth of somebody else's box for as long as the
# retry budget lasts, with neither lane's logs saying why. So: probe the lock
# free with NO generator alive, release it at once, and only then start the
# load and go straight in. The residual is the sub-second gap between this
# release and wcomb's own CreateNew. IT IS NARROWED TO THAT FLOOR, NOT CLOSED.
function Wait-LockFree([string]$tag, [int]$maxTries = 60) {
  $script:lockfree = $false
  for ($t = 1; $t -le $maxTries; $t++) {
    Try-TakeRigLock 'cfknee'
    if ($script:riglock_taken) {
      Release-RigLock 'cfknee'
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

# ===================================================== THE LADDER
# -Reps 1 -Threads 4,12 and the phase-default rungs 192,512,1024,2048,4096 -
# IDENTICAL to the banked load round's and the buffer round's, because a fitted
# `c_f` is a least-squares slope over a fold that is not linear in m and the
# rung set is therefore a free parameter of every figure. A round that moved it
# would not be extending those points, it would be starting a new curve.
# The -t4 arm is run and is NOT expected to decide anything: its noise floor is
# 11% against the full pool's 8%, and the load lane withdrew its -t4 arm
# outright. It is here because it costs nothing extra on the same legset and
# because an INDEPENDENT arm agreeing in sign is worth having when the -t12
# effect being looked for may be only a few points.
$extra = '-Reps 1 -Threads 4,12'
Say "LADDER start (one generator level at 10% of a core to split the 17-48 gap, plus 72% as a within-sitting high anchor; BUFFER FIXED AT 4096 KiB THROUGHOUT)"
Run-Legset 'q1' $extra; if ($script:legrc -ne 0) { $fails += 'q1' }

foreach ($step in @(@('g10a',10), @('g72a',72))) {
  $tag = $step[0]; $pct = [int]$step[1]
  Wait-LockFree $tag 60
  if (-not $script:lockfree) { Say "LEGSET $tag SKIPPED - lock never free, NO generator was started"; $fails += $tag; continue }
  Start-Load $pct 4096 1500
  $gp = $script:genpid
  try { Run-Legset $tag $extra 3; if ($script:legrc -ne 0) { $fails += $tag } } finally { Stop-Load $gp }
}

Run-Legset 'qm' $extra; if ($script:legrc -ne 0) { $fails += 'qm' }

foreach ($step in @(@('g72b',72), @('g10b',10))) {
  $tag = $step[0]; $pct = [int]$step[1]
  Wait-LockFree $tag 60
  if (-not $script:lockfree) { Say "LEGSET $tag SKIPPED - lock never free, NO generator was started"; $fails += $tag; continue }
  Start-Load $pct 4096 1500
  $gp = $script:genpid
  try { Run-Legset $tag $extra 3; if ($script:legrc -ne 0) { $fails += $tag } } finally { Stop-Load $gp }
}

Run-Legset 'q2' $extra; if ($script:legrc -ne 0) { $fails += 'q2' }
Say "LADDER done fails=[$($fails -join ',')]"

# A SWEEP FOR ANYTHING OF MINE STILL ALIVE. It reads the pid FILE, never a
# process name - `pkill -f`-shaped cleanup is what CLAUDE.md invariants 2 and
# 2a forbid, and on this box a name matches every lane's processes equally.
function Sweep-Leftovers([string]$where) {
  $left = @()
  foreach ($l in (Get-Content $pidfile -ErrorAction SilentlyContinue)) {
    if ($l -match 'GEN-(START|SELFTEST-START) pid=(\d+)') {
      $gp = [int]$Matches[2]
      try { $null = [Diagnostics.Process]::GetProcessById($gp); $left += $gp } catch { }
    }
  }
  if ($left.Count -gt 0) {
    Say "CFKNEE-LEFTOVERS at=$where $($left -join ',')"
    foreach ($gp in $left) { try { Stop-Process -Id $gp -Force } catch { } }
    Start-Sleep -Seconds 3
  } else { Say "CFKNEE-CLEAN at=$where no generator pid of mine is alive" }
}
Sweep-Leftovers 'final'
$back = Get-ForeignCpu
Say "CFKNEE foreign_cpu_after=$back"
Census 'final'
if ($fails.Count -gt 0) { Say "CFKNEE DONE WITH FAILURES: $($fails -join ',')" } else { Say "CFKNEE ALL DONE" }
Coord "DONE $(Now) $lane gen=cde69af2 (opus5 chip, <user>, apple-m3-ultra-512gb) - THE BOX IS FREE AND THE RIG LOCK IS RELEASED. Seven legsets ran; failures: $(if ($fails.Count) { $fails -join ',' } else { 'none' }). EVERY LOAD GENERATOR THIS LANE STARTED IS DEAD, verified by pid against $pidfile rather than by name, and foreign_cpu reads $back% of one core as I write - the quiet-sitting baseline on this box is ~17-20%. If that number is high, read $pidfile and kill by pid. I built nothing, installed nothing and stopped nothing; Adobe Creative Cloud is as I found it. My root is <rig>\cfknee18sep and it goes when the numbers are banked. Next lane: the box is yours."
