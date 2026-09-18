param(
  [string]$Root   = '<rig>\crpool-17sep',  # MY OWN root, UNLESS -Root names an inherited one (see INHERITANCE below)
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Rungs  = '288,320,352,384,416,448,480,512',
  [string]$Budget = '21474836480',               # NZBFAST_NTT_BUDGET, 20 GiB - keeps every force leg resident
  [switch]$SkipProbe
)
# crpool-round.ps1 - the five-arm CREATE-phase POOL-SIZE resident row-gate
# ladder at 4 MiB on GFNI-256, for lane parfast-create-pool-ladder-4mib-17sep.
#
# THE QUESTION, and why it is not the 17 Sep pool ladder's question. That round
# (rounds/poolladder4m-2026-09-17/, landed as 83bfea5fd) answered the
# pool-size question on the REPAIR path and scoped its answer there in words.
# Everything it established is `-Phase rowgate`. THE CREATE HAS NEVER BEEN
# MEASURED WITH PLACEMENT CONTROLLED AT ALL, and the gap that leaves is not
# academic - it is checkable in one grep:
#
#   grep -c affinity rounds/crg4-2026-09-16/*.log   ->   0
#
# The landed create round ran `-Phase create` at threads 4 and 16 with NO
# -Affinity on any leg. So its headline pool comparison - resident CPU
# crossover 381 at -t4 against 365 at -t16 - is a SIXTEEN-ROW GAP ACROSS TWO
# UNPINNED POOLS. The 17 Sep pinned sitting measured PLACEMENT ALONE swinging
# the crossover 42-52 rows at FIXED pool size on this same part, so the
# create's 16 rows sit inside the confound by a factor of three. That is
# exactly the arithmetic that voided the repair's "one second rung serves both
# pools" clause, and nothing has ever applied it to the create half.
#
# WHY IT IS NOT A TIDY-UP. The create section's recommendation - "384 is the
# only candidate that serves both paths", against a repair that wants 416 -
# rests on where the create crosses ON EACH POOL. If the create's pool ORDERING
# (t4 above t16) is a placement artefact, the arithmetic behind 384 needs
# re-reading. THIS ROUND IS NOT CHARTERED TO MOVE A CONSTANT. It measures, and
# the write-up says what the measurement does and does not license.
#
# THE ARMS mirror poolladder-round.ps1's table, and the mirroring IS THE POINT:
# the create numbers only mean something read against repair numbers taken with
# the same masks on the same part. Core Ultra 9 386H is 4 P (0-3), 8 E (4-11),
# 4 LP-E (12-15), so E is the only class wide enough to offer a within-class
# pool step, and that reasoning carries over unchanged.
#
#   1  4mc-t16                   -Threads 16   UNPINNED, all 16 cores, MIXED.
#                                  MUST RUN FIRST: wcomb builds the 16 GiB
#                                  fixture on the first ladder and -Affinity
#                                  arms EVERY leg including that create, so a
#                                  pinned arm first would build the fixture on
#                                  four cores. It is also the tie to crg4's
#                                  unpinned -t16 create reading of 365.
#   2  4mc-e4    0xF0   (4-7)    -Threads 4    four E-cores, ONE class.
#   3  4mc-e8    0xFF0  (4-11)   -Threads 8    eight E-cores, SAME ONE class.
#                                  ARMS 2 AND 3 ARE THE WITHIN-CLASS POOL STEP:
#                                  pool doubles, class fixed, nothing else
#                                  moves. On the repair path this step was +34
#                                  rows (344 -> 378).
#   4  4mc-p4    0xF    (0-3)    -Threads 4    four P-cores, one class. WITH
#                                  ARM 2 THIS IS THE SAME-POOL CLASS PAIR:
#                                  pool held at four, class moved E -> P. On
#                                  the repair path that pair was 344 against
#                                  381, i.e. class alone worth 37 rows at fixed
#                                  pool size.
#   5  4mc-m12   0xFFF  (0-11)   -Threads 12   4 P + 8 E. MIXED, and stated as
#                                  mixed - NOT a third rung of the within-class
#                                  ladder and it must never be read as one.
#
# ARM ORDER DIFFERS FROM poolladder-round.ps1 IN ONE PLACE, DELIBERATELY: that
# round ran m12 fourth and p4 fifth; this one runs p4 fourth and m12 fifth.
# The reason is what a sitting cut short must still answer. The chip's minimum
# is "a within-class pool step AND a same-pool class pair"; arms 2+3 are the
# step and arms 2+4 are the pair, so a round that dies after four arms has
# discharged its brief in full and loses only the mixed control. That control
# existed on the repair path to test the no-spare-core hypothesis, WHICH IS
# ALREADY DEAD (the 17 Sep sitting killed it directly - t16 came back monotone
# at 398 leaving no core idle), so m12 here is a placement data point and
# nothing is owed to it.
#
# RUNGS ARE 288..512, WIDER AT THE TOP THAN THE REPAIR ROUND'S 320..448 AND
# ONE LOWER AT THE BOTTOM. Both ends are forced, and the TOP end is forced by a
# standing rule rather than by taste.
#
# THE BOTTOM. The create crosses BELOW the repair on this part in CPU, so
# applying that offset to the repair round's five pinned CPU crossings
# (344/378/381/398/405) puts the expected create CPU crossings near
# 311/345/348/365/372. 4mc-e4 is the arm at risk of crossing under a 320 floor,
# and an arm with no crossing in range answers nothing, so 288 is the floor.
#
# THE TOP, AND THIS IS THE ONE THAT MATTERS. WALL TIME BEATS CPU TIME WHENEVER
# THE TWO DISAGREE - the maintainer's standing rule, 17 Sep 2026, memory topic
# nzbfast-wall-time-is-the-deciding-metric: "people care about wall times much
# more than cpu times... always improve wall times". A crossover round must
# therefore BRACKET THE WALL CROSSING, not merely the CPU one, because the wall
# reading is the one that decides a shipping question. On this part at this
# shape the two disagree by a lot and ALWAYS IN THE SAME DIRECTION - every
# banked 4 MiB resident crossing is 28-43 rows HIGHER in wall than in CPU:
#
#   path    pool   CPU    wall    wall-CPU
#   repair  t4     391    427     +36
#   repair  t16    405    >448    >+43   (never crossed inside 320..448)
#   create  t4     381    422     +41
#   create  t16    365    393     +28
#
# and the pinned REPAIR pool ladder is worse: two of its five arms (4m-t16 and
# 4m-m12) read `wall m ~ >448` and never crossed inside their rung set at all.
# A create round pinned to four E-cores at 320..448 would very likely publish
# the same non-answer on the deciding metric. 480 and 512 are what stop that.
#
# THE COST IS AFFORDABLE HERE IN A WAY IT WOULD NOT BE ON THE REPAIR PATH: a
# create leg at this shape walls 25-43 s unpinned against a repair leg's
# 65-88 s, so eight rungs of create cost about what five rungs of repair do.
# 256 was dropped to pay for 480 and 512, which is the right trade under the
# rule above: 256 guarded a CPU crossing that 288 also brackets, and the two
# new rungs guard the WALL crossing, which is the deciding one.
#
# NO RUNG CAN FALL THROUGH TO THE FOLD, which is what makes a low rung safe to
# ask for. The forced arm sets NZBFAST_CREATE_NTT_MIN_ROWS=0, so
# rows_and_present_admitted's floor clause reads `count >= 0 && n_slices >=
# create_ntt_min_present()`; n = 4,096 clears the x86 input floor of 2,048 on
# its own, so admission holds at EVERY rung in this list including 256, and
# wcomb's own path assert (`plan prep ... cold build(s)`) refuses the leg if it
# does not. The high-redundancy subfloor clause is never reached and is not
# relied on.
#
# INHERITANCE, and it is the one structural difference from the driver this
# copies. poolladder-round.ps1 always built its own binary and fixture because
# the lane before it had deleted its root. This round may or may not be handed
# one: parfast-4mib-pool8-class-isolation-17sep runs immediately ahead of me on
# this box and builds THE SAME TWO ARTEFACTS at exactly the shape I need - a
# binary from 06d5734b7 and fix-4194304-1024 at -Slice 4194304 -MemberMiB 1024
# -Recovery 640 - and I asked it on the coordination file to leave them. So
# -Root may name ITS root. The build block below already keys on
# `Test-Path $Bin` and the fixture block on wcomb's own reuse, so inheriting is
# spelled by passing -Root and nothing else changes. THE BYTE GATE STILL RUNS
# ON AN INHERITED BINARY, and that is the whole safety of inheriting: 4,173,312
# bytes is the invariant across every build of 06d5734b7 on this fleet, so an
# inherited artefact that is not that commit's is refused exactly as a
# mis-built one would be.
#
# THE BINARY GATE IS THE BYTE COUNT AND NOT THE sha256. The build embeds its
# own path, so the hash differs per root BY CONSTRUCTION and gating on it cost
# the previous lane a launch (its log is banked as
# poolladder-attempt1-shagate.log). The hash is RECORDED for provenance and
# never compared.
#
# READING THE RESULT, FIRST RULE: WALL DECIDES, CPU EXPLAINS. Where this
# round's CPU crossover and its WALL crossover disagree, the WALL one answers
# the shipping question and the divergence is ITSELF A FINDING to be reported
# with its size, never resolved quietly in favour of the tidier number.
# rowgate.py read prints both on every table (`CPU m ~ X   wall m ~ Y`), so
# there is no extra work to do - only the discipline of quoting both. The
# hygiene exception is not a loophole: CPU is far more robust to a loaded box,
# so read CPU to learn the MECHANISM and confirm the DECISION with wall, and
# say what the box was doing when the wall figure was taken. Concretely, the
# banked repair `-t16` wall bound above (`>448`) came off a ladder whose
# foreign CPU ran at a MEDIAN of 52% of a core and a max of 109%, where the
# create ladder's ran at 11-12% - so those two wall figures are not of equal
# weight and this round must not treat them as if they were.
#
# READING THE RESULT, SECOND RULE: CPU-SECONDS DO NOT COMPARE ACROSS MASKS. The class probe
# reads P/E at 1.74x on this part, so arm 3's raw `cpu=` must never be read
# against arm 4's, and an 8 E-core arm burning more CPU than a 4 P-core arm is
# not doing more work. Only the CROSSOVER compares across arms, because it is a
# ratio of fold to force WITHIN one arm on one core mix. Reduce per arm on the
# Mac with `python3 harness/rowgate.py read <log>` - it groups by
# (label, threads), which is why every arm carries a DISTINCT -Label - and then
# screen EVERY ladder with ladder-monotonicity-audit.py before believing any
# crossover. A tight A/A floor is evidence of AGREEMENT and not of correctness:
# the floor is a MAX over reps and is blind to a perturbation that hits both
# copies of a rung, so check monotonicity too, and check that the rungs
# BRACKETING the crossing are the firm ones.
#
# CONTAMINATION. This driver is DETACHED and self-reporting; whoever launches
# it must poll at 600 s AT THE LOOSEST and preferably not at all, because every
# ssh poll spawns a PowerShell under sshd outside the round's pid tree and
# lands in the round's own foreign_cpu.
$ErrorActionPreference = 'Stop'
if (-not $Bin) { $Bin = Join-Path $Root 'src\target\release\parfast.exe' }
$here  = $PSScriptRoot
$logs  = Join-Path $here 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null
. (Join-Path $here 'plib.ps1')

function Say([string]$m) { "$(Get-Date -Format o) $m" }
function Post([string]$line) {
  # Local append: costs the box nothing, unlike an ssh poll.
  try { Add-Content -Encoding UTF8 -Path $Coord -Value $line } catch { Say "COORD-WRITE-FAILED $_" }
}
function Load-Now { (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average }

# The load gate is a SECOND, cheaper instrument and NOT a repair to
# Require-QuietBox, whose 10%-of-box ceiling is 160% of a core here and lets
# one saturated core through BY DESIGN. IT RETURNS NOTHING AND SETS
# $script:quietOk, which is plib's own convention and is not a style choice:
# `Say` writes its line to the OUTPUT stream, so a function that both logs and
# returns a bool returns an ARRAY of [string, ..., bool].
function Wait-Quiet([string]$where, [int]$samples) {
  $script:quietOk = $false
  $capS = 7200; $t0 = Get-Date
  while ($true) {
    $waited = [int]((Get-Date) - $t0).TotalSeconds
    if ($waited -gt $capS) { Say "LOAD-GATE GAVE-UP at=$where waited_s=$waited"; return }
    $held = (Get-RigLockHolder).Held
    $pf   = @(Get-Process parfast -ErrorAction SilentlyContinue).Count
    $ok = $true; $reads = @()
    if ($held -or $pf -gt 0) { $ok = $false }
    else {
      for ($i = 0; $i -lt $samples; $i++) {
        $l = Load-Now; $reads += $l
        if ($l -ge 25) { $ok = $false }
        if ($i -lt ($samples - 1)) { Start-Sleep -Seconds 60 }
      }
    }
    if ($ok) { Say "LOAD-GATE ok at=$where loads=$($reads -join '/') waited_s=$waited"; $script:quietOk = $true; return }
    Say "LOAD-GATE busy at=$where riglock=$held parfast=$pf loads=$($reads -join '/') waited_s=$waited"
    Start-Sleep -Seconds 60
  }
}

# The core-class probe. `.claude/MACHINES.md` says cores 0-3 are P and 4-11 E -
# but this round's arm NAMES rest on that, so it is checked here rather than
# trusted. Arm 3 asserts that cores 8-11 are the SAME CLASS as cores 4-7, which
# is the premise of the only within-class pool step the part can offer, so the
# probe reads core 8 as well and a core-8 time that does not match core 4's is
# a reason to throw arm 3 away rather than to publish it. FIXED WORK, timed.
function Probe-Classes {
  $spin = @'
param([int]$Iters)
$sw=[Diagnostics.Stopwatch]::StartNew(); $x=0.0
for($i=0;$i -lt $Iters;$i++){ $x=$x+$i*1.000001 }
$sw.Stop(); "SPIN ms=$($sw.ElapsedMilliseconds) x=$x"
'@
  $f = Join-Path $here 'spin.ps1'; [IO.File]::WriteAllText($f, $spin)
  foreach ($m in @(@(0x1,'P-core0'), @(0x10,'E-core4'), @(0x100,'E-core8'), @(0x800,'E-core11'), @(0x1000,'LPE-core12'))) {
    $mask = [long]$m[0]; $name = $m[1]
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$f`" -Iters 12000000"
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = New-Object Diagnostics.Process; $p.StartInfo = $psi
    $w = [Diagnostics.Stopwatch]::StartNew(); $null = $p.Start()
    $got = 0
    try { $p.ProcessorAffinity = [IntPtr]$mask; $got = [long]$p.ProcessorAffinity } catch { $got = -1 }
    $o = $p.StandardOutput.ReadToEndAsync(); $null = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit(); $w.Stop()
    $cpu = $p.TotalProcessorTime.TotalSeconds; $p.Dispose()
    Say ("CLASS-PROBE $name mask=0x{0:X} got=0x{1:X} wall_s={2} cpu_s={3} {4}" -f $mask, $got, [math]::Round($w.Elapsed.TotalSeconds,3), [math]::Round($cpu,3), ($o.Result -replace "`r?`n",' '))
  }
  Remove-Item $f -Force
}

$arms = @(
  @{ label = '4mc-t16'; aff = '';      threads = 16; tag = 'crt16'; what = 'UNPINNED t16, all 16 cores (4 P + 8 E + 4 LP-E), MIXED - builds the fixture if it is not inherited; the tie to crg4 unpinned t16 create = 365' },
  @{ label = '4mc-e4';  aff = '0xF0';  threads = 4;  tag = 'cre4';  what = 'mask 0xF0, cores 4-7, FOUR E-CORES, one class - the pool-4 anchor and half of BOTH comparisons' },
  @{ label = '4mc-e8';  aff = '0xFF0'; threads = 8;  tag = 'cre8';  what = 'mask 0xFF0, cores 4-11, EIGHT E-CORES, SAME ONE CLASS - with the arm above, THE WITHIN-CLASS POOL STEP: pool doubles, class fixed' },
  @{ label = '4mc-p4';  aff = '0xF';   threads = 4;  tag = 'crp4';  what = 'mask 0xF, cores 0-3, FOUR P-CORES, one class - with 4mc-e4, THE SAME-POOL CLASS PAIR: pool held at four, class moved' },
  @{ label = '4mc-m12'; aff = '0xFFF'; threads = 12; tag = 'crm12'; what = 'mask 0xFFF, cores 0-11, 4 P + 8 E, MIXED and stated as mixed - a placement data point, not a rung of the within-class ladder' }
)

Say "CRPOOL-ROUND start root=$Root bin=$Bin rungs=$Rungs budget=$Budget arms=$($arms.Count)"

# THE BUILD AND THE EXTRACT ARE GATED LIKE A MEASUREMENT ARM. A `cargo build`
# plus a 16 GiB create is foreign load to whoever is measuring, every bit as
# much as a ladder is, so the gate comes FIRST and the TAKING-THE-BOX line
# comes after it passes: until then this lane is queued and says so. Inherited
# from poolladder-round.ps1, which is the one structural change IT made to the
# driver IT copied. Kept.
Wait-Quiet 'prebuild' 2
if (-not $script:quietOk) { Say "CRPOOL-ABORT load gate gave up before the build"; exit 8 }
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-create-pool-ladder-4mib-17sep gen=4dd0fbdd (<user>, opus5 chip; an internal note, lease to 2026-09-18T01:17:25Z) ACCOUNTS=none - TAKING THE BOX, now, for the five-arm CREATE-phase POOL-SIZE resident row-gate ladder at 4 MiB / n=4096: 4mc-t16 unpinned t16 (builds the fixture if it is not inherited), 4mc-e4 mask 0xF0 t4 (cores 4-7, four E), 4mc-e8 mask 0xFF0 t8 (cores 4-11, eight E, SAME class - this step is the round), 4mc-p4 mask 0xF t4 (cores 0-3, four P - with 4mc-e4 this is the same-pool class pair), 4mc-m12 mask 0xFFF t12 (cores 0-11, 4 P + 8 E, MIXED and stated as mixed). Rungs $Rungs, arms fold/force/force2/fold2, one rep, resident, NttBudget 20 GiB. THE QUESTION item 4 of an internal note left owed: the landed create round rounds/crg4-2026-09-16/ ran -Phase create at t4 and t16 with NO -Affinity on any leg, so its headline 381-against-365 is a 16-row gap across two UNPINNED pools, and the repair round measured placement ALONE swinging the crossover 42-52 rows at fixed pool size on this part. The create's gap is inside that confound by a factor of three. FIVE LADDERS, ONE SITTING: wcomb takes the lock per ladder, so the gaps between them are NOT openings. Each ladder gates on lock-free AND no-parfast AND load under 25, and waits out an rc=17 LOCK-BUSY for up to 40 minutes rather than dying. Will post DONE with the box-as-left statement and will DELETE my root. Kill by pid, never by pattern."

if (-not $SkipProbe) { Probe-Classes }

$WantBytes = 4173312
if (-not (Test-Path $Bin)) {
  # Win32_Process::Create (wlaunch.ps1) does not always see the user's PATH,
  # and rustup's shims live in the profile. Same fix wcomb.ps1 carries.
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  $src = Join-Path $Root 'src'
  # EXTRACT INSIDE THE GATED REGION, not at staging time. The 112 MB tarball is
  # scp'd up before launch - that is network work and costs the box little -
  # but unpacking ~25,000 files is disk and CPU that lands on whoever is
  # measuring, so it waits behind the same gate the build does.
  if (-not (Test-Path $src)) {
    $tgz = Join-Path $Root 'src-06d5734b7.tar.gz'
    if (-not (Test-Path $tgz)) { Say "CRPOOL-FAIL no source tree at $src and no tarball at $tgz"; exit 9 }
    New-Item -ItemType Directory -Force $src | Out-Null
    $xw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "tar -xzf `"$tgz`" -C `"$src`""
    $xrc = $LASTEXITCODE
    Say "EXTRACT rc=$xrc secs=$([math]::Round($xw.Elapsed.TotalSeconds,1)) into=$src"
    if ($xrc -ne 0) { Say "CRPOOL-FAIL extract rc=$xrc"; exit 9 }
  }
  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Say "CRPOOL-FAIL no Cargo.toml under $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line
  # of a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-crpool.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-crpool.log"
  if ($brc -ne 0) { Say "CRPOOL-FAIL build rc=$brc"; exit 9 }
} else {
  Say "BIN-INHERITED $Bin already present - no extract and no cargo build. The byte gate below runs on it UNCHANGED, which is what makes inheriting safe."
}
if (-not (Test-Path $Bin)) { Say "CRPOOL-FAIL bin not found after build: $Bin"; exit 9 }
$gotSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$gotLen = (Get-Item $Bin).Length
Say "BIN bytes=$gotLen want_bytes=$WantBytes sha256=$gotSha (a sha that matches no other round is EXPECTED and not a fault - the build embeds its own path; the byte count is the invariant across every build of 06d5734b7 on this fleet)"
if ($gotLen -ne $WantBytes) {
  Say "CRPOOL-FAIL binary byte count want=$WantBytes got=$gotLen - this is NOT the 06d5734b7 artefact the banked create and repair ladders used, so arm 1 would not tie to crg4 and no arm would be readable against the pinned repair sitting. Refusing rather than measuring it."
  exit 9
}
$fix = Join-Path $Root 'fix-4194304-1024'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused - no 16 GiB create and no settle wait)' } else { 'ABSENT - ladder 1 builds it, then waits out the settle' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

$rc = 0
foreach ($a in $arms) {
  Wait-Quiet $a.tag 1
  if (-not $script:quietOk) { Say "CRPOOL-ABORT load gate gave up before $($a.tag)"; $rc = 8; break }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-create-pool-ladder-4mib-17sep EXTENSION - still running, still ONE sitting: arm $($a.tag) ($($a.what)), $($arms.Count) arms total"
  $log = Join-Path $logs "$($a.tag).log"
  $wcomb = Join-Path $here 'wcomb.ps1'
  $affArg = if ($a.aff) { " -Affinity $($a.aff)" } else { '' }
  $inner = "-NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$Root`" -Bin `"$Bin`" -NoBuild" +
           " -Phase create -Tag $($a.tag) -Label $($a.label) -Slice 4194304 -MemberMiB 1024 -Recovery 640" +
           " -Rungs $Rungs -Threads $($a.threads) -Reps 1 -Residency resident -NttBudget $Budget" + $affArg
  Say "ARM $($a.tag) label=$($a.label) aff=$(if($a.aff){$a.aff}else{'none'}) threads=$($a.threads) log=$log"
  Say "ARGV powershell $inner"
  # cmd /c redirect, NOT Tee-Object: a Tee-Object log is UTF-16 and
  # harness/rowgate.py answers "REFUSED: no legs" on one.
  #
  # rc=17 IS THE ONE EXIT CODE WORTH WAITING OUT, and the narrowness is the
  # point. rc=17 is plib's LOCK-BUSY: it means "somebody else has the box",
  # never "this measurement is wrong", because the ladder stopped before its
  # first leg, so nothing was measured and nothing is contaminated by asking
  # again later. EVERY OTHER NON-ZERO rc STILL ENDS THE ROUND ON THE SPOT,
  # because those are the instrument REFUSING - a residency violation, a path
  # assert, an affinity readback mismatch, a cross-arm hash that does not match
  # - and retrying one of those would launder a refusal into a number.
  $arc = 0; $legs = 0; $lockWaits = 0
  while ($true) {
    & cmd /c "powershell $inner > `"$log`" 2>&1"
    $arc = $LASTEXITCODE
    $legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
    if ($arc -ne 17) { break }
    $lockWaits++
    if ($lockWaits -gt 20) { Say "CRPOOL-ARM-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  if ($arc -ne 0) { Say "CRPOOL-ARM-FAILED $($a.tag) rc=$arc - see $log"; $rc = $arc; break }
}

Say "CRPOOL-ROUND end rc=$rc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-create-pool-ladder-4mib-17sep gen=4dd0fbdd (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
