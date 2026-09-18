param(
  [string]$Root   = '<rig>\poolladder-17sep',  # MY OWN root: src\ from a git-archive of 06d5734b7; binary and fixture built here
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Rungs  = '320,352,384,416,448',
  [string]$Budget = '21474836480',               # NZBFAST_NTT_BUDGET, 20 GiB - keeps every force leg resident
  [switch]$SkipProbe
)
# poolladder-round.ps1 - the five-arm POOL-SIZE resident row-gate ladder at
# 4 MiB on GFNI-256, for lane parfast-4mib-pinned-pool-ladder.
#
# THE QUESTION, and why it is not the previous round's question. The 17 Sep
# pinned round (an internal note, "The four-arm
# pinned sitting, twice over") held the pool at FOUR threads and moved only the
# CPU mask, and found the resident CPU crossover swing 42-52 rows on placement
# alone - three to four times the 14-row -t4/-t16 gap the coincidence clause
# rests on. So that gap is inside the confound and says nothing about pool
# size. The comparison it wanted to make instead - pinned-4P against -t16 - had
# no -t16 number to make it against, because that arm is non-monotone in F/T in
# all three sittings the item has had. This round asks the pool-size question in
# the one way that needs NO full-box arm: MOVE THE POOL WITH THE CORE CLASS
# HELD FIXED.
#
# THE ONE WITHIN-CLASS POOL LADDER THIS PART CAN OFFER IS THE E-CORES.
# Core Ultra 9 386H is 4 P (0-3), 8 E (4-11), 4 LP-E (12-15). A P-only ladder
# cannot exist - there are four P-cores and that is the whole class - and an
# LP-E-only ladder is four as well. The E class is eight, so 4 E -> 8 E is the
# only step on this part where pool size doubles and the core class does not
# move at all. That step is the round; everything else is a tie or a control.
#
# THE ARMS, in run order, each naming its mask AND its core classes:
#   1  4m-t16                    -Threads 16   UNPINNED, all 16 cores, MIXED.
#                                  Runs first because wcomb builds the 16 GiB
#                                  fixture on the first ladder and -Affinity
#                                  arms EVERY leg including that create, so a
#                                  pinned arm first would build 16 GiB on four
#                                  cores. It is also the control that is KNOWN
#                                  to misbehave, and the other half of the
#                                  spare-core test below.
#   2  4m-e4    0xF0   (4-7)     -Threads 4    four E-cores, ONE class. Ties to
#                                  the finished sitting's 343/346 and is this
#                                  round's check that the REBUILT fixture is
#                                  comparable.
#   3  4m-e8    0xFF0  (4-11)    -Threads 8    eight E-cores, SAME ONE class.
#                                  ARM 2 AND ARM 3 ARE THE ROUND. Pool doubles,
#                                  class fixed, nothing else moves.
#   4  4m-m12   0xFFF  (0-11)    -Threads 12   4 P + 8 E. MIXED, and stated as
#                                  mixed - it is NOT a third rung of the
#                                  within-class ladder and must never be read
#                                  as one. It exists for the SECOND question:
#                                  it leaves the four LP-E cores idle where
#                                  arm 1 leaves nothing idle, so if arm 4 is
#                                  monotone where arm 1 is not, the spare-core
#                                  hypothesis lives; if arm 4 is ALSO
#                                  non-monotone the hypothesis is dead and the
#                                  shape is about something else (the force
#                                  leg's 16.5 GB resident peak on a 31.4 GB box
#                                  is the named suspect).
#   5  4m-p4    0xF    (0-3)     -Threads 4    four P-cores. Ties to the
#                                  finished sitting's 377/372. Last because
#                                  arm 2 already carries a tie, so a sitting
#                                  cut short after four arms still answers both
#                                  questions and loses only a second tie.
#
# NOT RUN, and deliberately: an 8-thread P-INCLUSIVE arm (0xFF is 4 P + 4 E).
# It would isolate core class at fixed pool size eight, which complements the
# placement figure the previous round took at fixed pool size four - but it
# mixes two classes in an arm whose whole purpose would be to hold class fixed,
# it costs a sixth ~25-minute ladder, and the placement confound is already
# measured. Owed, not skipped in silence.
#
# PRIORITY IS NOT TOUCHED ON ANY ARM, for the reason the previous round gives:
# arm 1 is a control against already-banked unpinned ladders and must differ
# from them in affinity and in nothing else.
#
# READING THE RESULT: CPU-SECONDS DO NOT COMPARE ACROSS MASKS. A P-core second
# and an E-core second buy different work - 1.72x on this part by the class
# probe below - so arm 3's raw `cpu=` must never be read against arm 5's, and
# an 8 E-core arm burning more CPU than a 4 P-core arm is not doing more work.
# What compares is the CROSSOVER, because it is a ratio of fold to force WITHIN
# one arm on one core mix. Reduce per arm on the Mac with
# `python3 harness/rowgate.py read <log>` - it groups by (label,
# threads), which is why every arm carries a DISTINCT -Label. Screen every
# ladder for MONOTONICITY as well as for its A/A floor: the floor is a MAX over
# reps and is blind to a perturbation that hits BOTH copies of a rung (one rung
# of the previous round reported a 0.5% floor while visibly broken), so a tight
# floor is evidence of agreement and not of correctness.
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
# trusted, and this round needs it more than the last one did: arm 3 asserts
# that cores 8-11 are the SAME CLASS as cores 4-7, which is the premise of the
# only within-class pool step the part can offer. So this probe reads core 8 as
# well, and a core-8 time that does not match core 4's is a reason to throw arm
# 3 away rather than to publish it. FIXED WORK, timed.
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
  @{ label = '4m-t16';  aff = '';      threads = 16; tag = 'plt16'; what = 'UNPINNED t16, all 16 cores (4 P + 8 E + 4 LP-E), MIXED - builds the fixture; the known-broken control and half of the spare-core test' },
  @{ label = '4m-e4';   aff = '0xF0';  threads = 4;  tag = 'ple4';  what = 'mask 0xF0, cores 4-7, FOUR E-CORES, one class - ties to the finished sitting 343/346 and checks the rebuilt fixture' },
  @{ label = '4m-e8';   aff = '0xFF0'; threads = 8;  tag = 'ple8';  what = 'mask 0xFF0, cores 4-11, EIGHT E-CORES, SAME ONE CLASS - with the arm above, THE round: pool doubles, class fixed' },
  @{ label = '4m-m12';  aff = '0xFFF'; threads = 12; tag = 'plm12'; what = 'mask 0xFFF, cores 0-11, 4 P + 8 E, MIXED and stated as mixed - the spare-core test: four LP-E cores left idle where t16 leaves none' },
  @{ label = '4m-p4';   aff = '0xF';   threads = 4;  tag = 'plp4';  what = 'mask 0xF, cores 0-3, FOUR P-CORES, one class - ties to the finished sitting 377/372' }
)

Say "POOLLADDER-ROUND start root=$Root bin=$Bin rungs=$Rungs budget=$Budget arms=$($arms.Count)"

# THE BUILD IS GATED LIKE A MEASUREMENT ARM, and that is the one structural
# change from pinaff-round.ps1, which this driver otherwise copies. That driver
# posted its CLAIM and then built, because it INHERITED its binary and fixture
# and had nothing to build. This round has to build a binary and a 39.7 GB
# fixture from scratch - the previous lane deleted crg4-16sep on finishing, as
# its owner had asked - and a `cargo build --release` plus a 16 GiB create is
# foreign load to whoever is measuring, every bit as much as a ladder is. So
# the gate comes FIRST and the TAKING-THE-BOX line comes after it passes: until
# then this lane is queued and says so, and the queue NOTE it posted before
# launch says the same in the same words.
Wait-Quiet 'prebuild' 2
if (-not $script:quietOk) { Say "POOLLADDER-ABORT load gate gave up before the build"; exit 8 }
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pinned-pool-ladder gen=86278d8d (<user>, opus5 chip; an internal note, lease to 2026-09-18T14:00:34Z) ACCOUNTS=none - TAKING THE BOX, now, for the five-arm POOL-SIZE resident row-gate ladder at 4 MiB / n=4096: 4m-t16 unpinned t16 (builds the fixture, mixed, the known-broken control), 4m-e4 mask 0xF0 t4 (cores 4-7, four E), 4m-e8 mask 0xFF0 t8 (cores 4-11, eight E, SAME class - this step is the round), 4m-m12 mask 0xFFF t12 (cores 0-11, 4 P + 8 E, MIXED and stated as mixed, four LP-E cores left idle), 4m-p4 mask 0xF t4 (cores 0-3, four P). Rungs $Rungs, arms fold/force/force2/fold2, one rep, 100 legs. THE QUESTION the 17 Sep pinned round left owed: it found placement alone swings the crossover 42-52 rows at fixed pool size, three to four times the 14-row -t4/-t16 gap the one-rung-serves-both-pools clause rests on, so that gap is inside the confound. Moving 4 E to 8 E doubles the pool with the core class held fixed and needs no full-box arm, which matters because the -t16 arm is non-monotone at this shape in all three sittings it has had. I BUILD A BINARY AND A 39.7 GB FIXTURE FIRST, about 25 minutes, and that build was gated on this same lock-free-and-quiet check because a cargo build is foreign load too. Then about 2.5 h of ladders. FIVE LADDERS, ONE SITTING: wcomb takes the lock per ladder, so the gaps between them are NOT openings. Each ladder gates on lock-free AND no-parfast AND load under 25, and waits out an rc=17 LOCK-BUSY for up to 40 minutes rather than dying. Will post DONE with the box-as-left statement and will DELETE my root. Kill by pid, never by pattern."

if (-not $SkipProbe) { Probe-Classes }

# BUILD, from a git-archive of 06d5734b7 - the commit BOTH landed 4 MiB rounds
# and BOTH pinned sittings built - because arm 1 is a control against those
# ladders and arms 2 and 5 are ties to the pinned sitting's numbers, and a
# control against a different binary is not a control. The expected artefact is
# 4,173,312 bytes, and the round REFUSES on a mismatch rather than measuring a
# binary nothing else measured.
#
# THE GATE IS THE BYTE COUNT AND NOT THE sha256, AND THAT IS NOT A WEAKENING.
# The chip brief quotes sha256 fddb6aa3...95295f and says to verify it on the
# box. That hash CANNOT match here and matching it would be the surprise: the
# section "The CREATE at 4 MiB: it crosses BELOW the repair, and 416 is the
# wrong rung for it" records, of its own build of this same commit, "the same
# byte count as both repair rounds, A DIFFERENT HASH BECAUSE THE BUILD EMBEDS
# ITS OWN PATH". My root is poolladder-17sep where theirs was crg4-16sep and
# pinaff-16sep, so the embedded path differs and so must the hash. What that
# leaves invariant across all four builds of 06d5734b7 is the 4,173,312-byte
# length, which is what is gated. The hash is RECORDED on the log for
# provenance, never compared.
$WantBytes = 4173312
$RefSha    = 'FDDB6AA34283001A8437D5A7208EAE5F7D026F8F7E67330E78E9CB307F95295F'
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
    if (-not (Test-Path $tgz)) { Say "POOLLADDER-FAIL no source tree at $src and no tarball at $tgz"; exit 9 }
    New-Item -ItemType Directory -Force $src | Out-Null
    $xw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "tar -xzf `"$tgz`" -C `"$src`"" 
    $xrc = $LASTEXITCODE
    Say "EXTRACT rc=$xrc secs=$([math]::Round($xw.Elapsed.TotalSeconds,1)) into=$src"
    if ($xrc -ne 0) { Say "POOLLADDER-FAIL extract rc=$xrc"; exit 9 }
  }
  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Say "POOLLADDER-FAIL no Cargo.toml under $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line
  # of a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-poolladder.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-poolladder.log"
  if ($brc -ne 0) { Say "POOLLADDER-FAIL build rc=$brc"; exit 9 }
}
if (-not (Test-Path $Bin)) { Say "POOLLADDER-FAIL bin not found after build: $Bin"; exit 9 }
$gotSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$gotLen = (Get-Item $Bin).Length
Say "BIN bytes=$gotLen want_bytes=$WantBytes sha256=$gotSha ref_sha256=$RefSha sha_same=$($gotSha -eq $RefSha) (a DIFFERENT sha here is expected and not a fault - the build embeds its own path and this root is not theirs; the byte count is the invariant)"
if ($gotLen -ne $WantBytes) {
  Say "POOLLADDER-FAIL binary byte count want=$WantBytes got=$gotLen - this is NOT the 06d5734b7 artefact the banked ladders used, so arm 1 would not be a control and arms 2 and 5 would not be ties. Refusing rather than measuring it."
  exit 9
}
$fix = Join-Path $Root 'fix-4194304-1024'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused)' } else { 'ABSENT - ladder 1 builds it' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

$rc = 0
foreach ($a in $arms) {
  Wait-Quiet $a.tag 1
  if (-not $script:quietOk) { Say "POOLLADDER-ABORT load gate gave up before $($a.tag)"; $rc = 8; break }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pinned-pool-ladder EXTENSION - still running, still ONE sitting: arm $($a.tag) ($($a.what)), $($arms.Count) arms total"
  $log = Join-Path $logs "$($a.tag).log"
  $wcomb = Join-Path $here 'wcomb.ps1'
  $affArg = if ($a.aff) { " -Affinity $($a.aff)" } else { '' }
  $inner = "-NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$Root`" -Bin `"$Bin`" -NoBuild" +
           " -Phase rowgate -Tag $($a.tag) -Label $($a.label) -Slice 4194304 -MemberMiB 1024 -Recovery 640" +
           " -Rungs $Rungs -Threads $($a.threads) -Reps 1 -Residency resident -NttBudget $Budget" + $affArg
  Say "ARM $($a.tag) label=$($a.label) aff=$(if($a.aff){$a.aff}else{'none'}) threads=$($a.threads) log=$log"
  Say "ARGV powershell $inner"
  # cmd /c redirect, NOT Tee-Object: a Tee-Object log is UTF-16 and
  # harness/rowgate.py answers "REFUSED: no legs" on one.
  #
  # rc=17 IS THE ONE EXIT CODE WORTH WAITING OUT, and the narrowness is the
  # point - it is kept exactly as pinaff-round.ps1 has it. rc=17 is plib's
  # LOCK-BUSY: it means "somebody else has the box", never "this measurement is
  # wrong", because the ladder stopped before its first leg, so nothing was
  # measured and nothing is contaminated by asking again later. EVERY OTHER
  # NON-ZERO rc STILL ENDS THE ROUND ON THE SPOT, because those are the
  # instrument REFUSING - a residency violation, a path assertion, a work copy
  # that is not pristine, and now a binary whose sha256 is not 06d5734b7's -
  # and retrying one of those would launder a refusal into a number.
  $arc = 0; $legs = 0; $lockWaits = 0
  while ($true) {
    & cmd /c "powershell $inner > `"$log`" 2>&1"
    $arc = $LASTEXITCODE
    $legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
    if ($arc -ne 17) { break }
    $lockWaits++
    if ($lockWaits -gt 20) { Say "POOLLADDER-ARM-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  if ($arc -ne 0) { Say "POOLLADDER-ARM-FAILED $($a.tag) rc=$arc - see $log"; $rc = $arc; break }
}

Say "POOLLADDER-ROUND end rc=$rc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pinned-pool-ladder gen=86278d8d (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
