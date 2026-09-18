param(
  [string]$Root   = '<rig>\poolladder2-17sep',  # MY OWN root: src\ from a git-archive of 06d5734b7; binary and fixture built here
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Rungs  = '320,352,384,416,448',
  [string]$Budget = '21474836480',               # NZBFAST_NTT_BUDGET, 20 GiB - keeps every force leg resident
  [switch]$SkipProbe
)
# poolladder2-round.ps1 - the SECOND sitting of the 4 MiB pool-size ladder on
# GFNI-256, plus the arm the first sitting owed. Lane
# `parfast-4mib-pool8-class-isolation-17sep`; items 1 and 2 of
# an internal note, which says to run them
# together because item 2's arm is only readable against item 1's.
#
# Copied from poolladder-round.ps1 one directory up, with the arm table changed
# and nothing else. Read that file's header for the machinery; this one states
# only what is different and why.
#
# THE TWO QUESTIONS.
#
# 1. REPLICATE. The first sitting found the resident CPU crossover move 344 to
#    378 - +34 rows - when the pool doubled from four E-cores to eight with the
#    core class held fixed. That rests on ONE sitting. The stated sub-box
#    reproducibility envelope on this part is 3 to 7 rows, so +34 is far outside
#    the noise and the EFFECT is safe, but the NUMBER is not replicated, and the
#    pinned round that preceded it took two independent whole sittings before it
#    trusted its figures.
#
#    MORE REPS CANNOT DO THIS JOB, and the reason is mechanical rather than a
#    matter of taste: the A/A floor is a MAX over reps, so it is monotonically
#    non-decreasing in rep count - adding reps can only ever raise the bar a
#    rung has to clear, never firm the rung. Only an independent whole sitting
#    buys confidence. So this round is ONE rep per rung, exactly as the first
#    was, and it is a different sitting on a rebuilt fixture and a rebuilt
#    binary.
#
# 2. ISOLATE CLASS AT FIXED POOL SIZE EIGHT, which is the real open question and
#    the reason these two items ride one sitting. The first sitting moved pool 4
#    to pool 8 WITHIN the E class. It cannot say whether the +34 belongs to the
#    POOL or to the E CLASS, because E is the only class on this part wide
#    enough to grow: 4 P-cores and 4 LP-E cores are whole classes, and 8 E-cores
#    are the only eight of one kind. An arm at mask 0xFF - cores 0-3 (P) plus
#    4-7 (E), eight threads - sits at the SAME pool size as the 0xFF0 arm with a
#    different core mix, which isolates class at fixed pool size eight exactly
#    as the pinned sitting isolated it at fixed pool size four.
#
#    WHAT THE ANSWER LOOKS LIKE, written down before the legs run so it cannot
#    be fitted afterwards: the first sitting read 4m-e8 at 378 and 4m-p4 at 381.
#    If 0xFF at t8 lands NEAR 378, the +34 is the POOL. If it lands WELL ABOVE,
#    part of the +34 is the class and the pool term is smaller than the first
#    sitting says.
#
#    That arm was deliberately NOT run in the first sitting and its absence is
#    recorded at the site in poolladder-round.ps1 under "NOT RUN, and
#    deliberately". It is MIXED - four P and four E - and it is stated as mixed
#    everywhere it appears here. It must never be read as a third rung of the
#    within-class ladder; its ONLY comparison is against 4m2-e8 at the same pool
#    size in this same sitting.
#
# THE ARMS, in run order, each naming its mask AND its core classes:
#   1  4m2-t16                    -Threads 16   UNPINNED, all 16 cores, MIXED.
#                                   Runs first for the same mechanical reason it
#                                   did in the first sitting: wcomb builds the
#                                   16 GiB fixture on the FIRST ladder and
#                                   -Affinity arms EVERY leg including that
#                                   create, so a pinned arm first would build
#                                   37.8 GB on four cores. Its number is a
#                                   by-product and not this round's business -
#                                   but it is the FIFTH independent sitting of
#                                   an arm that has been non-monotone in three
#                                   of four, so it is labelled and banked rather
#                                   than thrown away, and item 3
#                                   (parfast-t16-peak-vs-budget-17sep) is the
#                                   lane that owns that question.
#   2  4m2-e8   0xFF0  (4-11)     -Threads 8    eight E-cores, ONE class. THE
#                                   REPLICATE: the first sitting's 378 rests on
#                                   one reading and this is the scarce one.
#                                   Second, not last, because a sitting cut
#                                   short must not lose it.
#   3  4m2-pe8  0xFF   (0-7)      -Threads 8    four P + four E. MIXED, AND
#                                   STATED AS MIXED. Same pool size as arm 2,
#                                   different core mix - THE NEW ARM, and with
#                                   arm 2 it is this round.
#   4  4m2-e4   0xF0   (4-7)      -Threads 4    four E-cores, same one class as
#                                   arm 2. The pool-4 anchor that makes arm 2 a
#                                   pool STEP rather than a lone number. LAST on
#                                   purpose: it already carries three banked
#                                   readings (343, 346, 344) across two prior
#                                   sittings, so it is the arm a short sitting
#                                   can afford to lose, where arms 2 and 3 are
#                                   not.
#
# NOT RUN, and deliberately: 4m-p4 (0xF, four P, t4) and 4m-m12 (0xFFF, t12).
# p4 has two banked readings (377/372) plus the first sitting's 381 and moves
# neither question; m12 was the spare-core test and that hypothesis is already
# dead, killed directly by the first sitting's t16 arm coming back monotone at
# 398 while leaving no core idle. Four ladders is about 100 minutes and five
# would be 125 for nothing either item asks.
#
# LABELS ARE ALL DISTINCT AND ALL CARRY THE `4m2-` PREFIX, and that is
# load-bearing twice over. rowgate.py groups by (label, threads), so arms 2 and
# 3 - both eight threads - would reduce into ONE group if they shared a label,
# which is precisely the comparison this round exists to make and would destroy
# it. And the prefix keeps every number here separable from the first sitting's
# `4m-` labels when both are read together, which they will be.
#
# PRIORITY IS NOT TOUCHED ON ANY ARM, for the reason both previous rounds give:
# arm 1 is a control against already-banked unpinned ladders and must differ
# from them in affinity and in nothing else.
#
# READING THE RESULT: CPU-SECONDS DO NOT COMPARE ACROSS MASKS. The first
# sitting's class probe read P/E at 1.74x on this part, so arm 3 (four P cores
# in it) will burn fewer CPU-seconds than arm 2 (none) for the same work and
# that is not arm 3 doing less. What compares is the CROSSOVER, because it is a
# ratio of fold to force WITHIN one arm on one core mix. Screen every ladder for
# MONOTONICITY as well as for its A/A floor before believing any crossover - a
# tight floor is evidence of AGREEMENT and not of correctness, and one rung of
# the pinned round reported a 0.5% floor while visibly broken, because the pair
# is blind to a perturbation that hits BOTH copies of a rung.
#
# CONTAMINATION. This driver is DETACHED and self-reporting; whoever launches it
# must poll at 600 s AT THE LOOSEST and preferably not at all, because every ssh
# poll spawns a PowerShell under sshd outside the round's pid tree and lands in
# the round's own foreign_cpu.
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
# Require-QuietBox, whose 10%-of-box ceiling is 160% of a core here and lets one
# saturated core through BY DESIGN. IT RETURNS NOTHING AND SETS $script:quietOk,
# which is plib's own convention and is not a style choice: `Say` writes its
# line to the OUTPUT stream, so a function that both logs and returns a bool
# returns an ARRAY of [string, ..., bool].
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

# The core-class probe. The first sitting's probe is banked and its numbers are
# quoted in the handoff, but it is re-run here rather than inherited, for the
# same reason the whole round is re-run: this is an INDEPENDENT sitting, and a
# probe carried over from the sitting being replicated would import exactly the
# thing under test. It reads core 0 (P), cores 4, 8 and 11 (E) and core 12
# (LP-E). Two premises rest on it. Arm 2 asserts cores 8-11 are the SAME CLASS
# as cores 4-7 - a core-8 time that does not match core 4's is a reason to throw
# arm 2 away rather than publish it. Arm 3 asserts cores 0-3 are a DIFFERENT
# class from 4-7, which is the entire content of the arm; if P and E came back
# equal here, arm 3 would not isolate anything. FIXED WORK, timed.
function Probe-Classes {
  $spin = @'
param([int]$Iters)
$sw=[Diagnostics.Stopwatch]::StartNew(); $x=0.0
for($i=0;$i -lt $Iters;$i++){ $x=$x+$i*1.000001 }
$sw.Stop(); "SPIN ms=$($sw.ElapsedMilliseconds) x=$x"
'@
  $f = Join-Path $here 'spin.ps1'; [IO.File]::WriteAllText($f, $spin)
  foreach ($m in @(@(0x1,'P-core0'), @(0x8,'P-core3'), @(0x10,'E-core4'), @(0x80,'E-core7'), @(0x100,'E-core8'), @(0x800,'E-core11'), @(0x1000,'LPE-core12'))) {
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
  @{ label = '4m2-t16'; aff = '';      threads = 16; tag = 'p2t16'; what = 'UNPINNED t16, all 16 cores (4 P + 8 E + 4 LP-E), MIXED - builds the fixture because -Affinity arms the create too; a by-product here, and the FIFTH sitting of an arm non-monotone in three of four' },
  @{ label = '4m2-e8';  aff = '0xFF0'; threads = 8;  tag = 'p2e8';  what = 'mask 0xFF0, cores 4-11, EIGHT E-CORES, ONE class - THE REPLICATE of the first sitting 378, which rests on one reading against a 3-to-7-row envelope' },
  @{ label = '4m2-pe8'; aff = '0xFF';  threads = 8;  tag = 'p2pe8'; what = 'mask 0xFF, cores 0-7, FOUR P + FOUR E, MIXED AND STATED AS MIXED - THE NEW ARM: same pool size as the arm above, different core mix, so it isolates CLASS at fixed pool size eight and says whether the +34 is the pool or the class' },
  @{ label = '4m2-e4';  aff = '0xF0';  threads = 4;  tag = 'p2e4';  what = 'mask 0xF0, cores 4-7, FOUR E-CORES, same one class - the pool-4 anchor that makes the e8 arm a STEP; last because it already has three banked readings at 343/346/344' }
)

Say "POOLLADDER2-ROUND start root=$Root bin=$Bin rungs=$Rungs budget=$Budget arms=$($arms.Count)"

# THE BUILD IS GATED LIKE A MEASUREMENT ARM, kept from the first sitting's
# driver, which is where that structural change was made and why. This round
# has to build a binary and a 37.8 GB fixture from scratch - the first sitting
# deleted poolladder-17sep at 17:39Z as it had promised, and there is nothing to
# inherit on this box - and a `cargo build --release` plus a 16 GiB create is
# foreign load to whoever is measuring, every bit as much as a ladder is. So the
# gate comes FIRST and the TAKING-THE-BOX line comes after it passes: until then
# this lane is queued and its 18:52Z QUEUED line says so in the same words.
Wait-Quiet 'prebuild' 2
if (-not $script:quietOk) { Say "POOLLADDER2-ABORT load gate gave up before the build"; exit 8 }
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pool8-class-isolation-17sep gen=b32f78ea (<user>, opus5 chip; an internal note, lease to 2026-09-18T05:54:58Z) ACCOUNTS=none - TAKING THE BOX, now, converting my 18:52Z QUEUED marker. The lock was free and the box quiet on two samples a minute apart. FOUR arms, resident row-gate ladder at 4 MiB / n=4096, rungs $Rungs, arms fold/force/force2/fold2, ONE rep, NttBudget 20 GiB: 4m2-t16 unpinned t16 (builds the fixture - -Affinity arms every leg including the create, so a pinned arm cannot go first); 4m2-e8 mask 0xFF0 cores 4-11 eight E t8 (the REPLICATE of the first sitting 378); 4m2-pe8 mask 0xFF cores 0-7 four P plus four E t8, MIXED AND STATED AS MIXED (THE NEW ARM); 4m2-e4 mask 0xF0 cores 4-7 four E t4 (the pool-4 anchor, last because it has three banked readings). WHAT THIS ASKS: the first sitting moved pool 4 to pool 8 within the E class and got +34 rows, but E is the only class on this part wide enough to grow, so it cannot say whether the +34 is the POOL or the CLASS. Mask 0xFF at t8 is the same pool size as 0xFF0 with a different core mix, which isolates class at fixed pool size eight exactly as the pinned sitting did at pool size four. Near 378 means the +34 is the pool; well above means part of it is the class. ONE REP AND NOT MORE, deliberately: the A/A floor is a MAX over reps and monotonically non-decreasing in rep count, so reps cannot firm a rung and only an independent whole sitting can. I BUILD A BINARY AND A 37.8 GB FIXTURE FIRST, about 25 minutes plus a ~745 s fixture settle while Windows Search walks the new files, and that build and extract were gated on this same lock-free-and-quiet check because a cargo build is foreign load too. Then about 100 minutes of ladders. FOUR LADDERS, ONE SITTING: wcomb takes the lock PER LADDER, so the gaps between them are NOT openings. Each ladder gates on lock-free AND no-parfast AND load under 25, and waits out plib's rc=17 LOCK-BUSY for up to 40 minutes rather than dying - every other non-zero rc ends the round on the spot, because those are the instrument refusing. Will post DONE with the box-as-left statement and will DELETE my root. Kill by pid, never by pattern."

if (-not $SkipProbe) { Probe-Classes }

# BUILD, from a git-archive of 06d5734b7 - the commit BOTH landed 4 MiB rounds,
# BOTH pinned sittings and the first pool sitting built - because this round's
# whole purpose is to be comparable to that first sitting, and a replicate
# against a different binary is not a replicate.
#
# THE GATE IS THE BYTE COUNT AND NOT THE sha256, AND THAT IS NOT A WEAKENING.
# Older briefs quote sha256 fddb6aa3...95295f. That hash CANNOT match here and
# matching it would be the surprise: the build embeds its own path, and this
# root is poolladder2-17sep where the others were crg4-16sep, pinaff-16sep and
# poolladder-17sep. Gating on it cost the first sitting a launch, whose log is
# banked one directory up as poolladder-attempt1-shagate.log. What is invariant
# across all five builds of 06d5734b7 is the 4,173,312-byte length, which is
# what is gated; the hash is RECORDED for provenance and never compared. A wrong
# LENGTH still ends the round rather than measuring a binary nothing else
# measured.
$WantBytes = 4173312
$RefSha    = 'FDDB6AA34283001A8437D5A7208EAE5F7D026F8F7E67330E78E9CB307F95295F'
if (-not (Test-Path $Bin)) {
  # Win32_Process::Create (wlaunch.ps1) does not always see the user's PATH, and
  # rustup's shims live in the profile. Same fix wcomb.ps1 carries.
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  $src = Join-Path $Root 'src'
  # EXTRACT INSIDE THE GATED REGION, not at staging time. The 112 MB tarball is
  # scp'd up before launch - that is network work and costs the box little - but
  # unpacking ~25,000 files is disk and CPU that lands on whoever is measuring,
  # so it waits behind the same gate the build does.
  if (-not (Test-Path $src)) {
    $tgz = Join-Path $Root 'src-06d5734b7.tar.gz'
    if (-not (Test-Path $tgz)) { Say "POOLLADDER2-FAIL no source tree at $src and no tarball at $tgz"; exit 9 }
    New-Item -ItemType Directory -Force $src | Out-Null
    $xw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "tar -xzf `"$tgz`" -C `"$src`""
    $xrc = $LASTEXITCODE
    Say "EXTRACT rc=$xrc secs=$([math]::Round($xw.Elapsed.TotalSeconds,1)) into=$src"
    if ($xrc -ne 0) { Say "POOLLADDER2-FAIL extract rc=$xrc"; exit 9 }
  }
  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Say "POOLLADDER2-FAIL no Cargo.toml under $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line of
  # a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-poolladder2.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-poolladder2.log"
  if ($brc -ne 0) { Say "POOLLADDER2-FAIL build rc=$brc"; exit 9 }
}
if (-not (Test-Path $Bin)) { Say "POOLLADDER2-FAIL bin not found after build: $Bin"; exit 9 }
$gotSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$gotLen = (Get-Item $Bin).Length
Say "BIN bytes=$gotLen want_bytes=$WantBytes sha256=$gotSha ref_sha256=$RefSha sha_same=$($gotSha -eq $RefSha) (a DIFFERENT sha here is expected and not a fault - the build embeds its own path and this root is not theirs; the byte count is the invariant)"
if ($gotLen -ne $WantBytes) {
  Say "POOLLADDER2-FAIL binary byte count want=$WantBytes got=$gotLen - this is NOT the 06d5734b7 artefact the first sitting measured, so this round would not be a replicate of it. Refusing rather than measuring it."
  exit 9
}
$fix = Join-Path $Root 'fix-4194304-1024'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused)' } else { 'ABSENT - ladder 1 builds it' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

$rc = 0
foreach ($a in $arms) {
  Wait-Quiet $a.tag 1
  if (-not $script:quietOk) { Say "POOLLADDER2-ABORT load gate gave up before $($a.tag)"; $rc = 8; break }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pool8-class-isolation-17sep EXTENSION - still running, still ONE sitting: arm $($a.tag) ($($a.what)), $($arms.Count) arms total"
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
  # point - it is kept exactly as the first sitting has it. rc=17 is plib's
  # LOCK-BUSY: it means "somebody else has the box", never "this measurement is
  # wrong", because the ladder stopped before its first leg, so nothing was
  # measured and nothing is contaminated by asking again later. EVERY OTHER
  # NON-ZERO rc STILL ENDS THE ROUND ON THE SPOT, because those are the
  # instrument REFUSING - a residency violation, a path assertion, a work copy
  # that is not pristine, a binary of the wrong length - and retrying one of
  # those would launder a refusal into a number.
  $arc = 0; $legs = 0; $lockWaits = 0
  while ($true) {
    & cmd /c "powershell $inner > `"$log`" 2>&1"
    $arc = $LASTEXITCODE
    $legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
    if ($arc -ne 17) { break }
    $lockWaits++
    if ($lockWaits -gt 20) { Say "POOLLADDER2-ARM-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  if ($arc -ne 0) { Say "POOLLADDER2-ARM-FAILED $($a.tag) rc=$arc - see $log"; $rc = $arc; break }
}

Say "POOLLADDER2-ROUND end rc=$rc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pool8-class-isolation-17sep gen=b32f78ea (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
