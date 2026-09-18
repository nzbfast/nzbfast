param(
  [string]$Root   = '<rig>\pinaff-16sep',  # MY OWN root: src\ from a git-archive of 06d5734b7; binary and fixture built here
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Rungs  = '320,352,384,416,448',
  [string]$Budget = '21474836480',               # NZBFAST_NTT_BUDGET, 20 GiB - keeps every force leg resident
  [switch]$SkipProbe
)
# pinaff-round.ps1 - the four-arm pinned-affinity resident row-gate ladder at
# 4 MiB on GFNI-256, for lane parfast-4mib-pinned-affinity-pools.
#
# THE QUESTION. The 16 Sep 4 MiB rounds found that the four-thread pool crosses
# BELOW the sixteen-thread one (resident ~391 against ~405), inverting the
# 1 MiB ordering, and the recommendation that ONE second rung at 416 serves
# both pools rests on that inversion being small. But the `-t4` legs were NOT
# affinity-pinned and this part has THREE core classes (0-3 P, 4-11 E, 12-15
# LP-E) with a documented 1.43x single-thread swing from placement alone. So
# "four threads vs sixteen threads" is confounded with "fast cores vs mixed
# cores". These four arms separate them.
#
# THE ARMS, and the ONLY thing that differs between them is the CPU mask:
#   1  4m-p4          -Affinity 0xF  -Threads 4    four P-cores
#   2  4m-t4-unpinned                -Threads 4    the landed round's arm, the CONTROL
#   3  4m-t16                        -Threads 16   the landed round's other arm
#   4  4m-e4          -Affinity 0xF0 -Threads 4    four E-cores
#
# PRIORITY IS NOT TOUCHED ON ANY ARM. The pattern this copies
# (an internal note) sets PriorityClass High as
# well as the mask; this round must not, because arms 2 and 3 are controls
# against ALREADY-BANKED unpinned ladders and must differ from them in affinity
# and in nothing else. Raising priority on the pinned arms alone would make
# placement and priority move together and leave neither readable.
#
# ORDER IS DELIBERATE: most load-bearing first, so a sitting cut short still
# answers the question. Arm 1 against arm 3 IS the question (pool size held at
# the two ends, core mix held equal at the fast end); arm 2 is what makes the
# round comparable to the banked one at all, so it runs second rather than
# last; arm 4 brackets the `-t16` mix from the SLOW side, so that 1 and 4
# straddle 3 - if they do not straddle it, something other than core mix is
# moving and that is itself a finding.
#
# READING THE RESULT: CPU-SECONDS DO NOT COMPARE ACROSS ARMS. A P-core second
# and an E-core second buy different work, so arm 4's raw `cpu=` must never be
# read against arm 1's. What compares is the CROSSOVER, which is a ratio of
# fold to force WITHIN one arm on one core mix. Reduce per arm on the Mac with
# `python3 harness/rowgate.py read <log>` - it groups by (label,
# threads), which is why every arm carries a DISTINCT -Label.
#
# CONTAMINATION, WHICH COST THREE LANES A CELL EACH ON 16 Sep 2026 by three
# different mechanisms, none visible to the cheap lock-plus-parfast free-check:
# a concurrent round that took neither, a lane running probes WHILE IT WAITED
# (this lane, 14:43-14:45Z - see the NOTE on the coordination file), and a
# session CONTAMINATING ITS OWN ROUND BY WATCHING IT, since every ssh poll
# spawns a PowerShell under sshd outside the round's pid tree and PowerShell
# 5.1 startup is about a core-second. So: this driver is DETACHED and
# self-reporting, it gates every ladder on load as well as lock-and-parfast,
# and whoever launches it must poll it at a 10-MINUTE cadence, not a tight one.
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
# one saturated core through BY DESIGN. Two samples a minute apart before the
# first ladder and after any busy sample; a single sample between own ladders.
# IT RETURNS NOTHING AND SETS $script:quietOk, which is plib's own convention
# for Require-QuietBox and is not a style choice: `Say` writes its line to the
# OUTPUT stream, so a function that both logs and returns a bool returns an
# ARRAY of [string, string, ..., bool], and `if (-not (Wait-Quiet ...))` then
# tests an array rather than the verdict. plib's header records the same trap
# from the other side ("NOT `$foreign = Require-QuietBox ...`. That captures
# the guard's log lines along with its reading").
function Wait-Quiet([string]$where, [int]$samples) {
  $script:quietOk = $false
  $capS = 3600; $t0 = Get-Date
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

# The core-class probe. `.claude/MACHINES.md` says cores 0-3 are P and 4-11 E,
# from the firmware's event 55 - but this round's arm NAMES rest on that, so it
# is checked here rather than trusted. FIXED WORK, timed: an earlier version of
# this probe ran a fixed WALL and measured nothing, which is why the shape is
# spelled out. Expect four P-cores to finish materially faster than four E.
function Probe-Classes {
  $spin = @'
param([int]$Iters)
$sw=[Diagnostics.Stopwatch]::StartNew(); $x=0.0
for($i=0;$i -lt $Iters;$i++){ $x=$x+$i*1.000001 }
$sw.Stop(); "SPIN ms=$($sw.ElapsedMilliseconds) x=$x"
'@
  $f = Join-Path $here 'spin.ps1'; [IO.File]::WriteAllText($f, $spin)
  foreach ($m in @(@(0x1,'P-core0'), @(0x10,'E-core4'), @(0x1000,'LPE-core12'))) {
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

# ORDER. The FIRST arm builds the 16 GiB fixture (wcomb creates it when
# absent), and -Affinity arms EVERY leg of its invocation including that
# create - so a pinned arm first would build the fixture on four cores instead
# of sixteen. `4m-t16` is therefore first: it is unpinned, it builds the
# fixture at full box speed, and it is a control rather than a throwaway.
# It also puts the two arms that ANSWER the question - pinned-4P against the
# full-box mix - adjacent and first, so a sitting cut short after two ladders
# still answers it, after three also carries the control that ties this round
# to the banked one, and only the E-core bracket is lost.
$arms = @(
  @{ label = '4m-t16';         aff = '';     threads = 16; tag = 'pint16'; what = 'unpinned -t16, the CONTROL for the landed ~405; builds the fixture' },
  @{ label = '4m-p4';          aff = '0xF';  threads = 4;  tag = 'pinp4';  what = 'four P-cores (0-3) - with the arm above, THE comparison' },
  @{ label = '4m-t4-unpinned'; aff = '';     threads = 4;  tag = 'pint4';  what = 'unpinned -t4, the CONTROL for the landed ~391' },
  @{ label = '4m-e4';          aff = '0xF0'; threads = 4;  tag = 'pine4';  what = 'four E-cores (4-7) - brackets the -t16 mix from the SLOW side' }
)

Say "PINAFF-ROUND start root=$Root bin=$Bin rungs=$Rungs budget=$Budget arms=$($arms.Count)"

# The round may INHERIT its binary and fixture from
# parfast-create-rowgate-4mib-gfni256, or build its own, and which one happened
# is a fact about the evidence rather than a detail: arms 1 and 3 are controls
# against ladders built from 06d5734b7, so the provenance belongs on the
# coordination file and in the write-up, not in a lane's memory. COMPUTED here
# rather than asserted, because this lane sampled the shared root at 15:04Z
# between that lane's staging and its run, read it as bare, and was wrong.
$fixPath = Join-Path $Root 'fix-4194304-1024'
$prov = if ((Test-Path $Bin) -and (Test-Path $fixPath)) {
  "INHERITING the binary and the 16 GiB fixture from parfast-create-rowgate-4mib-gfni256 at $Root, as agreed, rather than building 16 GiB twice"
} elseif (Test-Path $Bin) {
  "INHERITING the binary at $Root; the fixture is absent and ladder 1 builds it"
} else {
  "BUILDING my own binary and 16 GiB fixture at $Root from a git-archive of 06d5734b7 - nothing was there to inherit"
}
Say "PROVENANCE $prov"
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pinned-affinity-pools gen=0d3406c2 (<user>, opus5 chip) ACCOUNTS=none - TAKING THE BOX for the four-arm pinned-affinity resident row-gate ladder at 4 MiB on GFNI-256: unpinned -t16, pinned 4 P-cores (0xF), unpinned -t4, pinned 4 E-cores (0xF0), rungs $Rungs, arms fold/force/force2/fold2, one rep, 80 legs. THE QUESTION: the 16 Sep -t4 round was not affinity-pinned and this part has three core classes with a 1.43x placement swing, so its pool inversion is confounded with core mix, and the recommendation that one second rung serves both pools rests on it. Affinity is the ONLY thing that moves between arms; priority stays Normal on every arm so the unpinned arms remain controls against the banked ladders. $prov. Expect ~2.5 h of ladders. Each ladder gates on lock-free AND no-parfast AND load under 25. Will post DONE with the box-as-left statement. Kill by pid, never by pattern."


# BUILD ONLY IF THERE IS NOTHING TO INHERIT, and the block above computes
# which. THE COMMENT THAT USED TO SIT HERE WAS WRONG AND IS THE REASON THE
# PROVENANCE IS COMPUTED AT RUN TIME AT ALL: it said crg4-16sep held only a
# source tree because parfast-create-rowgate-4mib-gfni256 had stood down before
# building anything, on the strength of ONE `ls` of that lane's root taken at
# 15:04Z while it was mid-build. That lane did not stand down - it re-queued,
# ran, posted DONE at 16:06:55Z, and left the binary and the 39,737,780,165 B
# fixture behind deliberately for this round. An empty-looking round root means
# "not started yet" at least as often as "abandoned", the same way an AWOL claim
# means "nobody said what happened" rather than "this is free".
#
# When the build DOES happen it is from a git-archive of 06d5734b7 - the commit
# BOTH landed 4 MiB rounds built - because arms 2 and 3 are controls against
# those rounds and a control against a different binary is not a control.
if (-not (Test-Path $Bin)) {
  # Win32_Process::Create (wlaunch.ps1) does not always see the user's PATH,
  # and rustup's shims live in the profile. Same fix wcomb.ps1 carries.
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  $src = Join-Path $Root 'src'
  if (-not (Test-Path $src)) { Say "PINAFF-FAIL no source tree at $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line
  # of a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-pinaff.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-pinaff.log"
  if ($brc -ne 0) { Say "PINAFF-FAIL build rc=$brc"; exit 9 }
}
if (-not (Test-Path $Bin)) { Say "PINAFF-FAIL bin not found after build: $Bin"; exit 9 }
Say "BIN sha256=$((Get-FileHash $Bin -Algorithm SHA256).Hash) bytes=$((Get-Item $Bin).Length)"
# The fixture is built by the FIRST ladder (wcomb creates it when absent) and
# reused by the other three. Wait-FixtureSettle then holds ladder 1 until
# Windows Search has finished walking it - on 16 Sep that was 589 s on one
# round and 977 s on another, and it is the whole reason ladder 1 is the one
# that would otherwise pay for the fixture.
$fix = Join-Path $Root 'fix-4194304-1024'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused)' } else { 'ABSENT - ladder 1 builds it' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null


$rc = 0
$probed = $false
foreach ($a in $arms) {
  $first = ($a.tag -eq $arms[0].tag)
  Wait-Quiet $a.tag $(if ($first) { 2 } else { 1 })
  if (-not $script:quietOk) { Say "PINAFF-ABORT load gate gave up before $($a.tag)"; $rc = 8; break }
  # The class probe runs INSIDE the sitting, after the first load gate has
  # passed - never before it. A probe is foreign load exactly like anybody
  # else's round, and running one while another lane measured is what this
  # lane did to create-width-additive-kernel-gfni-16sep at 14:43-14:45Z on
  # 16 Sep 2026 (see the NOTE on the coordination file). It is ~15 s of
  # single-core work and it belongs to my box time, not to somebody else's.
  if (-not $probed -and -not $SkipProbe) { Probe-Classes; $probed = $true }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pinned-affinity-pools EXTENSION - still running: arm $($a.tag) ($($a.what)), $($arms.Count) arms total"
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
  # ARM 4 OF THE PREVIOUS ATTEMPT DIED ON THE LINE BELOW, AND THIS LOOP IS WHY
  # THE ITEM IS BEING RUN A THIRD TIME. `wcomb` takes the rig lock PER LADDER,
  # so a four-arm round is four acquisitions and every gap between them is an
  # opening that reads, to anybody honouring the lock, exactly like the end of
  # a round. On 16 Sep 2026 arm 3 released at 18:25:40Z, another lane took the
  # lock 0.6 s later, arm 4 asked at 18:25:42Z and got LOCK-BUSY - and plib
  # exits 17 on that (plib.ps1 ~line 370), which the unconditional `break`
  # here turned into the loss of the whole arm and of the sitting's answer.
  # NEITHER LANE DID ANYTHING WRONG: the lock was genuinely free at the instant
  # each asked, which is why the fix belongs here and not on the takers.
  #
  # rc=17 IS THE ONE EXIT CODE WORTH WAITING OUT, and the narrowness is the
  # point. It means "somebody else has the box", never "this measurement is
  # wrong": the ladder stopped before its first leg, so nothing was measured
  # and nothing is contaminated by asking again later. Every other non-zero rc
  # still ends the round on the spot, because those are the instrument
  # REFUSING - a residency violation, a path assertion, a work copy that is not
  # pristine - and retrying one of those would just launder a refusal into a
  # number. The coordination line this round posts asks that the inter-ladder
  # gaps not be taken; this is what happens when somebody does not see it.
  #
  # The wait is BOUNDED, because an inter-ladder hand-over is minutes and a box
  # held for the best part of an hour is a queue this round should leave rather
  # than camp on: 20 waits of 120 s is 40 minutes per arm.
  $arc = 0; $legs = 0; $lockWaits = 0
  while ($true) {
    & cmd /c "powershell $inner > `"$log`" 2>&1"
    $arc = $LASTEXITCODE
    $legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
    if ($arc -ne 17) { break }
    $lockWaits++
    if ($lockWaits -gt 20) { Say "PINAFF-ARM-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  if ($arc -ne 0) { Say "PINAFF-ARM-FAILED $($a.tag) rc=$arc - see $log"; $rc = $arc; break }
}

Say "PINAFF-ROUND end rc=$rc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-4mib-pinned-affinity-pools gen=0d3406c2 (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
