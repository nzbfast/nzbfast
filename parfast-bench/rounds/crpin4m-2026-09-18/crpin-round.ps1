param(
  [string]$Root   = '<rig>\crpin-18sep',
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Budget = '21474836480',               # NZBFAST_NTT_BUDGET, 20 GiB - keeps every force leg resident
  [switch]$SkipProbe
)
# crpin-round.ps1 - FIVE create-phase ladders in ONE sitting off ONE fixture,
# for lane parfast-pinned-band-ladder-4mib. Item 1 of
# an internal note.
#
# A copy of rounds/crband-2026-09-18/crband-round.ps1 (per-ladder rungs
# in the arm table) with crpool4m's `aff` column restored and ONE new stage: the
# fine ladders' rungs are COMPUTED ON THIS BOX, between ladder 3 and ladder 4,
# from the crossovers ladders 2 and 3 just wrote. Everything else - the load
# gate, the byte gate, the rc=17 retry, the detached launch, the
# extract-inside-the-gate discipline - is inherited and unchanged.
#
# ============================== THE QUESTION ==============================
#
# the maintainer's wall-time rule (memory topic nzbfast-wall-time-is-the-deciding-metric)
# carries a limit: wall wins a disagreement "unless there's something excessive
# and it's an extremely unfair trade, like, 10x the cpu for a little bit better
# wall". THE BAND BETWEEN THE CPU CROSSOVER AND THE WALL CROSSOVER IS THE ONLY
# REGION WHERE THE TWO METRICS DISAGREE, so it is the only region where that
# limit can ever bite. It has never been priced on the CREATE path. Two rounds
# have tried and both failed for the SAME reason, from opposite directions:
#
#   * crpool4m (17 Sep) had a 32-row rung grid and bands 6-24 rows wide, so
#     every band fell BETWEEN measured rungs. CPU and wall agreed at every rung
#     it measured, which is an artefact of the grid and not a finding.
#   * crband (18 Sep) put 8-row rungs exactly where crpool4m's WIDEST band had
#     been, and MISSED - because the band MOVED. In crband's own sitting that
#     arm's band was [359, 394] and the ladder sat mostly above it.
#
# THE SECOND FAILURE IS WHAT MAKES THIS ROUND POSSIBLE. crband measured why: on
# an UNPINNED arm the band's LOCATION moves 30 rows between sittings while the
# band is 6-35 rows wide, so it cannot be aimed at. PINNED arms replicate
# within 5 rows (repair path, two sittings: 344->349, 378->377, 398->401). So
# the order of operations is PIN, then FIND THE BAND, then place the fine rungs
# - and the finding step has to happen IN THIS SITTING, because "replicates
# within 5" is a claim about 5 rows and the rung spacing here is 4.
#
# =============================== THE HARNESS ===============================
#
# THIS ROUND USES A NEWER HARNESS THAN crpool4m, WHICH IT IS REPLICATING, and
# that is checked rather than assumed - the class of defect this campaign keeps
# finding. Eight commits touch plib.ps1/wcomb.ps1 between crpool4m's e1731b0ee
# and this round's tip. Diffed:
#
#   * Invoke-Leg - THE FUNCTION THAT PRODUCES `wall` AND `cpu` - is BYTE-
#     IDENTICAL between the two (sha of the function body a70460e39b66 both
#     sides). So is Measure-ForeignDelta. This is a STRONGER statement than
#     crband could make about its own harness delta: crband argued its delta
#     could not reach an UNPINNED leg because the affinity block is guarded by
#     `if ($affWant)`; a byte-identical timing function covers PINNED legs too,
#     which is what this round runs.
#   * wcomb's delta is entirely (a) -Rungs/-Threads validation before the rig
#     lock, (b) a -Residency/-Phase measure refusal, neither of which this
#     round trips, (c) the create-path affinity readback assert, which fires
#     AFTER the leg and REFUSES it rather than changing the work it did, and
#     (d) two new LEG fields plus an exception log. None of it changes a leg.
#   * WHAT DOES DIFFER: Get-OwnPidTree was refactored into Resolve-OwnPidSet,
#     which is the own-pid set feeding FOREIGN-CPU accounting. So foreign_cpu
#     here is NOT a like-for-like instrument with crpool4m's and is quoted
#     WITHIN this sitting only, never across the two.
#
# THE PINS ARE ASSERTED, and crpool4m's were not. Run-Create got the affinity
# readback assert in 3bbe3d94d, so every pinned LEG line carries `affinity=`
# and `affinity_got=` and wcomb refuses the leg on a mismatch. crpool4m had to
# argue its pins from timings; this round reads them back. The round record
# states whether all pinned legs carry them EQUAL.
#
# ============================== THE FIVE LADDERS =============================
#
#   1  cpwarm  UNPINNED  -t16  rungs 288,320,352,384,416       builds the fixture
#   2  cpe8    0xFF0     -t8   rungs 288..512 (crpool4m's grid) replicate + AIM
#   3  cpp4    0xF       -t4   rungs 288..512 (crpool4m's grid) replicate + AIM
#   4  cpe8f   0xFF0     -t8   rungs COMPUTED from ladder 2's own crossovers
#   5  cpp4f   0xF       -t4   rungs COMPUTED from ladder 3's own crossovers
#
# THE ORDERING IS NOT FREE HERE, unlike crband's, and it is forced: -Affinity
# arms EVERY leg INCLUDING the fixture create, so a pinned ladder cannot be
# first. LADDER 1 IS UNPINNED AND BUILDS THE FIXTURE. Its numbers are a bonus -
# it adds a fifth reading to the four banked unpinned -t16 create crossovers,
# which span 30 rows and which crband established are not a measurable quantity
# at this resolution. Nothing here rests on it.
#
# ITS FIRST RUNG IS SPENT ON PURPOSE. Three of three fixture-building ladders in
# this campaign show a warm-up ramp confined to the first rung, with A/A floors
# of 9.6% / 15.7% / 35.5% against 0.1-2% typical. crband put its first rung
# INSIDE the region it was measuring and lost it. m=288 is far below every
# banked unpinned -t16 crossover (357, 359, 365, 387), so the ramp lands on a
# rung nothing depends on. NOTE the ramp is a property of BUILDING THE FIXTURE,
# not of being first: ladders 2-5 do not build one, so their bottom rungs are
# not discounted - which is crband's own finding ("no other ladder does").
#
# LADDERS 2 AND 3 DO TWO JOBS AT ONCE and that is why they must not be cut:
#   (a) they REPLICATE crpool4m's pinned CREATE crossovers (e8 393/409,
#       p4 394/410) on the same grid with a byte-identical timing function,
#       which tests the 5-row pinned-replication claim ON THE CREATE PATH - it
#       has only ever been shown on the repair path; and
#   (b) they LOCATE each arm's band in THIS sitting, which is what ladders 4
#       and 5 are aimed off.
# If the sitting must be cut, 4 and 5 are the deliverable and 2 and 3 are what
# aims them - so cutting 2 or 3 does not save a deliverable, it destroys one.
#
# LADDERS 4 AND 5 ARE PLACED BY bandplan.py, ON THIS BOX, FROM THIS SITTING'S
# LOGS, at 4-ROW spacing. Four and not eight: crpool4m's pinned bands are 16
# rows and an 8-row grid fits only two rungs in 16. bandplan.py REFUSES rather
# than guesses - if a coarse ladder never crossed in range, rowgate prints
# `<288` or `?` and there is no band to aim at, so the fine ladder is SKIPPED
# and the round record says so. IT NEVER FALLS BACK TO A BANKED BAND: aiming at
# yesterday's band is the exact move that cost crband its ladder.
#
# ====================== WHAT THIS ROUND DOES NOT LICENSE ======================
# Written BEFORE the sitting, so it cannot be trimmed to fit the numbers - the
# practice crpool4m and crband both used, and the reason both rounds' conclusions
# held when their numbers would have allowed a stronger claim.
#
# NO CONSTANT MOVES. The rung decision - 384 against 416 against
# create_ntt_min_rows taking its own clause at ~372 - is the maintainer's, it is open, and
# five lanes have now measured inputs without moving anything. This is the
# sixth. No sentence in this write-up may be read as a decision having been
# taken, and anything downstream citing it as "384 ships" is citing it wrongly.
#
# A PRICED BAND IS NOT A CHOSEN RUNG. This produces a trade ratio per rung. A
# ratio under 10x does not say a rung is right; it says the proportionality
# limit does not EXCLUDE it. Only the second claim is this round's.
#
# AN UNRESOLVED BAND IS NOT A CLEAN BILL. A narrow band means small
# differences, so rungs coming back inside their own A/A floors is the EXPECTED
# case, not a failure. The honest statement is then "the trade cannot be priced
# at this resolution on this part" - NOT "the trade is small", and NOT "the
# metrics agree". NO TOLERANCE IS WIDENED TO MANUFACTURE A VERDICT.
#
# A PINNED BAND IS NOT AN UNPINNED ONE. Whatever ratio comes out is a ratio for
# a pinned arm on a fixed core mix. crpool4m measured placement ALONE swinging
# the create crossover 27 rows at fixed pool size, so these figures do not
# transfer to a machine running unpinned, which is every user.
#
# REPLICATION IS A TWO-SITTING CLAIM. If ladders 2 and 3 land within 5 rows of
# crpool4m's, that is ONE independent repeat on the create path, which is what
# the repair path already has. It is not a general claim that pinned create
# arms are stable, and one sitting is not a replicate. More reps cannot firm a
# rung: the A/A floor is a MAX over reps.
#
# ONE PART, ONE PAYLOAD, ONE BLOCK SIZE. Core Ultra 9 386H, random bytes, 4 MiB,
# n = 4,096. No other box on this fleet is GFNI-256.
#
# ========================= READING AND HYGIENE RULES =========================
# WALL DECIDES, CPU EXPLAINS. Both crossovers are quoted on every table and any
# divergence is named with its size.
# CPU-SECONDS DO NOT COMPARE ACROSS MASKS - P/E is ~1.72-1.74x on this part, so
# an 8 E-core arm burning more CPU than a 4 P-core arm is not doing more work.
# Only the CROSSOVER compares across arms.
# A TIGHT A/A FLOOR IS AGREEMENT, NOT CORRECTNESS. Every ladder is screened with
# ladder-monotonicity-audit.py, and the rungs BRACKETING each crossing are
# checked for firmness - AND, per crband, the bracketing rung's own distance
# from F/T = 1 must exceed that rung's A/A floor, a test three of four banked
# unpinned readings FAIL.
# CONTAMINATION. This driver is DETACHED and self-reporting. Poll at 600 s at
# the loosest and preferably not at all: every ssh poll spawns a PowerShell
# under sshd outside the round's pid tree and lands in the round's own
# foreign_cpu.
$ErrorActionPreference = 'Stop'
if (-not $Bin) { $Bin = Join-Path $Root 'src\target\release\parfast.exe' }
$here  = $PSScriptRoot
$logs  = Join-Path $here 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null
. (Join-Path $here 'plib.ps1')

function Say([string]$m) { "$(Get-Date -Format o) $m" }
function Post([string]$line) {
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
# trusted. Ladder 2 asserts that cores 8-11 are the SAME CLASS as cores 4-7,
# which is the premise of the only within-class pool the part can offer, so the
# probe reads core 8 as well and a core-8 time that does not match core 4's is
# a reason to throw the arm away rather than to publish it. FIXED WORK, timed.
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

# Run one ladder. Factored out because ladders 4 and 5 are dispatched from a
# second loop, after their rungs exist - and a second COPY of this block is
# exactly how the two halves would drift apart.
#
# IT RETURNS NOTHING AND SETS $script:ladderRc, for the same reason Wait-Quiet
# sets $script:quietOk and which is NOT a style choice: `Say` writes its line to
# the OUTPUT stream, so a function that both LOGS and RETURNS would hand the
# caller an ARRAY of [string, string, ..., rc] and `if ($arc -ne 0)` would then
# be comparing an array to 0. plib's own convention, and the comment on
# Wait-Quiet above is where it is written down.
function Invoke-Ladder($a) {
  $script:ladderRc = 0
  Wait-Quiet $a.tag 1
  if (-not $script:quietOk) { Say "CRPIN-ABORT load gate gave up before $($a.tag)"; $script:ladderRc = 8; return }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-pinned-band-ladder-4mib EXTENSION - still running, still ONE sitting: ladder $($a.tag) ($($a.what)), 5 ladders total"
  $log   = Join-Path $logs "$($a.tag).log"
  $wcomb = Join-Path $here 'wcomb.ps1'
  $affArg = if ($a.aff) { " -Affinity $($a.aff)" } else { '' }
  $inner = "-NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$Root`" -Bin `"$Bin`" -NoBuild" +
           " -Phase create -Tag $($a.tag) -Label $($a.label) -Slice 4194304 -MemberMiB 1024 -Recovery 640" +
           " -Rungs `"$($a.rungs)`" -Threads `"$($a.threads)`" -Reps 1 -Residency resident -NttBudget $Budget" + $affArg
  Say "LADDER $($a.tag) label=$($a.label) aff=$(if($a.aff){$a.aff}else{'none (UNPINNED)'}) threads=$($a.threads) rungs=$($a.rungs) log=$log"
  Say "ARGV powershell $inner"
  # cmd /c redirect, NOT Tee-Object: a Tee-Object log is UTF-16 and
  # harness/rowgate.py answers "REFUSED: no legs" on one - which would
  # also take bandplan.py down with it, since it reads rowgate's output.
  #
  # rc=17 IS THE ONE EXIT CODE WORTH WAITING OUT, and the narrowness is the
  # point. rc=17 is plib's LOCK-BUSY: it means "somebody else has the box",
  # never "this measurement is wrong", because the ladder stopped before its
  # first leg, so nothing was measured and nothing is contaminated by asking
  # again later. EVERY OTHER NON-ZERO rc STILL ENDS THE ROUND ON THE SPOT,
  # because those are the instrument REFUSING - a residency violation, a path
  # assert, an AFFINITY READBACK MISMATCH, a cross-arm hash that does not match
  # - and retrying one of those would launder a refusal into a number.
  $arc = 0; $legs = 0; $lockWaits = 0
  while ($true) {
    & cmd /c "powershell $inner > `"$log`" 2>&1"
    $arc = $LASTEXITCODE
    $legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
    if ($arc -ne 17) { break }
    $lockWaits++
    if ($lockWaits -gt 20) { Say "CRPIN-LADDER-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  # The pins are ASSERTED by wcomb, but the round record has to be able to SAY
  # so, so count the readbacks here rather than trusting the absence of a
  # failure. A pinned ladder whose legs carry no affinity= field at all would
  # be a harness older than 3bbe3d94d - which is the silent-wrong case.
  if ($a.aff) {
    $legLines = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue | ForEach-Object { $_.Line })
    $withAff  = @($legLines | Where-Object { $_ -match 'affinity=0x' })
    $equal    = @($legLines | Where-Object { $_ -match 'affinity=(0x[0-9A-Fa-f]+) .*affinity_got=\1( |$)' })
    Say "AFFINITY-AUDIT $($a.tag) want=$($a.aff) legs=$($legLines.Count) with_affinity_field=$($withAff.Count) readback_equal=$($equal.Count)"
    if ($legLines.Count -gt 0 -and $equal.Count -ne $legLines.Count) {
      Say "CRPIN-AFFINITY-AUDIT-MISMATCH $($a.tag) - $($equal.Count) of $($legLines.Count) legs read their mask back equal. wcomb should have refused; read the log before believing ANY number from this ladder."
    }
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  $script:ladderRc = $arc
}

# THE COARSE LADDERS. Ladder 1 is unpinned and MUST be first (-Affinity arms the
# fixture create too). Ladders 2 and 3 are crpool4m's two pinned arms on
# crpool4m's own grid.
$coarse = @(
  @{ label = '4mcp-warm'; aff = '';      threads = '16'; rungs = '288,320,352,384,416';             tag = 'cpwarm'; what = 'UNPINNED t16 - BUILDS THE 16 GiB FIXTURE, so it must run first; -Affinity would otherwise pin the fixture create. m=288 is a SPENT warm-up rung by design. Its crossover is a bonus fifth reading of a quantity crband showed is not measurable at this resolution, and nothing here rests on it' },
  @{ label = '4mc-e8';    aff = '0xFF0'; threads = '8';  rungs = '288,320,352,384,416,448,480,512'; tag = 'cpe8';   what = 'mask 0xFF0, cores 4-11, EIGHT E-CORES, one class, on crpool4m grid - replicates crpool4m create CPU 393 / wall 409 AND locates this arm band in THIS sitting for ladder 4' },
  @{ label = '4mc-p4';    aff = '0xF';   threads = '4';  rungs = '288,320,352,384,416,448,480,512'; tag = 'cpp4';   what = 'mask 0xF, cores 0-3, FOUR P-CORES, one class, on crpool4m grid - replicates crpool4m create CPU 394 / wall 410 AND locates this arm band in THIS sitting for ladder 5' }
)

# THE FINE LADDERS. Their `rungs` are EMPTY here on purpose and are filled in
# after the coarse pair runs. A literal rung list in this table would be a
# banked band typed into a driver, which is the defect this round exists to fix.
$fine = @(
  @{ label = '4mc-e8-fine'; aff = '0xFF0'; threads = '8'; rungs = ''; tag = 'cpe8f'; from = 'cpe8'; what = 'THE DELIVERABLE - 4-row rungs across the band ladder cpe8 measured in THIS sitting' },
  @{ label = '4mc-p4-fine'; aff = '0xF';   threads = '4'; rungs = ''; tag = 'cpp4f'; from = 'cpp4'; what = 'THE DELIVERABLE - 4-row rungs across the band ladder cpp4 measured in THIS sitting' }
)

Say "CRPIN-ROUND start root=$Root bin=$Bin budget=$Budget coarse=$($coarse.Count) fine=$($fine.Count) rungs_per_ladder=$(($coarse | ForEach-Object { "$($_.tag):$($_.rungs)" }) -join ' ')"

# THE BUILD AND THE EXTRACT ARE GATED LIKE A MEASUREMENT ARM. A `cargo build`
# plus a 16 GiB create is foreign load to whoever is measuring, every bit as
# much as a ladder is, so the gate comes FIRST and the TAKING-THE-BOX line
# comes after it passes: until then this lane is queued and says so.
Wait-Quiet 'prebuild' 2
if (-not $script:quietOk) { Say "CRPIN-ABORT load gate gave up before the build"; exit 8 }
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-pinned-band-ladder-4mib gen=1db62464 (<user>, opus5 chip; an internal note, lease to 2026-09-18T15:54:51Z) ACCOUNTS=none - TAKING THE BOX, now, for FIVE create-phase ladders in ONE sitting off ONE fixture at 4 MiB / n=4096: cpwarm UNPINNED t16 rungs 288..416 (builds the 16 GiB fixture, m=288 spent as a warm-up rung); cpe8 mask 0xFF0 t8 and cpp4 mask 0xF t4 on crpool4m grid 288..512 (replicate its pinned CREATE crossovers 393/409 and 394/410, AND locate each arm band in this sitting); then cpe8f and cpp4f, 4-ROW rungs across the bands cpe8 and cpp4 actually measured, computed ON THIS BOX by bandplan.py from those two logs. Item 1 of an internal note: the CPU/wall proportionality band is the only region where the maintainer wall-time limit can bite and it has never been priced on the create path; crband showed it cannot be aimed at on an UNPINNED arm because the band moves 30 rows between sittings, and that pinned arms replicate within 5. FIVE LADDERS, ONE SITTING: wcomb takes the rig lock PER LADDER, so anybody inspecting the lock will see five separate holds and THE GAPS BETWEEN THEM ARE NOT OPENINGS. Each ladder gates on lock-free AND no-parfast AND load under 25, and waits out an rc=17 LOCK-BUSY rather than dying. Estimate ~2h30 including a ~2 min build, the 16 GiB create and its ~989 s settle. NO CONSTANT MOVES - this round produces evidence only. Will post DONE with the box-as-left statement and will DELETE my root. Kill by pid, never by pattern."

if (-not $SkipProbe) { Probe-Classes }

$WantBytes = 4173312
if (-not (Test-Path $Bin)) {
  # Win32_Process::Create (wlaunch.ps1) does not always see the user's PATH,
  # and rustup's shims live in the profile. Same fix wcomb.ps1 carries.
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  $src = Join-Path $Root 'src'
  # EXTRACT INSIDE THE GATED REGION, not at staging time. The tarball is scp'd
  # up before launch - that is network work and costs the box little - but
  # unpacking ~25,000 files is disk and CPU that lands on whoever is measuring,
  # so it waits behind the same gate the build does.
  if (-not (Test-Path $src)) {
    $tgz = Join-Path $Root 'src-06d5734b7.tar.gz'
    if (-not (Test-Path $tgz)) { Say "CRPIN-FAIL no source tree at $src and no tarball at $tgz"; exit 9 }
    New-Item -ItemType Directory -Force $src | Out-Null
    $xw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "tar -xzf `"$tgz`" -C `"$src`""
    $xrc = $LASTEXITCODE
    Say "EXTRACT rc=$xrc secs=$([math]::Round($xw.Elapsed.TotalSeconds,1)) into=$src"
    if ($xrc -ne 0) { Say "CRPIN-FAIL extract rc=$xrc"; exit 9 }
  }
  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Say "CRPIN-FAIL no Cargo.toml under $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line
  # of a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-crpin.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-crpin.log"
  if ($brc -ne 0) { Say "CRPIN-FAIL build rc=$brc"; exit 9 }
} else {
  Say "BIN-INHERITED $Bin already present - no extract and no cargo build. The byte gate below runs on it UNCHANGED, which is what makes inheriting safe."
}
if (-not (Test-Path $Bin)) { Say "CRPIN-FAIL bin not found after build: $Bin"; exit 9 }
$gotSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$gotLen = (Get-Item $Bin).Length
Say "BIN bytes=$gotLen want_bytes=$WantBytes sha256=$gotSha (a sha that matches no other round is EXPECTED and not a fault - the build embeds its own path; the byte count is the invariant across every build of 06d5734b7 on this fleet)"
if ($gotLen -ne $WantBytes) {
  Say "CRPIN-FAIL binary byte count want=$WantBytes got=$gotLen - this is NOT the 06d5734b7 artefact the banked create ladders used, so ladders 2 and 3 would not tie to crpool4m pinned create crossovers and the replication half of this round would answer nothing. Refusing rather than measuring it."
  exit 9
}
$fix = Join-Path $Root 'fix-4194304-1024'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused - no 16 GiB create and no settle wait)' } else { 'ABSENT - ladder 1 builds it, then waits out the settle' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

$rc = 0
foreach ($a in $coarse) {
  Invoke-Ladder $a
  if ($script:ladderRc -ne 0) { Say "CRPIN-LADDER-FAILED $($a.tag) rc=$($script:ladderRc) - see $logs\$($a.tag).log"; $rc = $script:ladderRc; break }
}

# ===================== THE BAND STEP, ON THIS BOX =====================
# This is the one thing this driver does that its ancestors do not. crband
# placed its fine rungs from a band measured the DAY BEFORE and missed, because
# the band moved. These are placed from the logs the last two ladders just
# wrote, minutes ago, on the same fixture, in the same sitting.
#
# A REFUSAL HERE IS AN ANSWER, NOT AN ERROR. bandplan.py exits 3 when the
# coarse ladder never crossed in range: there is then no band to aim at, and a
# fine ladder placed anyway would be aimed at nothing. That ladder is SKIPPED
# and the round record says which and why. The round does NOT fall back to
# crpool4m's band - the whole point of the sitting is that a banked band is not
# a place to aim.
if ($rc -eq 0) {
  $py = (Get-Command python -ErrorAction SilentlyContinue)
  if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue) }
  if (-not $py) {
    Say "CRPIN-BANDPLAN-UNAVAILABLE no python on PATH - the two fine ladders cannot be placed from this sitting's own logs, and placing them from a banked band is refused by design. The coarse half of the round stands; ladders 4 and 5 are NOT run."
  } else {
    foreach ($f in $fine) {
      $srcLog = Join-Path $logs "$($f.from).log"
      $bp     = Join-Path $here 'bandplan.py'
      $rg     = Join-Path $here 'rowgate.py'
      # NATIVE invocation, not `cmd /c "..."`: cmd re-parses the whole string
      # and strips quotes by its own rules, so a quoted interpreter path
      # followed by more quoted arguments is a known mangling. PowerShell
      # passes these four argv entries through untouched.
      $out    = & $py.Source $bp $srcLog "--rowgate=$rg" 2>&1
      $brc2   = $LASTEXITCODE
      foreach ($line in @($out)) { Say "BANDPLAN $($f.tag) <- $($f.from): $line" }
      $rungLine = @($out) | Where-Object { $_ -match '^RUNGS ' } | Select-Object -First 1
      if ($brc2 -eq 0 -and $rungLine) {
        $f.rungs = ($rungLine -replace '^RUNGS\s+', '').Trim()
        Say "BANDPLAN-OK $($f.tag) rungs=$($f.rungs) - placed from THIS sitting's $($f.from).log, not from a banked band"
      } else {
        Say "BANDPLAN-REFUSED $($f.tag) rc=$brc2 - no aimable band from $($f.from).log, so this fine ladder is SKIPPED. That is the designed behaviour and is reported as a result, not patched around."
      }
    }
    foreach ($f in $fine) {
      if (-not $f.rungs) { continue }
      Invoke-Ladder $f
      if ($script:ladderRc -ne 0) { Say "CRPIN-LADDER-FAILED $($f.tag) rc=$($script:ladderRc) - see $logs\$($f.tag).log"; $rc = $script:ladderRc; break }
    }
  }
}

Say "CRPIN-ROUND end rc=$rc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-pinned-band-ladder-4mib gen=1db62464 (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
