param(
  [string]$Root   = '<rig>\crband-18sep',
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Budget = '21474836480',               # NZBFAST_NTT_BUDGET, 20 GiB - keeps every force leg resident
  [switch]$SkipProbe
)
# crband-round.ps1 - THREE UNPINNED create-phase ladders in ONE sitting off ONE
# fixture, for lane parfast-create-band-and-interleave-18sep. Items 1 and 2 of
# an internal note.
#
# A copy of rounds/crpool4m-2026-09-17/crpool-round.ps1 with the arm
# table replaced, -Rungs moved INTO the arm table (the three ladders do not
# share a rung set) and the coordination text rewritten. Everything else - the
# load gate, the byte gate, the rc=17 retry, the detached launch, the
# extract-inside-the-gate discipline - is that driver's and is unchanged.
#
# ============================ THE TWO QUESTIONS ============================
#
# ITEM 1 - THE PROPORTIONALITY BAND IS UNPRICED ON THE CREATE PATH. the maintainer's
# wall-time rule (memory topic nzbfast-wall-time-is-the-deciding-metric) carries
# a limit: wall wins a disagreement "unless there's something excessive and it's
# an extremely unfair trade, like, 10x the cpu for a little bit better wall".
# THE BAND BETWEEN THE CPU CROSSOVER AND THE WALL CROSSOVER IS THE ONLY REGION
# WHERE THE TWO METRICS DISAGREE, so it is the only region where that limit can
# ever bite. crpool4m could not sample it: its bands are 6-24 rows and its rung
# grid is 32, so every band fell BETWEEN measured rungs and CPU and wall agreed
# at every rung it measured. Ladder `cband` puts five rungs at 8-row spacing
# across 4mc-t16's band (CPU 387, wall 411), which is the widest of the five.
#
# WHAT IS ALREADY IN THE STANDING RULE AND SHOULD NOT BE: the 0.1x-at-384 /
# 5.7x-at-416 trade degradation now recorded there came off the banked UNPINNED
# -t4 (rounds/crg4-2026-09-16/), whose band was 41 rows. Under
# controlled placement crpool4m read bands of 6-24, so PART OF THAT 41 WAS
# PLACEMENT AND NOT MECHANISM, and those two figures should not be quoted as a
# pinned result. This ladder is what replaces them.
#
# A NARROW BAND MEANS SMALL DIFFERENCES, SO UNRESOLVED RUNGS ARE THE EXPECTED
# CASE AND NOT A FAILURE. "The trade cannot be priced at this resolution on this
# part" is publishable and is exactly what the limit needs to know. NO TOLERANCE
# IS TO BE WIDENED TO MANUFACTURE A VERDICT.
#
# ITEM 2 - WHY THE SAME UNPINNED ARM READ 365 AND THEN 387. crpool4m's unpinned
# -t16 read 387 CPU where crg4's read 365: 22 rows on the same configuration,
# binary and fixture SHAPE, larger than the entire 16-row gap crpool4m was
# chartered to investigate. regrid-and-arm-split.py (banked in that round's
# directory, no box time) settled two thirds of it already:
#
#   * THE RUNG GRID IS REFUTED. On the common grid 320..512 every reading is
#     identical to its own-grid reading. Not a reduction artefact.
#   * THE SWING IS LOCATED IN THE FOLD ARM. Between the sittings the fold is
#     5.8% cheaper in CPU (6.1% wall) and the force only 3.0% (2.6%). A
#     crossover is where fold/force = 1, so symmetric noise cancels; that ~3 pp
#     differential IS the 22 rows.
#
# WHAT SURVIVED: crg4 ran its two pools INTERLEAVED in one ladder
# (-Threads 4,16) where crpool4m ran a solo -t16; the fixture was a different
# instance; and crg4's sitting was noisier. Ladders `csolo` and `cinter` are
# those two shapes against ONE fixture instance in ONE sitting, which holds the
# fixture fixed and is the control that isolates interleaving.
#
# A FOURTH CANDIDATE, FOUND BY READING AND REFUTED BEFORE THE SITTING. The two
# banked rounds did not run the same harness: crg4 ran plib 3b0e254e + wcomb
# 1ad3f260 (commit e11512488) and crpool4m ran plib 1a714068 + wcomb 70fe0efe
# (commit e1731b0ee), 878 inserted lines apart. Nobody had named that. Diffed
# line by line, IT CANNOT REACH AN UNPINNED CREATE LEG:
#
#   * Invoke-Leg's only change is the affinity block, guarded by
#     `if ($affWant)`, and $affWant is 0 on an unpinned leg - PowerShell treats
#     0 as false, so the block does not execute and wall/cpu are measured by
#     identical code.
#   * The create argv is byte-identical when -Budget is unset: the newer
#     version builds `c -q -t$threads -s$slice -c$m` and appends ` -m$budget`
#     only `if ($budget -ne 'big')`. This round does not pass -Budget, and
#     neither did either banked round.
#   * -Payload defaults to `random`, which is the historical member-writing
#     loop to the byte, and the fixture directory name is unchanged for it.
#   * -Residency on the create path went from silently inert to asserted. An
#     assert refuses a leg; it does not change the work the leg does.
#
# SO THE HARNESS IS NOT THE 22 ROWS, and the three candidates the handoff names
# remain the three. BUT ONE READING DOES NOT SURVIVE IT: foreign-CPU accounting
# DID change (Get-OwnPidTree now resolves an ancestor-walking own-pid set, and
# Measure-ForeignDelta is new), so crg4's "12% median" and crpool4m's "8%
# median" WERE MEASURED BY TWO DIFFERENT INSTRUMENTS and are not a like-for-like
# noise comparison. foreign_cpu is quoted WITHIN a sitting in this round's
# write-up and never across the two banked ones.
#
# ============================ THE THREE LADDERS ============================
#
#   1  cband   -Threads 16   rungs 384,392,400,408,416     ITEM 1.
#   2  csolo   -Threads 16   rungs 320,352,384,416,448,480,512   ITEM 2, solo.
#   3  cinter  -Threads 4,16 rungs 320,352,384,416,448,480,512   ITEM 2, crg4's shape.
#
# ALL THREE ARE UNPINNED, so -Affinity arms nothing and the "arm 1 must be
# unpinned" rule (which exists because -Affinity pins the FIXTURE CREATE too) is
# satisfied by every ordering. The ordering is therefore free, and it is chosen
# for item 2:
#
#   cband RUNS FIRST AND BUILDS THE FIXTURE so that csolo and cinter are
#   SYMMETRIC - both post-settle, neither carrying the 16 GiB create and its
#   456-745 s settle. Item 2's whole question is a contrast between those two,
#   and a contrast is worth more than either one's tie to a banked number.
#
#   THE PRICE, STATED: crpool4m's 387 was read from a ladder in POSITION 1 that
#   built its own fixture, and csolo is in position 2. So a csolo that does not
#   reproduce 387 has ladder position as a residual explanation, and this round
#   cannot exclude it. THE ORDERING BUYS BACK MORE THAN IT COSTS, because cband
#   and csolo are both unpinned -t16 and SHARE THE RUNGS 384 AND 416: comparing
#   their fold and force readings at those two rungs is a within-sitting,
#   same-configuration estimate of exactly that position-plus-repeat term, which
#   no other ordering provides and which nothing in this campaign has ever
#   measured. It is a free internal control and it is why the ordering is this
#   way round.
#
# EVERY LADDER GETS A DISTINCT -Label: rowgate.py read groups by
# (label, threads), and cinter's -t16 legs must not fold into csolo's.
#
# RUNGS. cband's five are the item's cell as written. csolo's and cinter's seven
# are the COMMON GRID regrid-and-arm-split.py established - the grid on which
# both banked readings are unchanged from their own-grid values - so this
# round's two readings are directly comparable to 387 and 365 with no
# re-gridding step and no grid candidate to re-open.
#
# NO RUNG CAN FALL THROUGH TO THE FOLD: the forced arm sets
# NZBFAST_CREATE_NTT_MIN_ROWS=0 and n = 4,096 clears the x86 input floor of
# 2,048, so admission holds at 320 as it does at 512, and wcomb's own path
# assert refuses any leg that took the other path.
#
# ====================== WHAT THIS ROUND DOES NOT LICENSE ======================
# Written BEFORE the sitting, so it cannot be trimmed to fit the numbers - the
# practice crpool4m's README used and the reason its conclusions held when its
# numbers would have allowed a stronger claim.
#
# NO CONSTANT MOVES. The rung decision - 384 against 416 against
# create_ntt_min_rows taking its own clause at ~372 - is the maintainer's, it is open, and
# it is explicitly waiting on wall-based inputs. This lane is the fifth to
# measure inputs and the fifth not to move anything. No sentence in this
# write-up may be read as a decision having been taken, and anything downstream
# citing it as "384 ships" is citing it wrongly.
#
# A PRICED BAND IS NOT A CHOSEN RUNG. Item 1 produces a trade ratio per rung.
# A ratio under 10x does not say the rung is right; it says the proportionality
# limit does not EXCLUDE it. Those are different claims and only the second is
# this round's.
#
# AN UNRESOLVED BAND IS NOT A CLEAN BILL. If the rungs inside the band come back
# inside their own A/A floors, the honest statement is "the trade cannot be
# priced at this resolution on this part" - NOT "the trade is small", and NOT
# "the metrics agree".
#
# ITEM 2 CANNOT CLEAR AN INTERLEAVED LADDER, ONLY CONVICT ONE. If solo and
# interleaved land together, that is evidence the mechanism is not interleaving
# IN THIS CELL at this pool pair on this part - it does not certify the other
# interleaved ladders in the campaign, which use different pools and shapes.
#
# ONE SITTING IS NOT A REPLICATE, and more reps cannot firm a rung: the A/A
# floor is a MAX over reps. Whatever this produces is reported as one sitting.
#
# ONE PART, ONE PAYLOAD, ONE BLOCK SIZE. Core Ultra 9 386H, random bytes, 4 MiB,
# n = 4,096. No other box on this fleet is GFNI-256.
#
# ========================= READING AND HYGIENE RULES =========================
# WALL DECIDES, CPU EXPLAINS. Both crossovers are quoted on every table and any
# divergence is named with its size. rowgate.py read prints both.
# CPU-SECONDS DO NOT COMPARE ACROSS MASKS - inert here, since all three ladders
# are unpinned, but cinter's -t4 and -t16 legs are two different pools and only
# their CROSSOVERS compare.
# A TIGHT A/A FLOOR IS AGREEMENT, NOT CORRECTNESS. Every ladder is screened with
# rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py and the rungs
# BRACKETING each crossing are checked for firmness before any crossover is
# believed.
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
  @{ label = '4mcb-band';  threads = '16';   rungs = '384,392,400,408,416';         tag = 'cband';  what = 'ITEM 1 - the PROPORTIONALITY BAND at 8-row spacing across 4mc-t16 band (CPU 387, wall 411), unpinned t16. RUNS FIRST and builds the 16 GiB fixture, so csolo and cinter are symmetric' },
  @{ label = '4mcb-solo';  threads = '16';   rungs = '320,352,384,416,448,480,512'; tag = 'csolo';  what = 'ITEM 2 - unpinned t16 SOLO on the common grid, the shape crpool4m ran when it read 387' },
  @{ label = '4mcb-inter'; threads = '4,16'; rungs = '320,352,384,416,448,480,512'; tag = 'cinter'; what = 'ITEM 2 - unpinned t4 AND t16 INTERLEAVED in one ladder on the same grid, the shape crg4 ran when it read 365/381' }
)

Say "CRBAND-ROUND start root=$Root bin=$Bin budget=$Budget ladders=$($arms.Count) rungs_per_ladder=$(($arms | ForEach-Object { "$($_.tag):$($_.rungs)" }) -join ' ')"

# THE BUILD AND THE EXTRACT ARE GATED LIKE A MEASUREMENT ARM. A `cargo build`
# plus a 16 GiB create is foreign load to whoever is measuring, every bit as
# much as a ladder is, so the gate comes FIRST and the TAKING-THE-BOX line
# comes after it passes: until then this lane is queued and says so. Inherited
# from poolladder-round.ps1, which is the one structural change IT made to the
# driver IT copied. Kept.
Wait-Quiet 'prebuild' 2
if (-not $script:quietOk) { Say "CRBAND-ABORT load gate gave up before the build"; exit 8 }
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-create-band-and-interleave-18sep gen=ab723405 (<user>, opus5 chip; an internal note, lease to 2026-09-18T07:39:38Z) ACCOUNTS=none - TAKING THE BOX, now, for THREE UNPINNED create-phase ladders in ONE sitting off ONE fixture at 4 MiB / n=4096: cband -t16 rungs 384,392,400,408,416 (item 1, the CPU/wall proportionality band at 8-row spacing - this ladder builds the 16 GiB fixture); csolo -t16 rungs 320..512 on the common grid (item 2, the shape crpool4m read 387 from); cinter -Threads 4,16 INTERLEAVED on the same grid (item 2, the shape crg4 read 365/381 from). Items 1 and 2 of an internal note. THREE LADDERS, ONE SITTING: wcomb takes the rig lock PER LADDER, so anybody inspecting the lock will see three separate holds and THE GAPS BETWEEN THEM ARE NOT OPENINGS. Each ladder gates on lock-free AND no-parfast AND load under 25, and waits out an rc=17 LOCK-BUSY for up to 40 minutes rather than dying. Estimate ~1h35 of ladder plus a ~2 min build, a 16 GiB create and its 456-745 s settle. Will post DONE with the box-as-left statement and will DELETE my root. Kill by pid, never by pattern."

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
    if (-not (Test-Path $tgz)) { Say "CRBAND-FAIL no source tree at $src and no tarball at $tgz"; exit 9 }
    New-Item -ItemType Directory -Force $src | Out-Null
    $xw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "tar -xzf `"$tgz`" -C `"$src`""
    $xrc = $LASTEXITCODE
    Say "EXTRACT rc=$xrc secs=$([math]::Round($xw.Elapsed.TotalSeconds,1)) into=$src"
    if ($xrc -ne 0) { Say "CRBAND-FAIL extract rc=$xrc"; exit 9 }
  }
  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Say "CRBAND-FAIL no Cargo.toml under $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line
  # of a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-crband.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-crband.log"
  if ($brc -ne 0) { Say "CRBAND-FAIL build rc=$brc"; exit 9 }
} else {
  Say "BIN-INHERITED $Bin already present - no extract and no cargo build. The byte gate below runs on it UNCHANGED, which is what makes inheriting safe."
}
if (-not (Test-Path $Bin)) { Say "CRBAND-FAIL bin not found after build: $Bin"; exit 9 }
$gotSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$gotLen = (Get-Item $Bin).Length
Say "BIN bytes=$gotLen want_bytes=$WantBytes sha256=$gotSha (a sha that matches no other round is EXPECTED and not a fault - the build embeds its own path; the byte count is the invariant across every build of 06d5734b7 on this fleet)"
if ($gotLen -ne $WantBytes) {
  Say "CRBAND-FAIL binary byte count want=$WantBytes got=$gotLen - this is NOT the 06d5734b7 artefact the banked create and repair ladders used, so arm 1 would not tie to crg4 and no arm would be readable against the pinned repair sitting. Refusing rather than measuring it."
  exit 9
}
$fix = Join-Path $Root 'fix-4194304-1024'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused - no 16 GiB create and no settle wait)' } else { 'ABSENT - ladder 1 builds it, then waits out the settle' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

$rc = 0
foreach ($a in $arms) {
  Wait-Quiet $a.tag 1
  if (-not $script:quietOk) { Say "CRBAND-ABORT load gate gave up before $($a.tag)"; $rc = 8; break }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-create-band-and-interleave-18sep EXTENSION - still running, still ONE sitting: ladder $($a.tag) ($($a.what)), $($arms.Count) ladders total"
  $log = Join-Path $logs "$($a.tag).log"
  $wcomb = Join-Path $here 'wcomb.ps1'
  $inner = "-NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$Root`" -Bin `"$Bin`" -NoBuild" +
           " -Phase create -Tag $($a.tag) -Label $($a.label) -Slice 4194304 -MemberMiB 1024 -Recovery 640" +
           " -Rungs `"$($a.rungs)`" -Threads `"$($a.threads)`" -Reps 1 -Residency resident -NttBudget $Budget"
  Say "LADDER $($a.tag) label=$($a.label) UNPINNED threads=$($a.threads) rungs=$($a.rungs) log=$log"
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
    if ($lockWaits -gt 20) { Say "CRBAND-LADDER-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  if ($arc -ne 0) { Say "CRBAND-LADDER-FAILED $($a.tag) rc=$arc - see $log"; $rc = $arc; break }
}

Say "CRBAND-ROUND end rc=$rc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) parfast-create-band-and-interleave-18sep gen=ab723405 (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
