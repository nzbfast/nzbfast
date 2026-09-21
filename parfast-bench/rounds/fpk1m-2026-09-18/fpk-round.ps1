param(
  [string]$Root   = '<rig>\fpk18sep',
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Budget = '12884901888',               # NZBFAST_NTT_BUDGET, 12 GiB - the banked 1 MiB nibble round's own value
  [switch]$SkipProbe
)
# fpk-round.ps1 - the 1 MiB FOLD PARALLELISM ladder on the GFNI-256 class, for
# lane fold-parallelism-knee-18sep, arm 2 of that chip.
#
# A copy of rounds/crband-2026-09-18/crband-round.ps1 with the arm
# table replaced, the phase changed from create to measure, and the
# coordination text rewritten. The load gate, the byte/sha gate, the rc=17
# retry, the detached launch and the extract-inside-the-gate discipline are
# that driver's and are unchanged.
#
# ============================== THE QUESTION ==============================
#
# THE FINDING THIS TESTS IS NOT IN DOUBT AND IS NOT WHAT THIS ROUND MEASURES.
# Three banked rounds on intel-i5-10600kf (i5-10600KF, 6c/12t, AVX2 without GFNI - the
# NIBBLE class) agree that the FOLD's effective parallelism (cpu/wall) gives out
# at high m while the TRANSFORM's does not:
#   64 KiB  -t12 fold holds 10.1-11.2 to m=2048 and drops to 6.08/6.05 at
#           m=4096, independently in cf-two-binary-control-2026-09-16/ and
#           wcomb-k-nibble-2026-09-16/. -t4 and -t6 hold theirs throughout.
#   1 MiB   -t12 never pays at ANY rung: efficiency 0.54-0.60 of the pool
#           throughout, and at m=2048 it is WORSE in wall than -t6 (153.303 s
#           against 147.593 s) - t6-1mib-nibble-smt-2026-09-16/.
#   control It is not the pool and not memory: in the same 64 KiB log the -t12
#           FORCE arm at m=4096 holds 8.89 at a LARGER footprint (1,029 MB) than
#           the collapsing fold cell (682.5 MB). A working-set/bandwidth
#           threshold was ranked first and then REFUTED by that control.
#   control It is not load: cf-load-term-2026-09-16/ read the same cell at 17%,
#           48%, 83% and 14% of a core of foreign CPU and got 6.09/6.08/6.07/
#           6.10 - a 0.5% spread across a fivefold change in box load.
#
# WHAT IS IN DOUBT IS ITS GENERALITY. Every one of those rounds is on ONE PART.
# intel-i5-10600kf is this fleet's only nibble-class box, so "SMT never pays at 1 MiB"
# is currently a property of that silicon and not of the fold. This round runs
# the same 1 MiB ladder, leg for leg, on intel-core-ultra-9-386h - Core Ultra 9 386H, the
# fleet's only GFNI-256 part - and asks whether the shape appears there too.
#
#   If it DOES  the fold's parallelism giving out at high m is a property of
#               the FOLD and deserves a constant's attention.
#   If it does NOT  it is an i5-10600KF story and must be LABELLED as one, and
#               the 1 MiB -t12 readings banked so far stop being evidence about
#               the fold at all.
#
# ============ THE CONFOUND THIS PART CARRIES, AND THE TWO LADDERS ============
#
# THE TWO BOXES DO NOT DISAGREE ONLY ABOUT GFNI. On the i5 the ladder decomposes
# cleanly: -t4 -> -t6 adds two PHYSICAL cores, -t6 -> -t12 adds NO cores at all
# and is pure SMT. intel-core-ultra-9-386h has NO SMT and is HYBRID - 16C/16T as 4 P-cores
# (0-3), 8 E (4-11) and 4 LP-E (12-15), with a measured 1.43x single-thread
# swing decided purely by where Windows puts an unpinned thread
# (`.claude/MACHINES.md`). So an unpinned -t12 here is 4 P + 8 E, and a fall in
# cpu/wall at -t12 is explicable by CORE CLASS with no reference to the fold.
# **An unpinned ladder on this part therefore cannot answer the question
# alone.** Two things fix that, and this round does both:
#
#   LADDER A `fpku` - UNPINNED -t4,6,12, Reps 2. The direct leg-for-leg
#     analogue of t6-1mib-nibble-smt-2026-09-16, same rungs, same budget, same
#     fixture shape. It is what the chip asks for and it is READ WITH THE
#     CONFOUND NAMED, never as a bare pool ladder.
#     Its class-neutral reading is the FOLD-vs-FORCE contrast WITHIN a pool:
#     both arms run at every rung in the same sitting on the same cores, so
#     whatever core class an unpinned -t12 lands on, BOTH arms land on it. That
#     is the same instrument the i5's own refutation of the bandwidth
#     hypothesis used, and it transfers to a hybrid part unchanged.
#
#   LADDER B `fpke` - PINNED to the EIGHT E-CORES (mask 0xFF0), -t4,6,8,
#     Reps 1. A HOMOGENEOUS pool ladder: one core class, no SMT, no placement.
#     This is the cleanest statement the part can make of "does fold
#     parallelism give out as the pool grows", and no box on this fleet has
#     offered it before. crband-2026-09-18 measured that the UNPINNED full-box
#     crossover on this very part swings 30 rows across four sittings while the
#     -t4 arm replicates within 6, so a pinned arm is not a luxury here.
#
# ============== WHAT THIS ROUND DOES NOT LICENSE ==============
# ONE PART, ONE SITTING, ONE BLOCK SIZE, ONE PAYLOAD. An agreement with the i5
# would be two parts agreeing, not a law; a disagreement would locate the
# finding on the i5, not explain it.
# CPU-SECONDS DO NOT COMPARE ACROSS MASKS. Ladder B's E-core seconds must never
# be read against ladder A's mixed-placement seconds. What compares is the
# SHAPE of cpu/wall against pool size WITHIN a ladder, and the fold/force ratio
# WITHIN a cell.
# NO CONSTANT MOVES. Not NTT_WINDOW_COMBINE_X86, not NTT_MIN_MISSING*. This
# produces evidence; crates/ is untouched whatever it finds.
# WALL DECIDES, CPU EXPLAINS (memory topic nzbfast-wall-time-is-the-deciding-
# metric). Both are quoted on every table and any divergence is named.
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
# Require-QuietBox, whose 10%-of-box ceiling is 160% of a core here and lets one
# saturated core through BY DESIGN. It RETURNS NOTHING and sets $script:quietOk,
# which is plib's own convention: `Say` writes to the OUTPUT stream, so a
# function that both logs and returns a bool returns an ARRAY.
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

# The core-class probe, from crband-round.ps1 unchanged except that LADDER B's
# ARM NAME rests on it: 0xFF0 is asserted to be eight cores of ONE class, so a
# core-11 time that does not match core-4's is a reason to THROW LADDER B AWAY
# rather than to publish it. FIXED WORK, timed.
function Probe-Classes {
  $spin = @'
param([int]$Iters)
$sw=[Diagnostics.Stopwatch]::StartNew(); $x=0.0
for($i=0;$i -lt $Iters;$i++){ $x=$x+$i*1.000001 }
$sw.Stop(); "SPIN ms=$($sw.ElapsedMilliseconds) x=$x"
'@
  $f = Join-Path $here 'spin.ps1'; [IO.File]::WriteAllText($f, $spin)
  foreach ($m in @(@(0x1,'P-core0'), @(0x10,'E-core4'), @(0x80,'E-core7'), @(0x100,'E-core8'), @(0x800,'E-core11'), @(0x1000,'LPE-core12'))) {
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

# -Rungs 192,512,1024,2048 and NOT measure's default 4,096: the fixture is
# -c2048, so m = recovery = 2048 is the last legal rung and wcomb's RUNG-BOUND
# guard refuses the default up front. This is the banked 1 MiB nibble round's
# own rung set, which is what makes ladder A a leg-for-leg analogue.
# -Budget 2048 for the same reason it used it: at 1 MiB the phase default -m128
# is a window of a few hundred sources, under NTT_MIN_WINDOW_PRESENT and
# nothing the dispatcher would ever run.
$rungs = '192,512,1024,2048'
$arms = @(
  @{ label = 'g1m-unpinned'; threads = '4,6,12'; affinity = '';      reps = 2; tag = 'fpku';
     what  = 'LADDER A - the leg-for-leg analogue of the banked 1 MiB nibble ladder, UNPINNED -t4,6,12. RUNS FIRST and builds the 8 GiB fixture, so ladder B is symmetric. Read with the hybrid-placement confound named; its class-neutral reading is fold-vs-force WITHIN a pool' },
  @{ label = 'g1m-ecore';    threads = '4,6,8';  affinity = '0xFF0'; reps = 1; tag = 'fpke';
     what  = 'LADDER B - the HOMOGENEOUS pool ladder: pinned to the eight E-cores (4-11), -t4,6,8, one core class, no SMT, no placement. The cleanest statement this part can make of whether fold parallelism gives out as the pool grows' }
)

Say "FPK-ROUND start root=$Root bin=$Bin budget=$Budget ladders=$($arms.Count) rungs=$rungs"

# THE BUILD AND THE EXTRACT ARE GATED LIKE A MEASUREMENT ARM. A `cargo build`
# plus an 8 GiB create is foreign load to whoever is measuring, every bit as
# much as a ladder is, so the gate comes FIRST and the TAKING-THE-BOX line
# comes after it passes: until then this lane is queued and says so.
Wait-Quiet 'prebuild' 2
if (-not $script:quietOk) { Say "FPK-ABORT load gate gave up before the build"; exit 8 }
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) fold-parallelism-knee-18sep gen=585c33c3 (<user>, opus5 chip; an internal note, lease to 2026-09-18T12:25:50Z) ACCOUNTS=none - TAKING THE BOX, now, for TWO 1 MiB measure-phase ladders in ONE sitting off ONE fixture (16 members x 512 MiB, slice 1048576, n=8192, -c2048): fpku UNPINNED -t4,6,12 Reps 2 (the leg-for-leg analogue of the banked 1 MiB nibble ladder - this ladder builds the fixture); fpke PINNED to the eight E-cores 0xFF0 -t4,6,8 Reps 1 (the homogeneous pool ladder this hybrid part needs before an unpinned one can be read). Arm 2 of the fold-parallelism-knee chip: whether the i5's 'the fold's cpu/wall gives out at high m while the transform's does not' is a property of the FOLD or of the i5-10600KF. intel-core-ultra-9-386h is the fleet's only GFNI-256 part, so no other box substitutes. TWO LADDERS, ONE SITTING: wcomb takes the rig lock PER LADDER, so anybody inspecting the lock will see two separate holds and THE GAP BETWEEN THEM IS NOT AN OPENING. Each ladder gates on lock-free AND no-parfast AND load under 25, and waits out an rc=17 LOCK-BUSY rather than dying. Estimate ~25 min build, an 8 GiB create and its settle, then ~1h50 of ladder. NO CONSTANT MOVES - this round produces evidence only. Will post DONE with the box-as-left statement and will DELETE my root. Kill by pid, never by pattern. I take the box having read it free twice 60 s apart at 04:28Z and 04:31Z, 75 min after parfast-create-band-and-interleave-18sep posted its release at 03:15Z; rar15-pdr-candidates-x86-cells and rarfast-header-vint-width-on-rewrite are named QUEUED on this file and neither has an OPEN claim in an internal note, and codex-parfast-create-hotpaths-18sep's QUEUED line names intel-i5-10600kf first. If any of the three posts a CLAIM I stand down after the current ladder."

if (-not $SkipProbe) { Probe-Classes }

if (-not (Test-Path $Bin)) {
  # Win32_Process::Create does not always see the user's PATH, and rustup's
  # shims live in the profile. Same fix wcomb.ps1 carries.
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  $src = Join-Path $Root 'src'
  # EXTRACT INSIDE THE GATED REGION, not at staging time. The tarball is scp'd
  # up before launch - network work, which costs the box little - but unpacking
  # ~25,000 files is disk and CPU that lands on whoever is measuring.
  if (-not (Test-Path $src)) {
    $tgz = Join-Path $Root 'src.tar.gz'
    if (-not (Test-Path $tgz)) { Say "FPK-FAIL no source tree at $src and no tarball at $tgz"; exit 9 }
    New-Item -ItemType Directory -Force $src | Out-Null
    $xw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "tar -xzf `"$tgz`" -C `"$src`""
    $xrc = $LASTEXITCODE
    Say "EXTRACT rc=$xrc secs=$([math]::Round($xw.Elapsed.TotalSeconds,1)) into=$src"
    if ($xrc -ne 0) { Say "FPK-FAIL extract rc=$xrc"; exit 9 }
  }
  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Say "FPK-FAIL no Cargo.toml under $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line
  # of a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-fpk.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-fpk.log"
  if ($brc -ne 0) { Say "FPK-FAIL build rc=$brc"; exit 9 }
} else {
  Say "BIN-INHERITED $Bin already present - no extract and no cargo build. The sha gate below runs on it UNCHANGED, which is what makes inheriting safe."
}
if (-not (Test-Path $Bin)) { Say "FPK-FAIL bin not found after build: $Bin"; exit 9 }
# THE SHA IS PINNED HERE AND RE-CHECKED BEFORE EVERY LADDER, rather than gated
# against a figure known in advance. crband could gate on a byte count because
# it was reproducing a banked artefact; this round builds its own tree, so
# there is no prior figure and inventing one would be theatre. What the gate is
# actually FOR is the t6ctl hazard - the binary moving UNDER a multi-ladder
# sitting - and for that, pinning the sha observed at the start is exactly as
# strong and needs no oracle. The two ladders must be ONE executable or their
# ladders are not comparable.
$binSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$binLen = (Get-Item $Bin).Length
Say "BIN bytes=$binLen sha256=$binSha $Bin (a sha matching no other round is EXPECTED - the build embeds its own path)"
$fix = Join-Path $Root 'fix-1048576-512'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused - no 8 GiB create and no settle wait)' } else { 'ABSENT - ladder A builds it, then waits out the settle' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

$rc = 0
foreach ($a in $arms) {
  $nowSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
  if ($nowSha -ne $binSha) { Say "FPK-FAIL binary MOVED under the sitting: sha256=$nowSha want=$binSha - the two ladders would not be one executable"; $rc = 9; break }
  Wait-Quiet $a.tag 1
  if (-not $script:quietOk) { Say "FPK-ABORT load gate gave up before $($a.tag)"; $rc = 8; break }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) fold-parallelism-knee-18sep EXTENSION - still running, still ONE sitting: ladder $($a.tag) ($($a.what)), $($arms.Count) ladders total"
  $log = Join-Path $logs "$($a.tag).log"
  $wcomb = Join-Path $here 'wcomb.ps1'
  $inner = "-NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$Root`" -Bin `"$Bin`" -NoBuild" +
           " -Phase measure -Tag $($a.tag) -Label $($a.label) -Slice 1048576 -MemberMiB 512 -Recovery 2048" +
           " -Rungs `"$rungs`" -Threads `"$($a.threads)`" -Reps $($a.reps) -Budget 2048 -NttBudget $Budget"
  if ($a.affinity) { $inner += " -Affinity $($a.affinity)" }
  Say "LADDER $($a.tag) label=$($a.label) affinity=$(if ($a.affinity) { $a.affinity } else { 'UNPINNED' }) threads=$($a.threads) reps=$($a.reps) rungs=$rungs log=$log"
  Say "ARGV powershell $inner"
  # cmd /c redirect, NOT Tee-Object: a Tee-Object log is UTF-16 and
  # harness/rowgate.py answers "REFUSED: no legs" on one.
  #
  # rc=17 IS THE ONE EXIT CODE WORTH WAITING OUT. It is plib's LOCK-BUSY: the
  # ladder stopped before its first leg, so nothing was measured and nothing is
  # contaminated by asking again later. EVERY OTHER NON-ZERO rc ENDS THE ROUND
  # ON THE SPOT, because those are the instrument REFUSING - a residency
  # violation, a path assert, an affinity readback mismatch - and retrying one
  # of those would launder a refusal into a number.
  $arc = 0; $legs = 0; $lockWaits = 0
  while ($true) {
    & cmd /c "powershell $inner > `"$log`" 2>&1"
    $arc = $LASTEXITCODE
    $legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
    if ($arc -ne 17) { break }
    $lockWaits++
    if ($lockWaits -gt 20) { Say "FPK-LADDER-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  if ($arc -ne 0) { Say "FPK-LADDER-FAILED $($a.tag) rc=$arc - see $log"; $rc = $arc; break }
}

Say "FPK-ROUND end rc=$rc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) fold-parallelism-knee-18sep gen=585c33c3 (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
