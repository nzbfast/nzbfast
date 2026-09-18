param(
  [Parameter(Mandatory=$true)][string]$Root,     # holds src\ (origin/main's tree) and every log
  [Parameter(Mandatory=$true)][string]$UntilUtc  # give up waiting for a free box past this
)
# nibaskx86.ps1 - is the windowed NTT row ask conservative on the x86 NIBBLE class?
#
# Written 15 Sep 2026 for lane parfast-ntt-nibble-windowed-ask-15sep
# (an internal note, section 8,
# "The windowed row ask on nibble"). Under -t4 -m128 the dispatcher folds
# m = 256..319 at 64 KiB because the windowed ask puts the transform's edge at
# 320; the forced W = 512 arm beat the fold there, but it runs 7 windows where
# an admitted transform runs 10. This measures the transform INSIDE the budget
# (wcomb.ps1's `inb` arm) against the fold, in order:
#
#   1. waits until the box is FREE - no ~\.parfast-rig.lock and no
#      parfast/cargo/rustc, twice a minute apart - or exits 5 past -UntilUtc;
#   2. GATE: `auto` and `inb` at rungs `auto` transforms (64 KiB m = 320, 336;
#      128 KiB m = 448), one rep. The two must run the same W, window count and
#      window size, or `inb` is not `auto`'s admission and the round stops
#      (exit 3) with the tree and fixtures left for a look;
#   3. the rounds: fold / inb / auto / inb2 / fold2, flipped on even reps,
#      three reps, 64 KiB n = 16,384 at m = 256..336 and 128 KiB n = 16,384 at
#      m = 256..448;
#   4. removes src\target and both fixtures, keeps every log, posts DONE.
#
# Each wcomb.ps1 run takes and releases the rig lock itself; a run refused
# with 17 (someone took the box in the seconds between two runs) waits for a
# free box again and retries. Posts CLAIM / DONE to <rig>\COORDINATION-intel-i5-10600kf.txt.
#
# The budgets are 128 MiB less four workers' FlatPlan::scratch_bytes(m, 512)
# with the paired and additive arenas on (mirror.py's arenas(), which
# reproduces every recorded x86 decision): 113,172,480 - 36,864 * m. Width and
# worker count are the same at 64 and 128 KiB, so one map serves both shapes.
$ErrorActionPreference = 'Stop'
$claim = 'parfast-ntt-nibble-windowed-ask-15sep'
$coord = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$lk = Join-Path $env:USERPROFILE '.parfast-rig.lock'
function Get-Ts { (Get-Date).ToUniversalTime().ToString('o') }
function Get-TsZ { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Coord([string]$kind, [string]$text) { Add-Content -Path $coord -Value "$kind $(Get-TsZ) $claim (opus lane, <user>) - $text" }
# riglock-round-dir-waiters-16sep: presence-as-hold (Test-Path, no liveness
# check) is the defect fixed for the shared harness in 49d5c9795 - see
# harness/riglock_state.py and
# an internal note. This copy is the
# RECORD of the 15 Sep nibble windowed-ask round as it actually ran (the
# i5-nibask-*.log files are banked beside this file); left unconverted so the
# record matches the binary-plus-script that produced them.
function Test-Busy {
  (Test-Path $lk) -or [bool](Get-Process parfast, cargo, rustc -ErrorAction SilentlyContinue)
}
function Wait-Free {
  $deadline = [datetime]::Parse($UntilUtc).ToUniversalTime()
  while ($true) {
    if (-not (Test-Busy)) {
      Start-Sleep -Seconds 60
      if (-not (Test-Busy)) { return }
    }
    if ((Get-Date).ToUniversalTime() -gt $deadline) {
      "NIBASK-DEADLINE the box never came free ts=$(Get-Ts)"
      Coord 'RELEASE' "WITHDRAWN: the waiter reached its deadline $UntilUtc without a free box; nothing run."
      exit 5
    }
    Start-Sleep -Seconds 60
  }
}

$budgets = '256=103735296,272=103145472,288=102555648,304=101965824,320=101376000,336=100786176,384=99016704,448=96657408'
$src = Join-Path $Root 'src'
$h = Join-Path $src 'research\harness'
$arms = 'fold,inb,auto,inb2,fold2'
$s128 = '-Slice 131072 -MemberMiB 128 -Recovery 1024'

function Run-Wcomb([string]$tag, [string]$extra) {
  # Returns the exit code as its LAST pipeline value: the NIBASK-RUN lines below
  # are output too, so a caller that takes the whole pipeline gets an array, and
  # `$array -ne 0` is truthy - which stopped the first launch after a clean gate.
  while ($true) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File $h\wcomb.ps1 -Root $Root -Phase validate -Tag $tag -NttBudgets $budgets $extra >> `"$Root\$tag.log`" 2>&1"
    $rc = $LASTEXITCODE
    "NIBASK-RUN tag=$tag rc=$rc secs=$([math]::Round($sw.Elapsed.TotalSeconds,1)) ts=$(Get-Ts)"
    if ($rc -ne 17) { return $rc }
    "NIBASK-LOCK-BUSY tag=$tag, waiting for the box again"
    Wait-Free
  }
}

function Read-Legs([string]$log) {
  foreach ($line in (Get-Content $log)) {
    $t = $line.TrimStart([char]0xFEFF)
    if (-not $t.StartsWith('LEG ')) { continue }
    $kv = @{}
    foreach ($tok in $t.Split(' ')) { $i = $tok.IndexOf('='); if ($i -gt 0) { $kv[$tok.Substring(0, $i)] = $tok.Substring($i + 1) } }
    $kv
  }
}

"NIBASK-WAIT root=$Root until=$UntilUtc pid=$PID ts=$(Get-Ts)"
Wait-Free
"NIBASK-FREE ts=$(Get-Ts)"
# The tree ships as $Root\bundle.tar and is unpacked only now, so thousands of
# new files (and the scanner behind them) never land beside another round's legs.
if (-not (Test-Path $src)) {
  cmd /c "tar -xf `"$Root\bundle.tar`" -C `"$Root`" 2>&1"
  "NIBASK-UNPACK rc=$LASTEXITCODE ts=$(Get-Ts)"
  if (-not (Test-Path (Join-Path $h 'wcomb.ps1'))) { "NIBASK-FAIL unpack"; exit 9 }
}
Coord 'CLAIM' "took the box: under $Root builds origin/main parfast inside wcomb.ps1's rig lock (~5 min of cargo), then -t4 -m128 validate rounds fold / in-budget forced transform / auto with A/A copies, 64 KiB m=256..336 and 128 KiB m=256..448, 3 reps (~1 h, each wcomb run takes ~\.parfast-rig.lock). Please hold timed work until the DONE line."
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }
# Windows Search re-indexed rewritten fixture slices under the user profile on
# the Core Ultra (an internal note); files
# created under a not-content-indexed directory inherit the attribute.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

# 2. the gate. The first run builds (under the lock) and makes the 64 KiB fixture.
$rc = @(Run-Wcomb 'nibask-gate64' '-Reps 1 -Rungs 320,336 -Arms auto,inb')[-1]
if ($rc -ne 0) { "NIBASK-FAIL gate64 rc=$rc"; Coord 'RELEASE' "STOPPED: gate64 wcomb run failed rc=$rc, see $Root\nibask-gate64.log; tree and fixtures left in place."; exit 9 }
$rc = @(Run-Wcomb 'nibask-gate128' "-NoBuild -Reps 1 -Rungs 448 -Arms auto,inb $s128")[-1]
if ($rc -ne 0) { "NIBASK-FAIL gate128 rc=$rc"; Coord 'RELEASE' "STOPPED: gate128 wcomb run failed rc=$rc, see $Root\nibask-gate128.log; tree and fixtures left in place."; exit 9 }
$bad = 0
foreach ($g in @('nibask-gate64', 'nibask-gate128')) {
  $legs = @(Read-Legs (Join-Path $Root "$g.log"))
  foreach ($m in @($legs | ForEach-Object { $_['m'] } | Sort-Object -Unique)) {
    $a = $legs | Where-Object { $_['m'] -eq $m -and $_['arm'] -eq 'auto' } | Select-Object -First 1
    $b = $legs | Where-Object { $_['m'] -eq $m -and $_['arm'] -eq 'inb' } | Select-Object -First 1
    $same = $a -and $b -and $a['path'] -eq 'ntt' -and $b['path'] -eq 'ntt' -and $a['ntt_w'] -eq $b['ntt_w'] -and $a['windows'] -eq $b['windows'] -and $a['win_slices'] -eq $b['win_slices'] -and $a['restored'] -eq '16/16' -and $b['restored'] -eq '16/16'
    "NIBASK-GATE $g m=$m auto=$($a['path'])/W$($a['ntt_w'])/$($a['windows'])x$($a['win_slices'])/cpu$($a['cpu']) inb=$($b['path'])/W$($b['ntt_w'])/$($b['windows'])x$($b['win_slices'])/cpu$($b['cpu']) same=$same"
    if (-not $same) { $bad++ }
  }
}
if ($bad) {
  "NIBASK-GATE-FAIL $bad rung(s): inb is not auto's admission; stopping"
  Coord 'RELEASE' "STOPPED at the gate: the in-budget forced arm did not reproduce auto's windows at $bad rung(s); nothing further run, tree and fixtures left in $Root for a look. Box is free."
  exit 3
}

# 3. the rounds.
$rc64 = @(Run-Wcomb 'nibask-64k' "-NoBuild -Reps 3 -Flip -Rungs 256,272,288,304,320,336 -Arms $arms")[-1]
$rc128 = @(Run-Wcomb 'nibask-128k' "-NoBuild -Reps 3 -Flip -Rungs 256,272,288,304,320,336,384,448 -Arms $arms $s128")[-1]

# 4. clean up the build and the fixtures; the logs stay.
foreach ($d in @((Join-Path $src 'target'), (Join-Path $Root 'fix'), (Join-Path $Root 'fix-131072-128'))) {
  if (Test-Path $d) { Remove-Item -Recurse -Force $d; "NIBASK-REMOVED $d" }
}
"NIBASK-DONE rc64=$rc64 rc128=$rc128 ts=$(Get-Ts)"
Coord 'DONE' "finished: nibask-64k rc=$rc64, nibask-128k rc=$rc128 (gate passed: in-budget force reproduced auto's windows at 64 KiB m=320,336 and 128 KiB m=448). Rig lock released by each round; src\target and both fixtures removed from $Root, logs and per-leg traces kept there. Box is free."
