# t6ctl.ps1 - the -t6 arm at 1 MiB on the nibble class, lane
# parfast-t6-1mib-nibble-smt.
#
# THE QUESTION. c_w, the combine's CPU per row per window, rises from -t4 to
# the full pool on this part, and it rises MORE at 1 MiB (1.840) than at
# 64 KiB (1.624) - where on the Core Ultra 9 it SHRINKS. The two-binary c_f
# control (an internal note, 16 Sep) decomposed
# the 64 KiB half with a -t6 arm and found the rise is SIBLINGS: -t4 -> -t6
# adds two PHYSICAL cores and costs +8.1%/+12.2%, -t6 -> -t12 adds no cores at
# all and costs a further +61.3%/+56.2%. It could not reach the GROWTH, which
# is 64 KiB against 1 MiB. This round is the same instrument at 1 MiB:
#   candidate 1  the sibling penalty itself grows with the block
#                -> t6/t4 stays near 1.08-1.12 and t12/t6 is what grows
#   candidate 2  the block moves the CORE-COUNT step too (bandwidth or LLC)
#                -> t6/t4 is visibly above 1.12 and carries a real share
#
# ONE BINARY, ONE SITTING, THREE THREAD COUNTS. All three arms must be mine and
# measured together: a ratio is only a ratio between cells measured together,
# and the banked 1 MiB figures come from a sitting under ~69% foreign CPU. The
# -t4 and -t12 arms are therefore not padding.
#
# THE BINARY IS THE BANKED ROUND'S OWN, 8983A55A4E260BA3 (= origin/main
# 4fedd8b33), reused in place rather than rebuilt. That is deliberate: the
# banked 1 MiB cells this round compares against were produced by THIS
# executable on THIS fixture, so reusing it removes the binary as a variable
# entirely - and the two-binary control established that sixty-four commits of
# par2repair/gf16/par2ntt are worth under 2.3% of these constants on this part
# anyway. It also costs no build, which is ~2 min of all twelve threads.
#
# -Residency IS DELIBERATELY NOT PASSED, against this lane's brief. wcomb.ps1's
# residency assert has no budget distinction, but -Phase measure runs TWO force
# legs per rung: a 'big' one resident by construction and a -Budget one
# WINDOWED by construction, and the windowed one IS the c_w measurement. So
# -Residency resident fails at the SECOND force leg of the round. Checked
# against every banked log in rounds/: all 564 residency=resident legs
# are -Phase rowgate and not one is measure. What buys the same protection here
# is -NttBudget (which wcomb applies to budget='big' legs only, deliberately)
# plus the POST-HOC assert at the bottom of this script.
$ErrorActionPreference = 'Stop'
$root    = '<rig>\t6sep16'
$harness = Join-Path $root 'harness'
$bin     = '<rig>\wcomb-16sep\src\target\release\parfast.exe'
$binWant = '8983A55A4E260BA395B42D252EC1A421B1F35AB8B789CD3F3191E2E01E8E2C84'
$fixsrc  = '<rig>\wcomb-16sep\fix-1048576-512'
$fix     = Join-Path $root 'fix-1048576-512'
$tag     = 't6m1'
$lock    = Join-Path $env:USERPROFILE '.parfast-rig.lock'
. (Join-Path $harness 'plib.ps1')

function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" }

Say "T6CTL start root=$root bin=$bin"
if (-not (Test-Path $bin)) { Say "T6CTL-FAIL binary absent $bin"; exit 9 }
$h = (Get-FileHash $bin -Algorithm SHA256).Hash
# THE BINARY IS NOT MINE AND I DID NOT BUILD IT, so it can move under me
# between this lane queuing and this lane running: wcomb-16sep is another
# lane's root and at least one queued lane runs -NoBuild against this same
# path. A silently rebuilt parfast would make the comparison against the
# banked 1 MiB cells a comparison against a different executable, with every
# field of every LEG line still well-formed.
if ($h -ne $binWant) { Say "T6CTL-FAIL binary sha256=$h wanted=$binWant - the shared binary MOVED; re-read the round's premise before running"; exit 9 }
Say "BIN sha256=$h $bin"

# Try-TakeRigLock, NOT Take-RigLock: the plain one `exit 17`s on a busy box,
# which would kill this round outright over a lock race it could simply wait
# out. The waiter has already established the box is free twice 60 s apart, so
# a busy lock here is a genuine race with another waiter sampling the same gap
# - the documented "the lock does not order two waiters" hazard - and losing it
# means waiting, not dying.
$got = $false
for ($try = 1; $try -le 60 -and -not $got; $try++) {
  if ($try -gt 1) { Say "LOCK busy, retry $try in 30s"; Start-Sleep -Seconds 30 }
  foreach ($line in (Try-TakeRigLock 't6ctl')) { Say $line }
  $got = $script:riglock_taken
}
if (-not $got) { Say "T6CTL-FAIL could not take the rig lock in 30 minutes"; exit 17 }
$staged = $false
try {
  # THE FIXTURE IS COPIED, NOT SHARED. fix-1048576-512 lives in
  # nibble-block-size-row-gate-16sep's root and the legs WRITE into fix\work\,
  # so pointing at it would damage another lane's corpus. 20.0 GB (10.01 GB
  # pristine + 10.01 GB work), C: to C: per the TLC/QLC rule - the round's
  # brief said ~8 GiB, which is the pristine members alone and not what
  # Copy-Item moves. C: had 208 GB free at 14:40Z on 16 Sep.
  #
  # UNDER THE LOCK, because 20 GB of C:-to-C: copy is minutes of heavy I/O and
  # would land on whoever holds the box otherwise. wcomb takes the lock itself,
  # so this is released before the legs and retaken by them.
  if (-not (Test-Path (Join-Path $fix 'gold.txt'))) {
    Say "FIXTURE copying $fixsrc -> $fix"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Copy-Item $fixsrc $fix -Recurse -Force
    Say "FIXTURE copied secs=$([math]::Round($sw.Elapsed.TotalSeconds,1))"
  } else { Say "FIXTURE reused $fix" }
  cmd /c "attrib +I `"$root`" /S /D" | Out-Null
  cmd /c "attrib +I `"$root\*`" /S /D" | Out-Null
  $pf = @(Get-ChildItem (Join-Path $fix 'pristine') -File).Count
  $wf = @(Get-ChildItem (Join-Path $fix 'work') -File).Count
  Say "FIXTURE pristine=$pf work=$wf"
  if ($pf -ne 29 -or $wf -ne 29) { Say "T6CTL-FAIL fixture copy incomplete pristine=$pf work=$wf (want 29/29)"; exit 9 }
  $staged = $true
} finally {
  Release-RigLock $lock
}
if (-not $staged) { exit 9 }

# ONE invocation, three thread counts, two reps: 3 pools x 2 reps x (4 fold +
# 4 resident force + 4 windowed force) = 72 legs. -Reps 2 keeps the internal
# mirror the banked round had; the brief priced -Reps 1 at half the wall and
# the loss of exactly that.
#
# -Rungs 192,512,1024,2048 because the fixture is -c2048 and m = recovery is
# the last legal rung; wcomb's RUNG-BOUND guard refuses measure's default
# 4,096 up front. Passing -Rungs also sets the FORCE rungs to the same list
# (they default to 256,1024,4096), which is what makes 12 legs per pool per rep
# and matches the banked round leg for leg.
#
# -Budget 2048 because at 1 MiB the default -m128 is a window of a few hundred
# sources, under NTT_MIN_WINDOW_PRESENT and nothing the dispatcher would run.
# The banked round used -m2048 and these cells must be comparable with it.
$out   = Join-Path $root "$tag.log"
$wcomb = Join-Path $harness 'wcomb.ps1'
$rc = 17
for ($try = 1; $try -le 60 -and $rc -eq 17; $try++) {
  if ($try -gt 1) { Say "LEGSET $tag lock busy, retry $try in 30s"; Start-Sleep -Seconds 30 }
  cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$root`" -Phase measure -Tag $tag -Bin `"$bin`" -NoBuild -Reps 2 -Threads 4,6,12 -Slice 1048576 -MemberMiB 512 -Recovery 2048 -Rungs 192,512,1024,2048 -Budget 2048 -NttBudget 12884901888 > `"$out`" 2>`"$root\$tag.err`""
  $rc = $LASTEXITCODE
}
$legs = 0
if (Test-Path $out) { $legs = @(Select-String -Path $out -Pattern '^LEG ').Count }
Say "LEGSET $tag rc=$rc legs=$legs log=$out"
if ($rc -ne 0) { Say "T6CTL-FAIL $tag rc=$rc"; exit 9 }

# THE RESIDENCY ASSERT -Residency COULD NOT DO HERE. Every budget=big force leg
# must have windowed NOWHERE (windows=0) and each transform call must have
# covered ALL present sources (ntt_n = n - m); anything else means the resident
# arm crossed the admission gate and this ladder priced ntt_window_row_gate
# under the resident gate's name. The windowed legs are exempt BY DESIGN - they
# are the c_w measurement and windows>0 is what they are for.
$bad = 0; $checked = 0
foreach ($l in (Select-String -Path $out -Pattern '^LEG ').Line) {
  if ($l -notmatch 'budget=big' -or $l -notmatch 'arm=force') { continue }
  $checked++
  $m = [int]([regex]::Match($l, ' m=(\d+) ').Groups[1].Value)
  $n = [int]([regex]::Match($l, ' n=(\d+) ').Groups[1].Value)
  $w = [int]([regex]::Match($l, ' windows=(\d+) ').Groups[1].Value)
  $nn = [regex]::Match($l, ' ntt_n=([0-9/]*) ').Groups[1].Value
  $want = $n - $m
  if ($w -ne 0) { Say "RESIDENCY-FAIL windows=$w at m=$m"; $bad++ }
  foreach ($x in $nn.Split('/')) { if ($x -and [int]$x -ne $want) { Say "RESIDENCY-FAIL ntt_n=$x want=$want at m=$m"; $bad++ } }
}
Say "RESIDENCY checked=$checked bad=$bad"
if ($bad -gt 0) { Say "T6CTL-FAIL residency"; exit 9 }
if ($checked -ne 24) { Say "T6CTL-FAIL residency checked=$checked want=24 - the resident force arm did not run the ladder this round claims"; exit 9 }
Say "T6CTL ALL DONE"
