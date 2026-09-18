# waskt4run.ps1 - lane parfast-nibble-windowed-ask-t4-16sep (re-claimed 17 Sep).
#
# THE WINDOWED ASK ON THE NIBBLE CLASS AT 1 MiB, AT THE FOUR-THREAD POOL.
# The second owed bullet of "The WINDOWED ASK on the NIBBLE class at 1 MiB:
# 312 under-asks here by 3x". Everything in that round is -t12, the pool that
# SET NTT_WINDOW_COMBINE_X86 = 312, and this class has the widest k spread
# between pools of any part on the fleet (249 at -t4 against 395 at -t12 at
# 1 MiB). So "312 under-asks on this class" and "312 under-asks on this class
# AT FULL POOL" are different findings, and nobody can judge a per-class split
# or a second parameter without knowing which it is.
#
# WHY THIS ROUND CAN ANSWER IT AND A k CANNOT. ntt_window_row_gate(sources,
# gate, k) takes three arguments and NONE of them is the pool. So if the
# measured EXCESS moves with the pool, neither option parked with the maintainer can be
# conservative for real users - a per-class split still ships one number per
# class to every pool, and a second parameter in the WINDOW term still has no
# pool to read. That is a THIRD answer to his question 2. If the excess is
# flat across the pool, that is the result that strengthens the per-class
# split. Both outcomes change the decision; neither is a coefficient.
#
# -Threads '4,12' RATHER THAN -t4 ALONE, and this is the design point.
# wcomb's rowgate loop is `foreach rung { foreach thread { foreach arm } }`,
# so the two pools are measured ADJACENT IN TIME AT EVERY RUNG: a drift in box
# conditions hits both equally, and the pool comparison becomes internal to one
# sitting rather than a comparison against numbers taken on another night. The
# 16 Sep -t12 figures then become a cross-check instead of the baseline.
#
# THE BINARY AND THE FIXTURE ARE THE 16 Sep ROUND'S OWN, which the chip did not
# expect to survive and which removes the cross-binary step outright:
# <rig>\wcomb-16sep\src\target\release\parfast.exe is sha256
# 8983A55A4E260BA395B42D252EC1A421B1F35AB8B789CD3F3191E2E01E8E2C84 (= the k
# round's and the ask round's binary, 1.5.0-beta.3 from origin/main 4fedd8b33)
# and fix-1048576-512 is intact with its gold.txt. Both are HASH-GATED below
# before a leg runs. The binary is COPIED into this root rather than run in
# place, and the fixture must be copied because the legs write into fix\work\.
#
# THE GRID IS 128..512 BY 64 AND IT IS NOT THE -t12 ROUND'S GRID, deliberately.
# That round ran 192..512 and its crossovers landed at 255 and 387. At -t4 the
# fold is relatively cheaper per row than the transform, so the crossovers sit
# LOWER - and the k round's own -t4 cells on THIS fixture say how much lower:
# fold 122.49 / 263.90 CPU-s at m = 192 / 512 (both reps averaged), resident
# force 116.60 / 130.01, -m2048 force 139.18 / 165.51. The transform ALREADY
# WINS at m = 192 resident (116.60 against 122.49), which puts that crossover
# near m = 177 - BELOW the bottom rung of the -t12 grid, where it could not
# have been bracketed at all. Linear from the same cells the -m2048 one is
# near m = 238. So the grid is shifted down one rung and extended up one, and
# it brackets all four expected crossovers: -t4 resident ~177 (128-192), -t4
# -m2048 ~238 (192-256), -t12 resident 255 (192-256), -t12 -m2048 387
# (384-448), with 512 as headroom in case the sitting moves the last one.
# ONE UNIFORM GRID ON ALL THREE LADDERS AND BOTH POOLS: a crossover is located
# by interpolating between the two rungs that bracket it, so a grid that
# changed between ladders would make the rung set a second variable.
#
# THE SHAPE LIMIT, read off the k round's own LEG lines rather than assumed.
# Under -m2048 this fixture is windows=3 win_slices=2064 slabs=1 at m = 192 and
# m = 512, and by m = 1,024 it has slabbed (windows=2, win_slices=4128,
# slabs=2) - so -m2048 is in shape across this whole grid. Under -m1024 the
# slab point is m = 512 (the 16 Sep round measured windows 7 -> 6, win_slices
# 1,040 -> 2,080, slabs 1 -> 2 there), so the -m1024 ladder's TOP RUNG IS OUT
# OF SHAPE and is excluded at reduction, exactly as that round excluded it.
# Every LEG line carries windows= / win_slices= / slabs=; waskred.py does the
# exclusion, and a -m1024 ladder that never crosses in shape yields a LOWER
# BOUND, which is the only direction the family's rule allows a constant to be
# argued from.
#
# A FOURTH LADDER, AND IT IS INSURANCE ON THE ONE CELL THE WHOLE EXCESS IS
# MEASURED FROM. The excess is (windowed crossover - resident crossover), so a
# resident crossover that is bracketed but not LOCATED turns both windowed
# numbers back into bounds. At -t4 that risk is real and quantified: the k
# round's two resident force reps at m = 192 are 122.80 and 110.41 CPU-s, an
# 11.2% rep spread, against a fold at 122.64 / 122.34 (0.2%). So "the transform
# already wins at 192" rests on a mean whose two samples straddle the fold -
# one rep says it wins, the other says it loses - and rowgate's A/A floor at
# that rung would be about 11% against an effect near 5%, which is the
# signature of a cell that comes back `unres`. The -m2048 estimate has no such
# problem (1.9% spread). Ladder D therefore re-runs ONLY the two bottom rungs
# of the RESIDENT ladder at -t4, three more reps, and it is placed immediately
# after ladder A rather than at the end of the sitting so the extra reps sit
# adjacent in time to the ones they reinforce. Those are the shortest legs in
# the round. At reduction the A and D legs at m = 128 and 192 are pooled - same
# binary, same fixture, same grid rungs, same pool, same sitting - which takes
# those two cells from 4 fold / 4 force samples to 10 and 10. THE POOLING IS
# SAID OUT LOUD IN THE WRITE-UP rather than buried: they are two wcomb
# invocations and therefore two lock holds, and if the two disagree beyond the
# A/A floor that is a finding about the sitting and not a cell to average away.

# It QUEUES rather than racing: the rig lock does not order waiters, so this
# carries an ahead-list and the cut-3 subject test (a lane is finished when its
# own DONE follows its own most recent CLAIM), which is the rule two earlier
# cuts of this waiter got wrong in one afternoon.
$ErrorActionPreference = 'Continue'
$R        = '<rig>\waskt4-17sep'
$SRC16    = '<rig>\wcomb-16sep'
$SRCFIX   = Join-Path $SRC16 'fix-1048576-512'
$SRCBIN   = Join-Path $SRC16 'src\target\release\parfast.exe'
$WANTHASH = '8983A55A4E260BA395B42D252EC1A421B1F35AB8B789CD3F3191E2E01E8E2C84'
$WANTLEN  = 4174848
$W        = Join-Path $R 'src\research\harness\wcomb.ps1'
$BIN      = Join-Path $R 'bin\parfast.exe'
$COORD    = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$LK       = Join-Path $env:USERPROFILE '.parfast-rig.lock'
$GRID     = '128,192,256,320,384,448,512'
$ID       = 'parfast-nibble-windowed-ask-t4-16sep'
$GEN      = 'b236ac3f'
$AHEADPID = 17256                          # ntt-depth1-tile-second-class-17sep's driver, holding the lock at 18:43:57Z
$AHEAD    = @('ntt-depth1-tile-second-class-17sep')
$DEADLINE = [datetime]::Parse('2026-09-18T01:30:00Z').ToUniversalTime()
$QUIETFALLBACK = 45

function Stamp { (Get-Date).ToUniversalTime().ToString('o') }
function Post([string]$l) { try { Add-Content -Path $COORD -Value $l -Encoding UTF8 } catch { } }
function Test-Busy {
  if (Test-Path $LK) { return $true }
  if (Get-Process parfast,cargo,rustc -ErrorAction SilentlyContinue) { return $true }
  return $false
}
# CUT 3, carried over verbatim in spirit from waskrun.ps1: key on the line's
# SUBJECT (the third token, which is where both record types on this box put
# the id) and require a lane's own DONE to come AFTER its own most recent
# CLAIM. A keyword test cannot be made safe: cut 1 matched `NOT taking`, the
# opening phrase of every queue NOTE, and cut 2 matched a courteous DONE line
# that NAMED THE LANES BEHIND IT. Each cleared a whole ahead-list in under a
# second. The subject test is also what makes a multi-round campaign safe - a
# lane that posts DONE and then re-CLAIMs goes back to blocking this waiter.
$coordOffset = 0
try { $coordOffset = (Get-Item $COORD).Length } catch { }
function Test-AheadDone([string]$id) {
  try {
    $txt = [IO.File]::ReadAllText($COORD)
    if ($txt.Length -le $coordOffset) { return $false }
    $lines = $txt.Substring($coordOffset) -split "`r?`n"
    $lastClaim = -1; $lastDone = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $m = [regex]::Match($lines[$i], '^(DONE|CLAIM)\s+\S+\s+(\S+)')
      if (-not $m.Success) { continue }
      if ($m.Groups[2].Value -ne $id) { continue }
      if ($m.Groups[1].Value -eq 'CLAIM') { $lastClaim = $i } else { $lastDone = $i }
    }
    return ($lastDone -ge 0 -and $lastDone -gt $lastClaim)
  } catch { }
  return $false
}

"WASKT4-WAIT id=$ID pid=$PID aheadpid=$AHEADPID ahead=$($AHEAD -join ',') grid=$GRID deadline=$($DEADLINE.ToString('o')) start=$(Stamp)"
$waitStart = (Get-Date).ToUniversalTime()
# Phase 1: the pid holding the lock now. StartTime is checked so a RECYCLED
# pid cannot read as busy forever.
while ($true) {
  if ($AHEADPID -le 0) { break }
  $p = Get-Process -Id $AHEADPID -ErrorAction SilentlyContinue
  if (-not $p -or $p.StartTime.ToUniversalTime() -ge $waitStart) { break }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "WASKT4-DEADLINE waiting on pid $AHEADPID ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 60
}
"WASKT4-AHEADPID-GONE pid=$AHEADPID ts=$(Stamp)"

# Phase 2: the lanes that queued ahead, with a quiet fallback for one that
# never posts a completion.
$quietSince = $null
while ($true) {
  $pending = @($AHEAD | Where-Object { -not (Test-AheadDone $_) })
  if ($pending.Count -eq 0) { "WASKT4-AHEAD-CLEAR ts=$(Stamp)"; break }
  if (Test-Busy) { $quietSince = $null }
  elseif (-not $quietSince) { $quietSince = (Get-Date).ToUniversalTime() }
  elseif (((Get-Date).ToUniversalTime() - $quietSince).TotalMinutes -ge $QUIETFALLBACK) {
    "WASKT4-AHEAD-FALLBACK quiet $QUIETFALLBACK min, unreported: $($pending -join ',') ts=$(Stamp)"
    Post "NOTE $(Stamp) $ID gen=$GEN - taking the box on the quiet-box fallback: $QUIETFALLBACK continuous minutes with no rig lock and no parfast/cargo/rustc, while $($pending -join ', ') had a CLAIM on this file with no DONE after it. If that is your round paused rather than finished, say so here and I stand down at the end of my current ladder. Kill by pid, never by pattern."
    break
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "WASKT4-DEADLINE pending=$($pending -join ',') ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 120
}

# Phase 3: free TWICE, two minutes apart. A round releases its lock a beat
# before its last child exits, and a multi-ladder SITTING releases the lock
# BETWEEN its invocations - so one quiet sample is not a free box. This is the
# check that actually held the line for two earlier waiters whose ahead-list
# logic had already failed.
while ($true) {
  if (-not (Test-Busy)) {
    Start-Sleep -Seconds 120
    if (-not (Test-Busy)) { break }
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "WASKT4-DEADLINE never free twice ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 60
}
"WASKT4-FREE ts=$(Stamp)"
Post "CLAIM $(Stamp) $ID gen=$GEN (opus5 chip, <user>, apple-m3-ultra-512gb) - TAKING THE BOX for a SITTING of three rowgate ladders, driver pid=$PID, will post DONE. Shape: 1 MiB n=8,192 on the surviving fix-1048576-512, ONE grid ($GRID) on all three ladders and BOTH pools (-Threads 4,12, two reps), resident then -m2048 then -m1024, about 4 to 5 hours. I BUILD NOTHING and I INSTALL NOTHING: the binary is wcomb-16sep's own 8983A55A... copied into my root and hash-gated, and the fixture is a COPY of wcomb-16sep's into my root (C:, never D:) - I write to no root but my own and I delete nothing of anyone else's. My root is <rig>\waskt4-17sep and I delete it when the numbers are banked. Kill by pid, never by pattern."

# ---- stage: binary (hash-gated) and fixture (copied, because legs write work\)
New-Item -ItemType Directory -Force $R, (Join-Path $R 'bin') | Out-Null
$got = (Get-FileHash $SRCBIN -Algorithm SHA256).Hash
$gotlen = (Get-Item $SRCBIN).Length
if ($got -ne $WANTHASH -or $gotlen -ne $WANTLEN) {
  "WASKT4-FAIL binary gate: got $got len $gotlen, want $WANTHASH len $WANTLEN ts=$(Stamp)"
  Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg and RELEASED the box: the binary I meant to run no longer hashes to 8983A55A... (got $got, len $gotlen). Measuring nothing rather than measuring an unknown binary. Box is free."
  exit 6
}
Copy-Item $SRCBIN $BIN -Force
"WASKT4-BIN-OK sha=$got len=$gotlen ts=$(Stamp)"

$myfix = Join-Path $R 'fix-1048576-512'
if (-not (Test-Path (Join-Path $myfix 'gold.txt'))) {
  if (-not (Test-Path (Join-Path $SRCFIX 'gold.txt'))) {
    "WASKT4-FAIL source fixture has no gold.txt ts=$(Stamp)"
    Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg and RELEASED the box: $SRCFIX has no gold.txt, so there is nothing to copy and I will not build a fixture I did not plan for. Box is free."
    exit 6
  }
  "WASKT4-FIXTURE-COPY from $SRCFIX ts=$(Stamp)"
  $cw = [Diagnostics.Stopwatch]::StartNew()
  robocopy $SRCFIX $myfix /E /NFL /NDL /NJH /NJS /R:1 /W:1 | Out-Null
  "WASKT4-FIXTURE-COPIED secs=$([math]::Round($cw.Elapsed.TotalSeconds,1)) ts=$(Stamp)"
}
# shape.txt so RUNG-BOUND reports VERIFIED rather than falling back to the
# -Recovery this script passes. The source fixture predates the field.
[IO.File]::WriteAllText((Join-Path $myfix 'shape.txt'), "slice=1048576 members=16 membermib=512 recovery=2048 payload=random`n")
$gn = (Get-ChildItem (Join-Path $myfix 'pristine') -File -ErrorAction SilentlyContinue).Count
$wn = (Get-ChildItem (Join-Path $myfix 'work') -File -ErrorAction SilentlyContinue).Count
"WASKT4-FIXTURE pristine=$gn work=$wn ts=$(Stamp)"
if ($gn -lt 17 -or $wn -lt 17) {
  "WASKT4-FAIL fixture incomplete ts=$(Stamp)"
  Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg and RELEASED the box: the copied fixture is incomplete (pristine=$gn work=$wn). Box is free."
  exit 6
}
# A 20 GB copy is 20 GB Windows Search has not seen. wcomb only settles a
# fixture it BUILT, so settle the copy here rather than letting the first
# ladder - the resident one, which is the headline - eat the indexer.
"WASKT4-SETTLE-WAIT 180 s after the copy ts=$(Stamp)"
Start-Sleep -Seconds 180

function Run-Round([string]$name, [string]$logname, [hashtable]$p) {
  "--- $name START $(Stamp) ---"
  try { & $W @p 2>&1 | Tee-Object -FilePath (Join-Path $R $logname); "--- $name OK $(Stamp) ---" }
  catch {
    "--- $name FAILED $(Stamp): $($_.Exception.Message)"
    Post "NOTE $(Stamp) $ID gen=$GEN - ladder '$name' FAILED: $($_.Exception.Message). The remaining ladders continue; wcomb's finally released the rig lock. Kill by pid, never by pattern."
  }
}
$common = @{ Root=$R; Phase='rowgate'; Slice=1048576; MemberMiB=512; Recovery=2048
             Rungs=$GRID; Reps=2; Threads='4,12'; Bin=$BIN; NoBuild=$true }

"=== RUN START $(Stamp) ==="
Run-Round 'A resident'       'waskt4res.log' ($common + @{
  Tag='waskt4res'; Label='nib-1m-n8192-res-t4t12'; NttBudget='12884901888'; Residency='resident' })
Run-Round 'D resident bottom rungs, 3 more reps at -t4' 'waskt4res3.log' (@{
  Root=$R; Phase='rowgate'; Slice=1048576; MemberMiB=512; Recovery=2048
  Rungs='128,192'; Reps=3; Threads='4'; Bin=$BIN; NoBuild=$true
  Tag='waskt4res3'; Label='nib-1m-n8192-res-t4-extra'; NttBudget='12884901888'; Residency='resident' })
Run-Round 'B windowed -m2048' 'waskt4w2k.log' ($common + @{
  Tag='waskt4w2k'; Label='nib-1m-n8192-win2k-t4t12'; Budget='2048'; Residency='windowed' })
Run-Round 'C windowed -m1024' 'waskt4w1k.log' ($common + @{
  Tag='waskt4w1k'; Label='nib-1m-n8192-win1k-t4t12'; Budget='1024'; Residency='windowed' })
"=== RUN END $(Stamp) ==="
$freegb = [math]::Round((Get-PSDrive C).Free/1GB,1)
Post "NOTE $(Stamp) $ID gen=$GEN - all three ladders returned, the rig lock is released and I am reducing on the Mac. My root $R stays until the numbers are banked, then goes. C: free ${freegb} GB. I will post a DONE line when the box is finally clear of me."
