# w3winrun.ps1 - lane parfast-nibble-third-window-shape-18sep (gen 249c7173).
#
# A THIRD WINDOW SIZE ON THE NIBBLE CLASS AT 1 MiB, which is the last owed
# bullet of "The windowed ask at the FOUR-thread pool, and what the WALL metric
# does to it". Two rounds have now concluded that ntt_window_row_gate's
# one-parameter form is the wrong SHAPE, from two window sizes (S = 2,064 and
# S = 1,040) - but two points cannot show a curve's form. They establish that
# no single k passes through both; they cannot separate "the form is wrong"
# from "these two cells are 11-12% apart and the measurement is worth about
# that". That separation is exactly what the maintainer's two parked options turn on: a
# per-class split is the same form with different constants, a second parameter
# is a different form.
#
# THE THIRD WINDOW IS -m1536 (S = 1,552), AND THE WIDE END WAS CONSIDERED AND
# REJECTED ON ARITHMETIC. The obvious third rung is -m4096 (S = 4,112, which
# the GFNI-256 class has on this same fixture shape) because it EXTENDS the
# range rather than interpolating into it. It is the wrong choice here, and
# the reason is the excess, not the window:
#
#   The ask is gate + gate*k/(S - k) with gate = 256 on this class at 1 MiB.
#   At S = 4,112 the fitted k values from the two banked cells (376 and 416)
#   predict an excess of 26 and 29 rows. The campaign has ALREADY measured
#   what a crossover is worth - the -t12 CPU arm replicated across two
#   sittings at 252 against 255 and 400 against 387, so 3 to 13 rows - and an
#   excess carries TWO crossovers' errors, about 14 rows. A 26-row excess
#   measured to +-14 rows inverts to k = 337 +- 185: a point that would make
#   the fit WORSE than the two it joined. At S = 1,552 the same k values
#   predict 82 and 94 rows, +-14 rows inverts to about +-47, and the point is
#   better conditioned than the S = 2,064 one already banked.
#
# AND NARROWER THAN 1,040 IS NOT AVAILABLE AT ALL, which is arithmetic and not
# a choice. reconstruct's plan_slabs keeps 2*m*w inside the spendable budget,
# so a window of S sources survives only to m ~ S/2 (the "windowed ask's FORM"
# section measures this: at S = 784 the GFNI-256 ladder has no crossover to
# find, the ask sitting 192 rows past the limit). Extrapolating this class's
# own fitted k to S = 784 puts its crossover at 444 to 472 against a limit of
# 392, so the nibble class walks into the same wall. S = 1,040 is the floor.
#
# SO THE THREE WINDOWS ARE 2,064 / 1,552 / 1,040, plus the resident anchor,
# ALL FOUR IN ONE SITTING ON ONE FIXTURE WITH ONE GRID. The two outer windows
# are re-run rather than taken from the bank on purpose: every excess is
# measured FROM the resident crossover, and a resident anchor from another
# night reintroduces the cross-sitting term the whole design is trying to beat.
# Their banked counterparts then become a drift cross-check instead of the
# baseline.
#
# THE GRID IS THE 17 Sep GRID, 128..512 BY 64, UNCHANGED AND DELIBERATELY SO.
# It brackets all four of that round's located crossovers (-t4 CPU 177 / 234 /
# 348, -t4 wall 185 / 240 / 353, -t12 CPU 252 / 400, -t12 wall 155 / 205 /
# 372), and it brackets the new ladder's predictions (-t4 ~265, -t12 wall
# ~250, -t12 CPU ~480 - that last one close to the top rung, and it is
# reported as a bound if it lands above it). Keeping the grid identical is
# what makes the three re-run ladders a REPLICATE of the banked round rather
# than a new measurement that happens to resemble one.
#
# -Threads '4,12' FOR THE SAME REASON THE 17 Sep ROUND USED IT: wcomb's
# rowgate loop is `foreach rung { foreach thread { foreach arm } }`, so both
# pools are measured adjacent in time at every rung. Here it buys something
# further - FOUR (pool, metric) cells each carrying three window sizes. One
# cell at this precision cannot reject the one-parameter form; four cells
# agreeing on the SIGN of the trend is a much stronger statement than any one
# of them, and four cells scattering is the other answer the chip asks for.
#
# LADDER E IS THE ANCHOR DRIFT CONTROL AND IT IS NOT OPTIONAL. Every excess in
# this round is (windowed crossover - resident crossover), so a resident anchor
# that moves across a six-hour sitting moves all four windowed cells TOGETHER,
# in the same direction, which is exactly the signature a shape failure would
# leave. The 17 Sep round's A/D control bounded one lock handover plus fifteen
# minutes at about 2%; nothing bounds six hours. So ladder E re-runs the three
# resident rungs that bracket every resident crossover in the round (128, 192,
# 256 - covering 155, 177, 185 and 252) at the END of the sitting, and the
# write-up states that drift rather than averaging it away.
#
# THE BINARY AND THE FIXTURE ARE THE 16 Sep ROUND'S, hash-gated below, the same
# pair the 17 Sep round ran: parfast.exe sha256 8983A55A... 4,174,848 bytes,
# 1.5.0-beta.3 from origin/main 4fedd8b33, and fix-1048576-512 (16 x 512 MiB at
# 1 MiB, -c2048, n = 8,192). The fixture is COPIED into this root because the
# legs write into fix\work\. Both survive on the box; neither is rebuilt.
#
# I BUILD NOTHING, INSTALL NOTHING, AND STOP NOTHING. Adobe Creative Cloud
# stays exactly as found - the banked round it is read against ran with it up
# (foreign_cpu medians 13.9-18.6% of a core), so stopping it would change
# conditions between the two rounds I most need comparable.
#
# It QUEUES rather than racing, with the ahead-list and the cut-3 subject test
# carried over from waskt4run.ps1 verbatim in spirit.
$ErrorActionPreference = 'Continue'
$R        = '<rig>\w3win-18sep'
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
$ID       = 'parfast-nibble-third-window-shape-18sep'
$GEN      = '249c7173'
$AHEADPID = 3208                           # cfload.ps1, parfast-load-term-and-third-binary-i5's driver, holding the lock at 01:45Z
$AHEAD    = @('parfast-load-term-and-third-binary-i5')
$DEADLINE = [datetime]::Parse('2026-09-19T12:00:00Z').ToUniversalTime()
$QUIETFALLBACK = 45

function Stamp { (Get-Date).ToUniversalTime().ToString('o') }
function Post([string]$l) { try { Add-Content -Path $COORD -Value $l -Encoding UTF8 } catch { } }
function Test-Busy {
  # THE LOCK IS AUTHORITATIVE AND THE PROCESS LIST IS CORROBORATION, so this
  # ORs them and tests the lock FIRST (.claude/MACHINES.md, the rig protocol:
  # an -and where an -or belongs takes a live box).
  if (Test-Path $LK) { return $true }
  if (Get-Process parfast,cargo,rustc -ErrorAction SilentlyContinue) { return $true }
  return $false
}
# CUT 3: key on the line's SUBJECT (third token) and require a lane's own DONE
# to come AFTER its own most recent CLAIM. A keyword test cannot be made safe -
# cut 1 matched `NOT taking`, the opening of every queue NOTE; cut 2 matched a
# courteous DONE that NAMED the lanes behind it. Each cleared a whole
# ahead-list in under a second.
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

"W3WIN-WAIT id=$ID pid=$PID aheadpid=$AHEADPID ahead=$($AHEAD -join ',') grid=$GRID deadline=$($DEADLINE.ToString('o')) start=$(Stamp)"
# ANNOUNCE THE QUEUE POSITION BEFORE WAITING, and name the pid I am queued
# BEHIND as well as my own. The lock does not order two waiters - they all
# sample the same gap after a release with no arbitration - so the only thing
# that stops two of us taking the same gap is that each can read the other's
# line here. This is NOT a claim on the box and takes nothing.
Post "NOTE $(Stamp) $ID gen=$GEN (opus5 chip, <user>, apple-m3-ultra-512gb) - NOT taking the box: I am QUEUED behind parfast-load-term-and-third-binary-i5 (its cfload.ps1 driver, pid $AHEADPID). My waiter is pid $PID and it holds NO lock. When that lane is done I want about 6 to 7 hours for five rowgate ladders on the nibble class at 1 MiB - a THIRD window size (-m1536, S=1552) beside the two already banked, plus the resident anchor and an anchor-drift control, all in one sitting on one grid. I build nothing, install nothing and stop nothing; Adobe Creative Cloud stays up because the round I am read against ran with it up. If you need the box ahead of me, say so here and I will stand down. Kill by pid, never by pattern."
$waitStart = (Get-Date).ToUniversalTime()
# Phase 1: the pid holding the lock now. StartTime is checked so a RECYCLED pid
# cannot read as busy forever.
while ($true) {
  if ($AHEADPID -le 0) { break }
  $p = Get-Process -Id $AHEADPID -ErrorAction SilentlyContinue
  if (-not $p -or $p.StartTime.ToUniversalTime() -ge $waitStart) { break }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "W3WIN-DEADLINE waiting on pid $AHEADPID ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 60
}
"W3WIN-AHEADPID-GONE pid=$AHEADPID ts=$(Stamp)"

# Phase 2: the lanes that queued ahead, with a quiet fallback for one that
# never posts a completion.
$quietSince = $null
while ($true) {
  $pending = @($AHEAD | Where-Object { -not (Test-AheadDone $_) })
  if ($pending.Count -eq 0) { "W3WIN-AHEAD-CLEAR ts=$(Stamp)"; break }
  if (Test-Busy) { $quietSince = $null }
  elseif (-not $quietSince) { $quietSince = (Get-Date).ToUniversalTime() }
  elseif (((Get-Date).ToUniversalTime() - $quietSince).TotalMinutes -ge $QUIETFALLBACK) {
    "W3WIN-AHEAD-FALLBACK quiet $QUIETFALLBACK min, unreported: $($pending -join ',') ts=$(Stamp)"
    Post "NOTE $(Stamp) $ID gen=$GEN - taking the box on the quiet-box fallback: $QUIETFALLBACK continuous minutes with no rig lock and no parfast/cargo/rustc, while $($pending -join ', ') had a CLAIM on this file with no DONE after it. If that is your round paused rather than finished, say so here and I stand down at the end of my current ladder. Kill by pid, never by pattern."
    break
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "W3WIN-DEADLINE pending=$($pending -join ',') ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 120
}

# Phase 3: free TWICE, two minutes apart. A round releases its lock a beat
# before its last child exits, and a multi-ladder SITTING releases it BETWEEN
# its invocations - so one quiet sample is not a free box.
while ($true) {
  if (-not (Test-Busy)) {
    Start-Sleep -Seconds 120
    if (-not (Test-Busy)) { break }
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "W3WIN-DEADLINE never free twice ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 60
}
"W3WIN-FREE ts=$(Stamp)"
# THE LANE AHEAD RAN A SYNTHETIC LOAD GENERATOR WITH ITS OWN DEADLINE, so a
# free lock is not yet a quiet box. Wait for foreign CPU to settle before the
# anchor ladder, and RECORD what it settled at - the wall figures in this round
# are only usable on a quiet box, and the anchor is the ladder every excess is
# measured from.
"W3WIN-QUIET-WATCH start=$(Stamp)"
for ($i = 0; $i -lt 10; $i++) {
  $c1 = (Get-Process -ErrorAction SilentlyContinue | Measure-Object -Property CPU -Sum).Sum
  Start-Sleep -Seconds 30
  $c2 = (Get-Process -ErrorAction SilentlyContinue | Measure-Object -Property CPU -Sum).Sum
  $pct = [math]::Round((($c2 - $c1) / 30.0) * 100, 1)
  "W3WIN-QUIET sample=$i foreign_1core_pct=$pct ts=$(Stamp)"
  if ($pct -lt 40) { break }
}
Post "CLAIM $(Stamp) $ID gen=$GEN (opus5 chip, <user>, apple-m3-ultra-512gb) - TAKING THE BOX for a SITTING of FIVE rowgate ladders, driver pid=$PID, will post DONE. A THIRD window size on the nibble class at 1 MiB: resident, -m1536 (NEW, S=1552), -m2048, -m1024, then three resident rungs again as an anchor-drift control. ONE grid ($GRID) on every ladder and BOTH pools (-Threads 4,12, two reps), about 6 to 7 hours. I BUILD NOTHING and I INSTALL NOTHING and I STOP NOTHING - Adobe Creative Cloud stays exactly as I found it, because the round I am read against ran with it up. The binary is wcomb-16sep's own 8983A55A... copied into my root and hash-gated, and the fixture is a COPY of wcomb-16sep's into my root (C:, never D:). I write to no root but my own and I delete nothing of anyone else's. My root is <rig>\w3win-18sep and I delete it when the numbers are banked. Kill by pid, never by pattern."

# ---- stage: binary (hash-gated) and fixture (copied, because legs write work\)
New-Item -ItemType Directory -Force $R, (Join-Path $R 'bin') | Out-Null
$got = (Get-FileHash $SRCBIN -Algorithm SHA256).Hash
$gotlen = (Get-Item $SRCBIN).Length
if ($got -ne $WANTHASH -or $gotlen -ne $WANTLEN) {
  "W3WIN-FAIL binary gate: got $got len $gotlen, want $WANTHASH len $WANTLEN ts=$(Stamp)"
  Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg and RELEASED the box: the binary I meant to run no longer hashes to 8983A55A... (got $got, len $gotlen). Measuring nothing rather than measuring an unknown binary. Box is free."
  exit 6
}
Copy-Item $SRCBIN $BIN -Force
"W3WIN-BIN-OK sha=$got len=$gotlen ts=$(Stamp)"

$myfix = Join-Path $R 'fix-1048576-512'
if (-not (Test-Path (Join-Path $myfix 'gold.txt'))) {
  if (-not (Test-Path (Join-Path $SRCFIX 'gold.txt'))) {
    "W3WIN-FAIL source fixture has no gold.txt ts=$(Stamp)"
    Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg and RELEASED the box: $SRCFIX has no gold.txt, so there is nothing to copy and I will not build a fixture I did not plan for. Box is free."
    exit 6
  }
  "W3WIN-FIXTURE-COPY from $SRCFIX ts=$(Stamp)"
  $cw = [Diagnostics.Stopwatch]::StartNew()
  robocopy $SRCFIX $myfix /E /NFL /NDL /NJH /NJS /R:1 /W:1 | Out-Null
  "W3WIN-FIXTURE-COPIED secs=$([math]::Round($cw.Elapsed.TotalSeconds,1)) ts=$(Stamp)"
}
# shape.txt so RUNG-BOUND reports VERIFIED rather than falling back to the
# -Recovery this script passes. The source fixture predates the field.
[IO.File]::WriteAllText((Join-Path $myfix 'shape.txt'), "slice=1048576 members=16 membermib=512 recovery=2048 payload=random`n")
$gn = (Get-ChildItem (Join-Path $myfix 'pristine') -File -ErrorAction SilentlyContinue).Count
$wn = (Get-ChildItem (Join-Path $myfix 'work') -File -ErrorAction SilentlyContinue).Count
"W3WIN-FIXTURE pristine=$gn work=$wn ts=$(Stamp)"
if ($gn -lt 17 -or $wn -lt 17) {
  "W3WIN-FAIL fixture incomplete ts=$(Stamp)"
  Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg and RELEASED the box: the copied fixture is incomplete (pristine=$gn work=$wn). Box is free."
  exit 6
}
# A 20 GB copy is 20 GB Windows Search has not seen. wcomb only settles a
# fixture it BUILT, so settle the copy here rather than letting the anchor
# ladder eat the indexer.
"W3WIN-SETTLE-WAIT 180 s after the copy ts=$(Stamp)"
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
Run-Round 'A resident (the anchor)' 'w3winres.log' ($common + @{
  Tag='w3winres'; Label='nib-1m-n8192-res-t4t12'; NttBudget='12884901888'; Residency='resident' })
Run-Round 'B windowed -m1536 (the NEW window, S=1552)' 'w3winw15.log' ($common + @{
  Tag='w3winw15'; Label='nib-1m-n8192-win15-t4t12'; Budget='1536'; Residency='windowed' })
Run-Round 'C windowed -m2048 (S=2064, replicate)' 'w3winw2k.log' ($common + @{
  Tag='w3winw2k'; Label='nib-1m-n8192-win2k-t4t12'; Budget='2048'; Residency='windowed' })
Run-Round 'D windowed -m1024 (S=1040, replicate)' 'w3winw1k.log' ($common + @{
  Tag='w3winw1k'; Label='nib-1m-n8192-win1k-t4t12'; Budget='1024'; Residency='windowed' })
Run-Round 'E resident anchor-drift control, 128/192/256' 'w3winres2.log' (@{
  Root=$R; Phase='rowgate'; Slice=1048576; MemberMiB=512; Recovery=2048
  Rungs='128,192,256'; Reps=2; Threads='4,12'; Bin=$BIN; NoBuild=$true
  Tag='w3winres2'; Label='nib-1m-n8192-res2-t4t12'; NttBudget='12884901888'; Residency='resident' })
"=== RUN END $(Stamp) ==="
$freegb = [math]::Round((Get-PSDrive C).Free/1GB,1)
Post "NOTE $(Stamp) $ID gen=$GEN - all five ladders returned, the rig lock is released and I am reducing on the Mac. My root $R stays until the numbers are banked, then goes. C: free ${freegb} GB. I will post a DONE line when the box is finally clear of me."
