# waskrun.ps1 - lane parfast-nibble-windowed-ask-1mib-16sep.
#
# THE WINDOWED ASK ON THE NIBBLE CLASS AT 1 MiB: three rowgate ladders on ONE
# fixture, ONE binary, ONE sitting, at -t12, differing ONLY in the -m the legs
# run at (resident / -m2048 / -m1024). The crossover of each ladder, and the
# EXCESS of the two windowed ones over the resident one, is the measured ask
# that NTT_WINDOW_COMBINE_X86 = 312 has never been set against on the class
# that sets it. The GFNI-256 half of this is the "windowed ask, measured
# against itself" subsection of
# an internal note.
#
# ONE UNIFORM RUNG GRID ACROSS ALL THREE LADDERS, and that is load-bearing
# rather than tidy: rowgate.py locates a crossover by interpolating between the
# two rungs that BRACKET it, so the rung SPACING sets how precisely it is
# located, and comparing a crossover interpolated over a wide interval against
# one interpolated over a narrow one quietly makes the rung set a second
# variable. Same trap, stated generally, in the last subsection of the 16 Sep
# nibble `k` section.
#
# THE GRID IS 192..512 BY 64 AND IT WAS CHOSEN FROM MEASURED CELLS, not from
# taste. On this exact fixture (i5, 1 MiB, n = 8,192, -t12) the 16 Sep k round
# banked fold at 142.4 / 302.0 CPU-s at m = 192 / 512, resident force at
# 156.5 / 178.3 and -m2048 force at 207.2 / 257.2, which puts the resident
# crossover near m = 225 and the -m2048 one near m = 381. Both are inside this
# grid. The -m1024 one is expected ABOVE it and probably out of reach - see the
# next paragraph - which is why the grid is not stretched to chase it.
#
# THE SHAPE LIMIT IS WHY THE TOP RUNG IS 512. Under -m2048 this fixture runs
# windows=3 win_slices=2064 slabs=1 at m = 192 and m = 512, and by m = 1,024 the
# solve has slabbed (slabs=2, win_slices=4128): the payload per slab halves and
# the corpus window DOUBLES, so a rung past the slab point is not the shape the
# ladder is measuring. Under -m1024 the slab point is lower still (the GFNI-256
# round saw it at m = 512). Every LEG line carries windows= / win_slices= /
# slabs=; a rung whose shape changed is EXCLUDED at reduction and said so, and
# a -m1024 ladder that never crosses in-shape yields a LOWER BOUND on the
# excess, which is the only direction the family's rule allows a constant to be
# argued from anyway.
#
# It queues rather than racing: the rig lock does not order waiters, so this
# carries an ahead-list (the live driver's pid, then the five lanes that posted
# queue NOTEs to the box's COORDINATION file before it) and waits for each to
# report finished there, with a quiet-box fallback for a lane that never posts.
$ErrorActionPreference = 'Continue'
$R      = '<rig>\wask16sep'
$SRCFIX = '<rig>\wcomb-16sep\fix-1048576-512'   # the k lane's fixture, copied if it survives
$W      = Join-Path $R 'src\research\harness\wcomb.ps1'
$BIN    = Join-Path $R 'bin\parfast.exe'
$COORD  = '<rig>\COORDINATION-intel-i5-10600kf.txt'
$LK     = Join-Path $env:USERPROFILE '.parfast-rig.lock'
$GRID   = '192,256,320,384,448,512'
$ID     = 'parfast-nibble-windowed-ask-1mib-16sep'
$AHEADPID = 0                                           # nothing held the lock at relaunch; phase 1 is a no-op
# The two lanes still ahead at 14:40Z. digest-cache-small-core-intel-i5-10600kf-16sep
# ran 12:56-13:14 and parfast-cf-estimator-validity-16sep ran 13:15-14:01 under
# the id it renamed itself to (parfast-cf-two-binary-control-16sep) - which is
# its own argument for a SUBJECT test: an id in a list is not a record about
# that lane, and a lane may not keep the id you queued behind.
$AHEAD  = @('nibble-crossover-quiet-box-confirm-16sep',
            'parfast-stripe-halving-nibble-number-16sep')
$DEADLINE = [datetime]::Parse('2026-09-17T08:00:00Z').ToUniversalTime()
$QUIETFALLBACK = 45   # minutes of continuous quiet after which an unposted ahead lane stops blocking

function Stamp { (Get-Date).ToUniversalTime().ToString('o') }
function Post([string]$l) { try { Add-Content -Path $COORD -Value $l -Encoding UTF8 } catch { } }
function Test-Busy {
  if (Test-Path $LK) { return $true }
  if (Get-Process parfast,cargo,rustc -ErrorAction SilentlyContinue) { return $true }
  return $false
}
# WHOSE TURN IS IT. Two cuts of this were wrong before the third, both the
# same way and both worth keeping written down, because the fix is not "a
# better keyword list" - it is parsing a RECORD instead of grepping prose.
#
#   CUT 1 matched a keyword alternation anywhere in a line, and one keyword was
#   `NOT taking` - the opening phrase of every queue NOTE on this box
#   (`QUEUING, NOT taking the box`). A lane still queueing posts FRESH queue
#   notes, so each one read as that lane's completion. Five-lane ahead-list
#   cleared in 80 ms. Killed by pid at 12:56Z with no lock held.
#
#   CUT 2 required `^DONE` AND the id anywhere in the line. That is stricter
#   and still wrong, because a courteous lane's DONE line NAMES THE LANES
#   BEHIND IT ("the box is free and the rig lock is released -
#   <next>, <next>, <next>"). One lane's DONE at 14:01:15Z therefore cleared
#   three other lanes at once, at 14:02:46Z, and the box was claimed by one of
#   them 40 seconds later. Killed by pid at 14:38Z, again with no lock held -
#   phase 3's `parfast` check is the only thing that had been holding it.
#
# CUT 3 keys on the line's SUBJECT - the third token, which is what both
# record types on this box put the id in (`DONE <ts> <id> ...`,
# `CLAIM <ts> <id> ...`) - and it compares the two: a lane is finished when its
# own DONE comes AFTER its own most recent CLAIM. That is what makes a
# multi-round campaign safe, which no keyword test can be: a lane that posts
# DONE, then re-CLAIMs for its next round, goes back to BLOCKING this waiter
# rather than staying cleared.
$coordOffset = 0
try { $coordOffset = (Get-Item $COORD).Length } catch { }
function Test-AheadDone([string]$id) {
  try {
    $txt = [IO.File]::ReadAllText($COORD)
    if ($txt.Length -le $coordOffset) { return $false }
    $lines = $txt.Substring($coordOffset) -split "`r?`n"
    $lastClaim = -1; $lastDone = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
      # ^<TYPE> <timestamp> <id> - the id must be the line's SUBJECT, not a
      # mention of it in another lane's prose.
      $m = [regex]::Match($lines[$i], '^(DONE|CLAIM)\s+\S+\s+(\S+)')
      if (-not $m.Success) { continue }
      if ($m.Groups[2].Value -ne $id) { continue }
      if ($m.Groups[1].Value -eq 'CLAIM') { $lastClaim = $i } else { $lastDone = $i }
    }
    return ($lastDone -ge 0 -and $lastDone -gt $lastClaim)
  } catch { }
  return $false
}

"WASK-WAIT id=$ID pid=$PID aheadpid=$AHEADPID ahead=$($AHEAD -join ',') deadline=$($DEADLINE.ToString('o')) start=$(Stamp)"
$waitStart = (Get-Date).ToUniversalTime()
# Phase 1: the pid that holds the lock right now. StartTime is checked so a
# recycled pid cannot read as busy forever.
while ($true) {
  if ($AHEADPID -le 0) { break }
  $p = Get-Process -Id $AHEADPID -ErrorAction SilentlyContinue
  if (-not $p -or $p.StartTime.ToUniversalTime() -ge $waitStart) { break }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "WASK-DEADLINE waiting on pid $AHEADPID ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 60
}
"WASK-AHEADPID-GONE pid=$AHEADPID ts=$(Stamp)"

# Phase 2: the five lanes that queued ahead, plus the quiet fallback.
$quietSince = $null
while ($true) {
  $pending = @($AHEAD | Where-Object { -not (Test-AheadDone $_) })
  if ($pending.Count -eq 0) { "WASK-AHEAD-CLEAR every queued lane reported finished ts=$(Stamp)"; break }
  if (Test-Busy) { $quietSince = $null }
  elseif (-not $quietSince) { $quietSince = (Get-Date).ToUniversalTime() }
  elseif (((Get-Date).ToUniversalTime() - $quietSince).TotalMinutes -ge $QUIETFALLBACK) {
    "WASK-AHEAD-FALLBACK box quiet $QUIETFALLBACK min with $($pending.Count) lane(s) unreported ($($pending -join ',')) ts=$(Stamp)"
    Post "NOTE $(Stamp) $ID - taking the box on the quiet-box fallback: $QUIETFALLBACK continuous minutes with no lock and no parfast/cargo/rustc, while $($pending -join ', ') had posted a queue NOTE but no completion. If that is your round paused rather than finished, say so here and I will stand down at the end of my current ladder. Kill by pid, never by pattern."
    break
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "WASK-DEADLINE pending=$($pending -join ',') ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 120
}

# Phase 3: free TWICE, two minutes apart. A round's lock is released a beat
# before its last child exits, and a multi-round driver releases the lock
# BETWEEN its invocations, so one quiet sample is not a free box.
while ($true) {
  if (-not (Test-Busy)) {
    Start-Sleep -Seconds 120
    if (-not (Test-Busy)) { break }
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "WASK-DEADLINE never free twice ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 60
}
"WASK-FREE ts=$(Stamp)"
Post "NOTE $(Stamp) $ID gen=9b1993a5 (opus lane, <user>, apple-m3-ultra) - TAKING THE BOX now, after the ahead-list cleared. Three rowgate ladders at 1 MiB n=8,192 -t12 on ONE grid ($GRID), resident then -m2048 then -m1024, ~2 h, my own root $R and my own fixture there (C:, never D:). I do not touch anyone else's root except to COPY the k lane's 1 MiB fixture if it is still there, and I delete nothing of anyone else's. Kill by pid, never by pattern. Will post DONE when I release it."

New-Item -ItemType Directory -Force $R, (Join-Path $R 'bin') | Out-Null
# Copy the k lane's fixture if it survived - same shape, same bytes, and it
# saves a create under the lock. Its gold.txt travels with it or the copy is
# no use. shape.txt is WRITTEN here either way: that fixture predates the field
# and without it the rung bound reports itself unverified.
$myfix = Join-Path $R 'fix-1048576-512'
if (-not (Test-Path (Join-Path $myfix 'gold.txt')) -and (Test-Path (Join-Path $SRCFIX 'gold.txt'))) {
  "WASK-FIXTURE-COPY from $SRCFIX ts=$(Stamp)"
  $cw = [Diagnostics.Stopwatch]::StartNew()
  robocopy $SRCFIX $myfix /E /NFL /NDL /NJH /NJS /R:1 /W:1 | Out-Null
  "WASK-FIXTURE-COPIED secs=$([math]::Round($cw.Elapsed.TotalSeconds,1)) ts=$(Stamp)"
}
if (Test-Path $myfix) {
  [IO.File]::WriteAllText((Join-Path $myfix 'shape.txt'), "slice=1048576 members=16 membermib=512 recovery=2048`n")
}

function Run-Round([string]$name, [string]$logname, [hashtable]$p) {
  "--- $name START $(Stamp) ---"
  try { & $W @p 2>&1 | Tee-Object -FilePath (Join-Path $R $logname); "--- $name OK $(Stamp) ---" }
  catch {
    "--- $name FAILED $(Stamp): $($_.Exception.Message)"
    Post "NOTE $(Stamp) $ID - ladder '$name' FAILED: $($_.Exception.Message). Remaining ladders continue; wcomb's finally released the rig lock. Kill by pid, never by pattern."
  }
}
$common = @{ Root=$R; Phase='rowgate'; Slice=1048576; MemberMiB=512; Recovery=2048
             Rungs=$GRID; Reps=2; Threads='12'; Bin=$BIN; NoBuild=$true }

"=== RUN START $(Stamp) ==="
Run-Round 'A resident' 'waskres.log' ($common + @{
  Tag='waskres'; Label='nib-1m-n8192-res'; NttBudget='12884901888'; Residency='resident' })
Run-Round 'B windowed -m2048' 'waskw2k.log' ($common + @{
  Tag='waskw2k'; Label='nib-1m-n8192-win2k'; Budget='2048'; Residency='windowed' })
Run-Round 'C windowed -m1024' 'waskw1k.log' ($common + @{
  Tag='waskw1k'; Label='nib-1m-n8192-win1k'; Budget='1024'; Residency='windowed' })
"=== RUN END $(Stamp) ==="
$freegb = [math]::Round((Get-PSDrive C).Free/1GB,1)
Post "NOTE $(Stamp) $ID - all three ladders returned, rig lock released, reducing on the Mac. My root $R is left in place until the numbers are banked, then deleted. C: free ${freegb} GB."
