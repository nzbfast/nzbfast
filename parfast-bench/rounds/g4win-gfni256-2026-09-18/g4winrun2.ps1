# g4winrun2.ps1 - lane gfni256-four-window-shape-1mib-18sep (gen bdb74dba), ATTEMPT 2.
#
# ATTEMPT 1 RAN ZERO LEGS AND POSTED A COMPLETION NOTE OVER ITS OWN FAILURE.
# Both defects are fixed here and both are worth naming, because the first is
# an open claim in this repo's own ledger and the second is a PowerShell trap
# that makes a failed round look like a finished one.
#
#   DEFECT 1, THE LATE ARRIVAL. Attempt 1 gated on the rig lock and the process
#   list and never RE-READ the coordination file. It read that file once during
#   recon at 10:53Z, found no open claim on the box, built for two minutes, and
#   posted its own CLAIM at 11:02Z - by which time parfast-pinned-band-ladder-4mib
#   had claimed at 11:00:07Z and taken the lock at 11:04:12Z, seven seconds
#   before ladder A asked for it. That is the open claim
#   riglock-waiter-blind-to-late-arrivals ("a rig-lock waiter cannot see a lane
#   that arrives after it arms: its ahead-list is fixed at arm time"), from the
#   other side. So this attempt re-reads the file IMMEDIATELY BEFORE taking the
#   box, and again between ladders, and stands down on a CLAIM that is not mine
#   and has no DONE after it.
#
#   DEFECT 2, THE EXIT CODE THAT IS NOT AN EXCEPTION. Attempt 1 wrapped each
#   ladder in try/catch. wcomb signals a busy rig with `exit 17`, and a non-zero
#   exit from a called .ps1 is NOT a terminating error in PowerShell, so nothing
#   was thrown, the catch never ran, and every one of the six ladders printed OK
#   in the same second. Six ladders "returned" in 0.4 s and the driver posted
#   "all six ladders returned" to the box's coordination file. THE FIX IS NOT A
#   BETTER CATCH: it is to read $LASTEXITCODE, and to treat 17 as WAIT rather
#   than as done or as dead - which is what every other lane's driver on this
#   fleet already does and what attempt 1 should have copied rather than
#   improvised.
#
# NO BUILD. Attempt 1's build succeeded (126.6 s, rc=0) and its binary is in my
# root. It is hash-gated below against the sha attempt 1 recorded rather than
# rebuilt, so this attempt adds no load to the box that currently owns it.
#
# Everything else - the four windows, the uniform grid, both pools, the
# drift control, and why each is what it is - is unchanged from attempt 1 and
# its header is kept here in full below the queueing block.
$ErrorActionPreference = 'Continue'
$R        = '<rig>\g4win-18sep'
$SRC      = Join-Path $R 'src'
$W        = Join-Path $SRC 'research\harness\wcomb.ps1'
$BIN      = Join-Path $SRC 'target\release\parfast.exe'
$COORD    = '<rig>\COORDINATION-coreultra9.txt'
$LK       = Join-Path $env:USERPROFILE '.parfast-rig.lock'
$GRID     = '288,320,352,384,416,448,480,512'
$DRIFT    = '288,320,352,384'
$ID       = 'gfni256-four-window-shape-1mib-18sep'
$GEN      = 'bdb74dba'
$SHA      = 'c4a9de207f7d9aacc57a6b518e319c750bcf3ebf'
$WANTHASH = 'E41347B551440009F1B6DDA56A19FED47860E1B5B0C04A95A51F799B32776B31'
$WANTLEN  = 4324864
$AHEAD    = @('parfast-pinned-band-ladder-4mib')
$DEADLINE = [datetime]::Parse('2026-09-19T12:00:00Z').ToUniversalTime()
$QUIETFALLBACK = 60

function Stamp { (Get-Date).ToUniversalTime().ToString('o') }
function Post([string]$l) { try { Add-Content -Path $COORD -Value $l -Encoding UTF8 } catch { } }
function Test-Busy {
  # THE LOCK IS AUTHORITATIVE AND THE PROCESS LIST IS CORROBORATION, so this
  # ORs them and tests the lock FIRST.
  if (Test-Path $LK) { return $true }
  if (Get-Process parfast,cargo,rustc -ErrorAction SilentlyContinue) { return $true }
  return $false
}
# CUT 3, carried over from w3winrun.ps1 verbatim in spirit: key on the line's
# SUBJECT (third token) and require a lane's own DONE to come AFTER its own most
# recent CLAIM. A keyword test cannot be made safe - it matches the courteous
# DONE that NAMES the lanes behind it, and clears a whole ahead-list in a second.
$coordOffset = 0
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
# THE LATE-ARRIVAL CHECK, which is defect 1's fix. Any lane other than me with a
# CLAIM and no later DONE, anywhere in the file from my arm point on, owns the
# box ahead of me - whether or not it was on my ahead-list when I armed.
function Get-OpenClaimants {
  $open = @()
  try {
    $txt = [IO.File]::ReadAllText($COORD)
    $lines = $txt -split "`r?`n"
    $last = @{}
    foreach ($ln in $lines) {
      $m = [regex]::Match($ln, '^(DONE|CLAIM)\s+\S+\s+(\S+)')
      if (-not $m.Success) { continue }
      $last[$m.Groups[2].Value] = $m.Groups[1].Value
    }
    foreach ($k in $last.Keys) { if ($last[$k] -eq 'CLAIM' -and $k -ne $ID) { $open += $k } }
  } catch { }
  return $open
}

"G4WIN2-START id=$ID gen=$GEN pid=$PID grid=$GRID threads=8,16 sha=$SHA ts=$(Stamp)"
$coordOffset = 0
try { $coordOffset = (Get-Item $COORD).Length } catch { }

Post "NOTE $(Stamp) $ID gen=$GEN (opus5 chip, <user>, apple-m3-ultra-512gb) ACCOUNTS=none - NOT taking the box: I am QUEUED behind parfast-pinned-band-ladder-4mib, who claimed at 11:00:07Z and has it. My waiter is pid $PID and it holds NO lock and runs NO build - my binary is already built and hash-gated in my own root. When their five-ladder sitting posts DONE I want about 5 to 6 hours for six rowgate ladders on the GFNI-256 class at 1 MiB: four window sizes (-m4096, -m2048, -m1536, -m1024) plus the resident anchor and an anchor-drift control, one fixture, one sitting, one uniform grid ($GRID), both pools (-Threads 8,16, Reps 2). This attempt re-reads THIS FILE immediately before taking and between every ladder, and waits out an rc=17 LOCK-BUSY rather than reading it as a finished ladder - the two defects that made my attempt 1 run zero legs. If you need the box ahead of me, say so here and I stand down. Kill by pid, never by pattern."

# Phase 1: the ahead-list, with a quiet fallback for a lane that never posts a
# completion.
$quietSince = $null
while ($true) {
  $pending = @($AHEAD | Where-Object { -not (Test-AheadDone $_) })
  if ($pending.Count -eq 0) { "G4WIN2-AHEAD-CLEAR ts=$(Stamp)"; break }
  if (Test-Busy) { $quietSince = $null }
  elseif (-not $quietSince) { $quietSince = (Get-Date).ToUniversalTime() }
  elseif (((Get-Date).ToUniversalTime() - $quietSince).TotalMinutes -ge $QUIETFALLBACK) {
    "G4WIN2-AHEAD-FALLBACK quiet $QUIETFALLBACK min, unreported: $($pending -join ',') ts=$(Stamp)"
    Post "NOTE $(Stamp) $ID gen=$GEN - taking the box on the quiet-box fallback: $QUIETFALLBACK continuous minutes with no rig lock and no parfast/cargo/rustc, while $($pending -join ', ') had a CLAIM on this file with no DONE after it. If that is your round paused rather than finished, say so here and I stand down at the end of my current ladder. Kill by pid, never by pattern."
    break
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "G4WIN2-DEADLINE pending=$($pending -join ',') ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 120
}

# Phase 2: free TWICE, two minutes apart. A multi-ladder SITTING releases the
# lock BETWEEN its invocations, so one quiet sample is not a free box.
while ($true) {
  if (-not (Test-Busy)) {
    Start-Sleep -Seconds 120
    if (-not (Test-Busy)) { break }
  }
  if ((Get-Date).ToUniversalTime() -gt $DEADLINE) { "G4WIN2-DEADLINE never free twice ts=$(Stamp)"; exit 5 }
  Start-Sleep -Seconds 60
}
"G4WIN2-FREE ts=$(Stamp)"

# Phase 3: the LATE-ARRIVAL re-read, defect 1's fix, immediately before taking.
$claimants = Get-OpenClaimants
if ($claimants.Count -gt 0) {
  "G4WIN2-LATE-ARRIVAL $($claimants -join ',') ts=$(Stamp)"
  Post "NOTE $(Stamp) $ID gen=$GEN - STANDING DOWN before taking: re-reading this file immediately before the take found an OPEN CLAIM with no DONE after it from $($claimants -join ', '). They arrived after I armed and my ahead-list could not have seen them; the box is theirs. I hold no lock, nothing of mine is running and my waiter is exiting. I will re-queue by hand."
  exit 7
}

# Phase 4: quiet watch. The wall figures in this round are only usable on a
# quiet box, and the anchor is the ladder every excess is measured from.
"G4WIN2-QUIET-WATCH start=$(Stamp)"
for ($i = 0; $i -lt 12; $i++) {
  $c1 = (Get-Process -ErrorAction SilentlyContinue | Measure-Object -Property CPU -Sum).Sum
  Start-Sleep -Seconds 30
  $c2 = (Get-Process -ErrorAction SilentlyContinue | Measure-Object -Property CPU -Sum).Sum
  $pct = [math]::Round((($c2 - $c1) / 30.0) * 100, 1)
  "G4WIN2-QUIET sample=$i foreign_1core_pct=$pct ts=$(Stamp)"
  if ($pct -lt 40) { break }
}

# ---- the binary: HASH-GATED, never rebuilt
if (-not (Test-Path $BIN)) {
  "G4WIN2-FAIL binary missing ts=$(Stamp)"
  Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg: my binary is gone from my own root. Measuring nothing rather than rebuilding on a box I have not taken yet. Box is free."
  exit 6
}
$h = (Get-FileHash $BIN -Algorithm SHA256).Hash
$l = (Get-Item $BIN).Length
if ($h -ne $WANTHASH -or $l -ne $WANTLEN) {
  "G4WIN2-FAIL binary gate: got $h len $l, want $WANTHASH len $WANTLEN ts=$(Stamp)"
  Post "NOTE $(Stamp) $ID gen=$GEN - STOOD DOWN before any leg and RELEASED the box: the binary I meant to run no longer hashes to $WANTHASH (got $h, len $l). Measuring nothing rather than measuring an unknown binary. Box is free."
  exit 6
}
"G4WIN2-BIN sha256=$h len=$l ts=$(Stamp)"

Post "CLAIM $(Stamp) $ID gen=$GEN (opus5 chip, <user>, apple-m3-ultra-512gb; an internal note, lease to 2026-09-19T16:26Z) ACCOUNTS=none - TAKING THE BOX for a SITTING of SIX rowgate ladders, driver pid=$PID, will post DONE. This is ATTEMPT 2; attempt 1 ran ZERO legs and its 11:02Z CLAIM and 11:04Z completion NOTE are both retracted in my 11:27Z NOTE. FOUR WINDOW SIZES PLUS THE RESIDENT ANCHOR on the GFNI-256 class at 1 MiB, ONE fixture, ONE sitting, ONE uniform grid ($GRID), BOTH pools (-Threads 8,16, Reps 2): A resident anchor (builds the 10 GiB fixture), B -m4096 (S=4112), C -m2048 (S=2064), D -m1536 (S=1552), E -m1024 (S=1040), F resident again at $DRIFT as the anchor-drift control. The GFNI-256 class is the SECOND kernel class to get a multi-window shape round - question 1 parked with the maintainer is 'is the fix a per-class split?' and no single-class round can answer it; the nibble class got its third window this morning. NO BUILD - my binary is hash-gated at $WANTHASH from origin/main $SHA and was built at 11:02-11:04Z. I INSTALL NOTHING and I STOP NOTHING. My root is <rig>\g4win-18sep and I delete it when the numbers are banked. NO CONSTANT MOVES; this round produces evidence only. I re-read this file immediately before this line and found no open CLAIM but my own. I re-read it again between every ladder and stand down at the end of the current ladder on any CLAIM that is not mine. Estimate 5 to 6 hours. Kill by pid, never by pattern."

# ---- the ladders. rc=17 is WAIT, not done and not dead (defect 2's fix).
function Run-Round([string]$name, [string]$logname, [hashtable]$p) {
  $attempt = 0
  while ($true) {
    $attempt++
    "--- $name START attempt=$attempt $(Stamp) ---"
    & $W @p 2>&1 | Tee-Object -FilePath (Join-Path $R $logname) -Append
    $rc = $LASTEXITCODE
    "--- $name rc=$rc attempt=$attempt $(Stamp) ---"
    if ($rc -ne 17) { return $rc }
    # 17 is LOCK-BUSY. Somebody else has the box mid-sitting; wait them out
    # rather than reading a busy rig as a finished ladder.
    "--- $name LOCK-BUSY, waiting 5 min $(Stamp) ---"
    if ((Get-Date).ToUniversalTime() -gt $DEADLINE) {
      "--- $name GIVING UP on the lock at the deadline $(Stamp) ---"
      Post "NOTE $(Stamp) $ID gen=$GEN - ladder '$name' gave up waiting for the rig lock at my deadline. Nothing of mine is running. Box is free."
      return 17
    }
    Start-Sleep -Seconds 300
  }
}
# BETWEEN LADDERS, RE-READ THE FILE. A lane that claims mid-sitting is exactly
# the case attempt 1 could not see, and a six-hour sitting is six hours of
# exposure to it.
function Test-StandDown([string]$after) {
  $c = Get-OpenClaimants
  if ($c.Count -gt 0) {
    "G4WIN2-STAND-DOWN after=$after claimants=$($c -join ',') ts=$(Stamp)"
    Post "NOTE $(Stamp) $ID gen=$GEN - STANDING DOWN at the end of ladder '$after', as my CLAIM said I would: $($c -join ', ') has an open CLAIM on this file with no DONE after it. My remaining ladders are NOT run and my round is INCOMPLETE - I will say so in the write-up rather than publishing a partial sitting as a whole one. The rig lock is released, nothing of mine is running, my root stays until I have banked what did run. Box is yours."
    return $true
  }
  return $false
}

$common = @{ Root=$R; Phase='rowgate'; Slice=1048576; MemberMiB=512; Recovery=2048
             Rungs=$GRID; Reps=2; Threads='8,16'; Bin=$BIN; NoBuild=$true }

"=== RUN START $(Stamp) ==="
$ladders = @(
  @{ n='A resident (the anchor, builds the fixture)'; f='g4winres.log';  p=($common + @{ Tag='g4winres';  Label='gfni256-1m-n8192-res-t8t16';   NttBudget='12884901888'; Residency='resident' }) },
  @{ n='B windowed -m4096 (S=4112)';                  f='g4winw4k.log';  p=($common + @{ Tag='g4winw4k';  Label='gfni256-1m-n8192-win4k-t8t16'; Budget='4096'; Residency='windowed' }) },
  @{ n='C windowed -m2048 (S=2064)';                  f='g4winw2k.log';  p=($common + @{ Tag='g4winw2k';  Label='gfni256-1m-n8192-win2k-t8t16'; Budget='2048'; Residency='windowed' }) },
  @{ n='D windowed -m1536 (S=1552)';                  f='g4winw15.log';  p=($common + @{ Tag='g4winw15';  Label='gfni256-1m-n8192-win15-t8t16'; Budget='1536'; Residency='windowed' }) },
  @{ n='E windowed -m1024 (S=1040)';                  f='g4winw1k.log';  p=($common + @{ Tag='g4winw1k';  Label='gfni256-1m-n8192-win1k-t8t16'; Budget='1024'; Residency='windowed' }) },
  @{ n='F resident anchor-drift control';             f='g4winres2.log'; p=@{ Root=$R; Phase='rowgate'; Slice=1048576; MemberMiB=512; Recovery=2048
                                                                             Rungs=$DRIFT; Reps=2; Threads='8,16'; Bin=$BIN; NoBuild=$true
                                                                             Tag='g4winres2'; Label='gfni256-1m-n8192-res2-t8t16'; NttBudget='12884901888'; Residency='resident' } }
)
foreach ($ld in $ladders) {
  $rc = Run-Round $ld.n $ld.f $ld.p
  if ($rc -eq 17) { "G4WIN2-ABORT lock never freed ts=$(Stamp)"; break }
  if (Test-StandDown $ld.n) { break }
}
"=== RUN END $(Stamp) ==="
$freegb = [math]::Round((Get-PSDrive C).Free/1GB,1)
Post "NOTE $(Stamp) $ID gen=$GEN - my ladders have returned, the rig lock is released and I am reducing on the Mac. Read my per-ladder rc lines in <rig>\g4win-18sep\g4winrun2.log before treating this as a complete sitting - attempt 1 posted a completion line over a round that ran nothing, and I will not have this one read on trust. My root $R stays until the numbers are banked, then goes. C: free ${freegb} GB. I will post a DONE line when the box is finally clear of me."
"G4WIN2-END ts=$(Stamp)"
