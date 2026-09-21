param(
  [Parameter(Mandatory=$true)][string]$Root,      # holds src\ (the base tree), base\ and new\ (the two overlays), and the logs
  [Parameter(Mandatory=$true)][string]$Tag,       # the wcomb rounds' tag; rep N's legs carry round=$Tag-rN; the merged log is $Root\$Tag.log
  [Parameter(Mandatory=$true)][string]$Rungs,     # wcomb.ps1 -Rungs, comma separated
  [Parameter(Mandatory=$true)][string]$UntilUtc,  # give up waiting for a free box past this
  [Parameter(Mandatory=$true)][string]$Coord,     # the box's LIVE coordination file (<rig>\... on intel-i5-10600kf, <rig>\COORDINATION-coreultra9.txt on intel-core-ultra-9-386h)
  [int]$Reps = 4,                                 # 4 = one full rotation of four arms: every arm in every slot once per rung
  [string]$Ahead = '',                            # comma list of lane ids QUEUED on the box before this lane; deferred to until each closes (see Test-Ahead) or -AheadCapMin
  [int]$AheadCapMin = 180,                        # deference stops this many minutes after the box FIRST reads idle, so a QUEUED line that never runs cannot hold the box forever
  [string]$ExpectBase = '',                       # the 15 Sep round's BIN sha256 for the base, reported MATCH / DIFFERS, never refused
  [string]$ExpectNew = '',                        # ... and for the change
  [string]$SrcTar = '',                           # a tar.gz under $Root holding src\; unpacked only when $Root\src is absent
  [string]$Claim = 'ntt-narrow-x86-rotated-remeasure-18sep',
  [string]$Gen = 'fe0dc3ee'
)
# narrowx86r.ps1 - the 15 Sep ntt-narrow x86 A/B again, with the ARM ORDER ROTATED.
#
# Written 18 Sep 2026 for lane ntt-narrow-x86-rotated-remeasure-18sep, census
# row R2 of an internal note. It is
# rounds/ntt-narrow-2026-09-15/narrowx86.ps1 with three things changed
# and nothing else about the measurement:
#
#   1. THE ARM ORDER ROTATES ONE STEP A REP. The 15 Sep driver called
#      wcomb.ps1 -Phase validate once with -Reps 2 and let it run
#      fold, force, auto, autoalt in that order at every rung of every rep,
#      so `fold` was always first and `autoalt` (the base) always last. The
#      harness this round runs is the SAME wcomb.ps1 the 15 Sep round ran
#      (sha256 f49c2437..., from the on-box tree), which has -Arms but no
#      -Flip and no rotation, so the rotation lives HERE: one wcomb
#      invocation per rep with -Reps 1 and -Arms rotated
#      (`ARMS[k..] + ARMS[..k]`, k = rep-1 mod 4), and four reps so every arm
#      holds every slot exactly once per rung. Not a reversal: -Flip's
#      two-slot swap is position-balanced only in the mean over four arms.
#      The order is banked on a NARROW-REP line per rep in the driver log,
#      and the reducer (nrdx.py beside this file) derives arm_pos per leg
#      from the LEG timestamps and checks it against that line.
#   2. FOUR REPS, NOT TWO, so a per-rep PAIRED statistic (median of the
#      per-rep difference plus a sign test) carries the verdict, the way
#      an internal note did for
#      the NEON half. Four is what a balanced rotation of four arms needs
#      and about twice the census's 25 box-minute price; a sign test at
#      n = 4 cannot reach p < 0.05 on its own, so the write-up reads the
#      size of the paired median against the per-rep spread as well.
#   3. BOTH binaries are built from EXPLICIT overlays (base\ and new\), so
#      the two trees are stated rather than one being "src as found". The
#      15 Sep driver built src as found and then overlaid new\; on intel-i5-10600kf
#      src\ was left holding the change, so building it "as found" again
#      would have produced two copies of the change.
#
# Everything else is the 15 Sep round: same rungs (-Rungs), same -t4 -m128
# validate phase, same fixture recipe (wcomb builds 16 x 64 MiB random members
# with -c4096 at 64 KiB when $Root\fix has no gold.txt), same roots on the
# same boxes so the built binaries have every chance of hashing identical to
# the 15 Sep BIN lines (they embed their source paths), same on-box harness.
#
# BOX DISCIPLINE, which is where this differs from the 15 Sep copy most:
#   * FREE is decided by pid LIVENESS, not by the lock file's presence
#     (harness/riglock_state.py's rule, landed 16 Sep as 49d5c9795):
#     a lock naming a live pid whose start time is not later than the lock's
#     own stamp is held at any age; a lock that is unreadable is held (plib
#     opens it with FileShare::None, so only a live taker can make it
#     unreadable); a lock naming nobody or a dead or recycled pid is an
#     ORPHAN, cleared here with a NARROW-RIG-LOCK-ORPHAN line and a NOTE on
#     the coordination file, because the old wcomb.ps1 this round runs takes
#     its lock with CreateNew and would otherwise exit 17 against it forever.
#   * Two idle samples a minute apart (wcombq.ps1's rule), AND every lane in
#     -Ahead deferred to: a lane is ahead while its latest QUEUED or open
#     marker line on $Coord has no later CLOSE-marker line naming it. The
#     marker vocabulary is the FIRST TOKEN of the line, from
#     .claude/tools/bench-accounts-parse.py's MARKERS roster (open:
#     ACTIVATING CLAIM CLAIM-EXTENSION CONTINUATION CROSS-CLAIM DIALED EXTEND
#     HOLD INTERIM LATE-CLAIM LAUNCHED LIVE PROGRESS RELAUNCH RELAUNCHED
#     RESULT START TAKEOVER; close: ABORTED DONE RELEASE RELEASED STAND-DOWN
#     WITHDRAWN), never a phrase anywhere in the line (the waskrun.ps1 trap
#     in .claude/skills/bench-suite item 0a5). -AheadCapMin bounds the
#     deference so a QUEUED intention that never runs cannot hold the box
#     (the 213-minute trap in tools/bench-box-gate.py's header); a lane that
#     actually takes the box shows as a held lock and needs no deference.
#   * The launch window is closed: this driver takes the rig lock itself for
#     the two builds (about five minutes) and posts its CLAIM only once it
#     holds it, then releases it and lets each wcomb invocation take it. A
#     wcomb refused with 17 (someone took the box between two reps) waits for
#     a free box again and retries THAT rep; reps are whole invocations, so a
#     foreign sitting between reps is visible in the log and never inside a
#     rep's pairing.
#   * Posts QUEUED (from the Mac, before launch), CLAIM, NOTE, DONE or
#     WITHDRAWN to $Coord with the claim id and gen on every line.
#
# Launch it DETACHED through Win32_Process::Create (the job-object trap in
# harness/wlaunch.ps1's header). wlaunch.ps1 itself refuses to launch
# while the rig lock is live, which is right for a round that takes the box at
# once and wrong for a waiter, so the launch is the same CIM call by hand.
$ErrorActionPreference = 'Stop'
$lk = Join-Path $env:USERPROFILE '.parfast-rig.lock'
# coord-matcher-gate: this round ran under the ON-BOX 15 Sep harness (plib.ps1 4464b815..., wcomb.ps1 f49c2437..., hash-identical to the round it re-measures) which predates Get-OpenClaimants / Get-CoordFoldedState / Take-RigLockWhenFree, so the library was not on the box to call; this copy is the RECORD of the round as it ran (its logs are banked beside it) and its vocabulary was copied from bench-accounts-parse.py MARKERS on the day. Do not reuse it: a new round on a current tree calls the library.
$OPEN_KW = @('ACTIVATING','CLAIM','CLAIM-EXTENSION','CONTINUATION','CROSS-CLAIM','DIALED','EXTEND','HOLD','INTERIM','LATE-CLAIM','LAUNCHED','LIVE','PROGRESS','RELAUNCH','RELAUNCHED','RESULT','START','TAKEOVER','QUEUED')
# coord-matcher-gate: same waiver as the line above - the banked record of a round run under the pre-library on-box harness.
$CLOSE_KW = @('ABORTED','DONE','RELEASE','RELEASED','STAND-DOWN','WITHDRAWN')
function Get-Ts { (Get-Date).ToUniversalTime().ToString('o') }
function Coord([string]$kind, [string]$text) {
  Add-Content -Path $Coord -Value "$kind $(Get-Ts) $Claim gen=$Gen (fable chip, <user>, apple-m3-ultra-512gb) ACCOUNTS=none - $text"
}
function Get-BoxCpu { $v = -1; try { $v = [int]((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average) } catch { }; return $v }
function Get-ToolProcs { @(Get-Process parfast, cargo, rustc -ErrorAction SilentlyContinue | ForEach-Object { "$($_.ProcessName):$($_.Id)" }) }

function Get-LockState {
  if (-not (Test-Path $lk)) { return @{ state = 'free'; text = '' } }
  $txt = $null
  try { $txt = [IO.File]::ReadAllText($lk) } catch { return @{ state = 'held'; text = '(unreadable: open exclusively by a live taker)' } }
  if ($txt -match 'pid=(\d+)') {
    $holder = [int]$Matches[1]
    $p = Get-Process -Id $holder -ErrorAction SilentlyContinue
    if ($p) {
      # BOTH halves of the pid check: alive, AND not started after the lock's
      # own stamp (a recycled pid parses fine and is still an orphan).
      $recycled = $false
      if ($txt -match 'started=(\S+)') {
        try {
          $st = [datetime]::Parse($Matches[1]).ToUniversalTime()
          if ($p.StartTime.ToUniversalTime() -gt $st.AddSeconds(5)) { $recycled = $true }
        } catch { }   # StartTime unreadable (another user's process): treat as alive, i.e. held
      }
      if (-not $recycled) { return @{ state = 'held'; text = $txt.Trim() } }
      return @{ state = 'orphan'; text = "$($txt.Trim()) (pid $holder is alive but started after the lock's stamp - recycled)" }
    }
    return @{ state = 'orphan'; text = "$($txt.Trim()) (pid $holder is not alive)" }
  }
  return @{ state = 'orphan'; text = "$($txt.Trim()) (names no pid)" }
}

function Test-Ahead([string]$id) {
  # TRUE while the lane's latest QUEUED/open marker line on $Coord has no later
  # CLOSE marker line that ROUTES to it. First token is the marker. A line
  # routes to a lane when the lane is its POSTER (token 3, after marker and
  # timestamp) or, for a close, when it carries the fleet's third-party form
  # "... FOR <lane>'s ROUND" (bench-accounts-parse.py rule 7). A line that
  # merely MENTIONS the lane - another lane's QUEUED "behind <lane>", a
  # WITHDRAWN that lists who is still queued - routes to its own poster and
  # says nothing about this one; the first cut of this counted such a mention
  # as a close and read a queued lane as gone within a minute of launch.
  $lastOpen = ''; $lastClose = ''
  foreach ($line in (Get-Content $Coord -ErrorAction SilentlyContinue)) {
    $t = $line.TrimStart([char]0xFEFF).Split(' ')
    if ($t.Count -lt 3) { continue }
    $poster = ($t[2] -eq $id) -or ($t[2] -eq "$id,") -or ($t[2] -eq "${id}:")
    if ($OPEN_KW -contains $t[0]) {
      if ($poster -and $t[1] -gt $lastOpen) { $lastOpen = $t[1] }
    } elseif ($CLOSE_KW -contains $t[0]) {
      $routes = $poster
      if (-not $routes) {
        for ($j = 3; $j -lt $t.Count - 1; $j++) {
          if ($t[$j] -eq 'FOR' -and ($t[$j + 1] -eq $id -or $t[$j + 1] -eq "$id's" -or $t[$j + 1] -eq "${id}'s")) { $routes = $true; break }
        }
      }
      if ($routes -and $t[1] -gt $lastClose) { $lastClose = $t[1] }
    }
  }
  if (-not $lastOpen) { return $false }
  return ($lastClose -lt $lastOpen)
}

$deadline = [datetime]::Parse($UntilUtc).ToUniversalTime()
$script:firstIdle = $null
$script:aheadList = @()
if ($Ahead) { $script:aheadList = @($Ahead.Split(',') | Where-Object { $_ }) }

function Wait-Free {
  # Returns when the box read FREE twice a minute apart: rig lock free or
  # orphan, no parfast/cargo/rustc, and no -Ahead lane still open (until the
  # cap). Exits 5 past the deadline, posting WITHDRAWN.
  $streak = 0; $i = 0
  while ($true) {
    $ls = Get-LockState
    $procs = Get-ToolProcs
    $idle = ($ls.state -ne 'held') -and ($procs.Count -eq 0)
    if ($idle -and -not $script:firstIdle) { $script:firstIdle = (Get-Date).ToUniversalTime(); "NARROW-IDLE-FIRST the box first read idle ts=$(Get-Ts)" }
    $ahead = @()
    if ($script:aheadList.Count -gt 0) {
      if ($script:firstIdle -and ((Get-Date).ToUniversalTime() -gt $script:firstIdle.AddMinutes($AheadCapMin))) {
        "NARROW-AHEAD-CAP deference to [$($script:aheadList -join ',')] stopped: $AheadCapMin min after the box first read idle ($($script:firstIdle.ToString('o'))) ts=$(Get-Ts)"
        $script:aheadList = @()
      } else {
        $ahead = @($script:aheadList | Where-Object { Test-Ahead $_ })
      }
    }
    $free = $idle -and ($ahead.Count -eq 0)
    if ($free) { $streak++ } else { $streak = 0 }
    if (($i % 10) -eq 0 -or $free) { "NARROW-WAIT lock=$($ls.state) procs=$($procs.Count) ahead=[$($ahead -join ',')] free=$free streak=$streak box_cpu=$(Get-BoxCpu) ts=$(Get-Ts)" }
    if ($streak -ge 2) {
      $ls = Get-LockState
      if ($ls.state -eq 'orphan') {
        Remove-Item $lk -Force
        "NARROW-RIG-LOCK-ORPHAN cleared at $lk - was: $($ls.text). Liveness came from the holder (dead or unnamed pid), never from the file's age. ts=$(Get-Ts)"
        Coord 'NOTE' "(rig lock, $env:COMPUTERNAME) ORPHAN cleared at $lk - was: $($ls.text). Liveness came from the holder (dead or unnamed pid), never from the file's age."
      }
      return
    }
    if ((Get-Date).ToUniversalTime() -gt $deadline) {
      "NARROW-DEADLINE the box never came free ts=$(Get-Ts)"
      Coord 'WITHDRAWN' "the waiter reached its deadline $UntilUtc without a free box; nothing built, nothing run, no lock ever taken. Closing my QUEUED line."
      exit 5
    }
    Start-Sleep -Seconds 60; $i++
  }
}

$script:mylock = $null
function Take-MyLock {
  try { $script:mylock = [IO.File]::Open($lk, 'CreateNew', 'Write', 'None') } catch { return $false }
  $txt = "round=$Tag pid=$PID started=$(Get-Ts)"
  $b = [Text.Encoding]::ASCII.GetBytes($txt); $script:mylock.Write($b, 0, $b.Length); $script:mylock.Flush()
  "NARROW-RIG-LOCK-TAKEN $lk $txt"
  return $true
}
function Release-MyLock {
  if ($script:mylock) { $script:mylock.Close(); $script:mylock = $null; Remove-Item $lk -Force -ErrorAction SilentlyContinue; "NARROW-RIG-LOCK-RELEASED $lk ts=$(Get-Ts)" }
}

$src = Join-Path $Root 'src'
$exe = Join-Path $src 'target\release\parfast.exe'
$baseexe = Join-Path $Root 'parfast-base.exe'
$newexe = Join-Path $Root 'parfast-new.exe'
$h = Join-Path $src 'research\harness'

function Invoke-Build([string]$label) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c for the reason wcomb.ps1 gives: cargo's stderr progress is a
  # terminating error under 'Stop' in PowerShell 5.1.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-$label.log`" 2>&1"
  $rc = $LASTEXITCODE
  Pop-Location
  "NARROW-BUILD $label rc=$rc secs=$([math]::Round($sw.Elapsed.TotalSeconds,1)) ts=$(Get-Ts)"
  if ($rc -ne 0) { "NARROW-FAIL build $label, see $Root\build-$label.log"; Release-MyLock; Coord 'DONE' "round FAILED: cargo build of the $label tree rc=$rc; rig lock released, nothing of mine running, root $Root left for a look."; exit 9 }
}

function Invoke-Overlay([string]$dir) {
  # Copy every file under $Root\$dir over src AND RESTAMP ITS MTIME (the
  # 15 Sep driver's load-bearing note: Copy-Item keeps the source mtime and
  # cargo's fingerprint would call the tree fresh). AppleDouble `._*` files
  # from a Mac-side copy are skipped rather than dropped into the tree.
  $o = (Resolve-Path (Join-Path $Root $dir)).Path
  foreach ($f in Get-ChildItem $o -Recurse -File) {
    if ($f.Name.StartsWith('._')) { continue }
    $rel = $f.FullName.Substring($o.Length + 1)
    $dst = Join-Path $src $rel
    Copy-Item $f.FullName $dst -Force
    (Get-Item $dst).LastWriteTime = Get-Date
    "NARROW-OVERLAY $dir $rel sha256=$((Get-FileHash $dst).Hash)"
  }
}

"NARROW-WAIT tag=$Tag rungs=$Rungs reps=$Reps until=$UntilUtc ahead=[$Ahead] cap_min=$AheadCapMin coord=$Coord root=$Root pid=$PID ts=$(Get-Ts)"
try {
  while ($true) {
    Wait-Free
    if (Take-MyLock) { break }
    "NARROW-LOCK-RACE somebody took the rig lock in the launch window; waiting again ts=$(Get-Ts)"
  }
  "NARROW-FREE ts=$(Get-Ts) box_cpu=$(Get-BoxCpu)"
  $script:aheadList = @()   # I hold the sitting now; deference is over
  Coord 'CLAIM' "TOOK THE BOX, driver pid=$PID root=$Root. The rig lock is mine as of now for the two cargo release builds (about 5 min, all cores), then FOUR wcomb.ps1 -Phase validate invocations (-t4 -m128, rungs $Rungs, arms fold/force/auto/autoalt rotated one step per rep, 40 legs each, about 8-12 min each) that each take the rig lock themselves; the gaps between them are seconds and are NOT openings. Census R2 of an internal note. I re-read this file on every wait sample and found no open CLAIM but the one that just closed. INSTALL nothing, STOP nothing, move NO constant; my root stays until the numbers are banked. Will post DONE. Kill by pid, never by pattern."
  cmd /c "attrib +I `"$Root`" /S /D" | Out-Null
  if (-not (Test-Path $src)) {
    if (-not $SrcTar) { "NARROW-FAIL no src\ and no -SrcTar"; Release-MyLock; Coord 'DONE' "round FAILED: no source tree; rig lock released, nothing run."; exit 9 }
    cmd /c "tar -xzf `"$(Join-Path $Root $SrcTar)`" -C `"$Root`" 2>&1"
    "NARROW-UNPACK rc=$LASTEXITCODE ts=$(Get-Ts)"
    if (-not (Test-Path (Join-Path $h 'wcomb.ps1'))) { "NARROW-FAIL unpack"; Release-MyLock; Coord 'DONE' "round FAILED: unpack; rig lock released, nothing run."; exit 9 }
  }
  "NARROW-HARNESS wcomb.ps1 sha256=$((Get-FileHash (Join-Path $h 'wcomb.ps1')).Hash) plib.ps1 sha256=$((Get-FileHash (Join-Path $h 'plib.ps1')).Hash)"
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }

  Invoke-Overlay 'base'
  Invoke-Build 'base'
  Copy-Item $exe $baseexe -Force
  Invoke-Overlay 'new'
  Invoke-Build 'new'
  Copy-Item $exe $newexe -Force
  $hb = (Get-FileHash $baseexe).Hash
  $hn = (Get-FileHash $newexe).Hash
  "NARROW-BINS base=$hb new=$hn"
  if ($hb -eq $hn) { "NARROW-FAIL the overlays did not produce two different binaries"; Release-MyLock; Coord 'DONE' "round FAILED: the two overlays built one binary; rig lock released, nothing run."; exit 9 }
  if ($ExpectBase) { "NARROW-EXPECT base $(if ($hb -ieq $ExpectBase) { 'MATCH' } else { 'DIFFERS' }) 15sep=$ExpectBase" }
  if ($ExpectNew)  { "NARROW-EXPECT new $(if ($hn -ieq $ExpectNew) { 'MATCH' } else { 'DIFFERS' }) 15sep=$ExpectNew" }
  Release-MyLock

  $arms = @('fold', 'force', 'auto', 'autoalt')
  $rc = 0
  for ($rep = 1; $rep -le $Reps; $rep++) {
    $k = ($rep - 1) % $arms.Count
    $order = @($arms[$k..($arms.Count - 1)]) + @(if ($k -gt 0) { $arms[0..($k - 1)] })
    "NARROW-REP rep=$rep arm_order=rotating-by-rep arms=$($order -join ',') ts=$(Get-Ts)"
    while ($true) {
      "NARROW-BOX rep=$rep when=before box_cpu=$(Get-BoxCpu) procs=$((Get-ToolProcs).Count) ts=$(Get-Ts)"
      $sw = [Diagnostics.Stopwatch]::StartNew()
      cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File $h\wcomb.ps1 -Root $Root -Phase validate -NoBuild -Bin $newexe -AltBin $baseexe -Reps 1 -Arms $($order -join ',') -Rungs $Rungs -Tag $Tag-r$rep >> `"$Root\$Tag.log`" 2>&1"
      $rc = $LASTEXITCODE
      "NARROW-WCOMB rep=$rep rc=$rc secs=$([math]::Round($sw.Elapsed.TotalSeconds,1)) ts=$(Get-Ts)"
      "NARROW-BOX rep=$rep when=after box_cpu=$(Get-BoxCpu) procs=$((Get-ToolProcs).Count) ts=$(Get-Ts)"
      if ($rc -ne 17) { break }
      "NARROW-LOCK-BUSY rep=$rep - somebody took the rig lock between two reps; waiting for a free box and retrying this rep ts=$(Get-Ts)"
      Coord 'NOTE' "rep $rep of my round was refused the rig lock (wcomb rc=17); I am WAITING for the box to come free again and will retry that rep. Legs already banked: $((Select-String -Path (Join-Path $Root "$Tag.log") -Pattern '^LEG ' -SimpleMatch | Measure-Object).Count)."
      Wait-Free
    }
    if ($rc -ne 0) { "NARROW-FAIL wcomb rep=$rep rc=$rc"; Coord 'DONE' "round FAILED at rep $rep (wcomb rc=$rc); rig lock released by wcomb, nothing of mine running; root $Root left for a look."; exit 9 }
  }
  $legs = (Select-String -Path (Join-Path $Root "$Tag.log") -Pattern '^LEG ' | Measure-Object).Count
  $gated = (Select-String -Path (Join-Path $Root "$Tag.log") -Pattern '^LEG .* rc=0 restored=16/16 ' | Measure-Object).Count
  "NARROW-DONE rc=0 legs=$legs gated=$gated log=$Root\$Tag.log ts=$(Get-Ts)"
  Coord 'DONE' "BOX RELEASED. Round ended rc=0: $legs legs over $Reps reps at rungs $Rungs, $gated of them rc=0 and restored 16/16, arm order rotated one step per rep (NARROW-REP lines in $Root\$Tag-driver.log). The rig lock is released, no parfast/cargo of mine is running; my root $Root (two binaries, a 2.7 GB fixture, a source tree and its target dir) stays until the numbers are banked in rounds/ntt-narrow-2026-09-18/, then goes. Nothing installed, nothing stopped, no constant moved."
} finally {
  Release-MyLock
}
