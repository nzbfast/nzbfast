# nttfw-i5.ps1 - the FIXED-WIDTH NTT `m` ladder, Windows half.
#
# WHAT IT MEASURES, and why it is not nttladder.py with different rungs.
# Sections 8.11 through 8.14 of
# an internal note price the per-window upper-
# tree charge `T(m)` by DIFFERENCING a one-window leg against a two-window leg
# at one `m`, which cancels a leaf term `c_l * S` on the assumption that `c_l`
# is the same at both window WIDTHS. Section 8.15.3 found that assumption false
# at the top of the `m` axis: `df/dS` is 0.32-0.34 ms/source to about 14,000
# sources a window and 0.027 above 22,000, a twelvefold collapse, and because
# windows NARROW as `m` rises the resulting error is CORRELATED with the axis.
# Run naively over 8.15's own 120-leg ladder the difference estimator returned
# a below-tile slope 35% low, a NEGATIVE middle slope, and the first knee at
# 3,179 against 4,369. Fitting `f(S)` and `F(m)` jointly was tried and rejected
# on a synthetic with known truth (second knee 18,142 against 21,845).
#
# THE FIX IS IN THE DESIGN, and this script is it. Every rung is budgeted for
# the SAME window width `S*`, so `f(S*)` is a constant that cancels outright and
# the window COUNT falls out of the corpus. The per-window charge is then
#
#     (syn_total - t_tail) / k_full   =   f(S*) + F(m)
#
# and differences between rungs are pure tree charge with no model of the leaf
# term anywhere. A constant offset moves neither a slope nor a knee: for
# `a1 + b1*m + G` and `a2 + b2*m + G` the crossing is `(a2-a1)/(b1-b2)`, `G`
# cancelled. The TAIL window - the remainder, at a different width - is excluded,
# which is why every window's own `(S, t)` is banked rather than the leg's sum.
#
# `S*` IS BOUNDED BELOW BY A SHIPPED RULE, NOT BY TASTE. `ntt_admit_within`
# step 3 halves the stripe while `arenas > budget - arenas`, so a rung holds
# `W = 512` only while `S* * block_size >= threads * scratch_bytes(m, 512)`.
# The arena GROWS with `m` while the present corpus `N - m` SHRINKS, and
# `par2gen::MAX_INPUT_SLICES` caps `N` at 32,768 blocks whatever the width, so
# the two close on each other and there is a hard ceiling on how far above the
# depth-1 tile any ladder can reach at a given block size (8.15.2's table).
# THIS SCRIPT REFUSES A RUNG IT CANNOT HOLD AT `W = 512` AT THE DERIVATION
# rather than running it and reading the answer, which is what cost section
# 8.14.8 its m = 6,000 rung; and it asserts `W`, `slabs`, `threads`, `path` and
# the achieved full-window widths on EVERY leg afterwards.
#
# THE ARENA TERM IS MEASURED, NOT CARRIED OVER (8.14.9): `conjugate::` and
# `additive::` scratch sit behind `enabled()` predicates that need not answer
# the same way on another kernel class, and the additive constant measured 76-207
# KB on NEON against the x86 form's 2,304,000 B - eleven to thirty times
# smaller. `-Phase probe` backs it out of `budget - S_first * block_size` at
# several `m` and prints the per-row slope in all three regimes; the ladder then
# takes `ARENA_C` from plan.txt.
#
# PLAN-FILE DRIVEN, because wlaunch.ps1 passes no arguments (the ssh session's
# job object kills a Start-Process round; see that file's header). plan.txt sits
# beside this script in the ROUND DIRECTORY, one `KEY=value` per line:
#
#   PHASE=fixture|probe|ladder|ctl      FIXROOT=<rig>\ntfwfix
#   SLICE=524288  NBLOCKS=3270  MEMBERS=10  RECOVERY=29000
#   THREADS=8  MARG=30000  SSTAR=2096  SEED=2001
#   RUNGS=1000,2500,4096,4369,...       REPS=2  REP0=0
#   ARENA_C=2304000                     OUT=legs.jsonl  TAG=
#   ID=<claim id>  COORD=COORDINATION-intel-i5-10600kf.txt
#   CTL=bsub|split|retain
#
# KEEP THIS FILE PURE ASCII. PowerShell 5.1 reads a BOM-less script as ANSI, so
# a literal micro sign in a regex silently matches nothing - the unit parser
# below takes any unit that is not ns/ms/s as micro, which is nttwork-i5.ps1's
# rule and is here for the same reason.
#
# LAUNCH (detached; Start-Process dies with the ssh session):
#   powershell -File <rig>\wlaunch.ps1 -Script <rig>\ntfw\nttfw-i5.ps1 -Tag ntfw -Root <rig>\ntfw
$ErrorActionPreference = 'Stop'
$Rd = Split-Path -Parent $PSCommandPath
$Root = if ($Rd) { Split-Path -Parent $Rd } else { '<rig>' }
. (Join-Path $Rd 'plib.ps1')

$plan = @{}
foreach ($l in (Get-Content (Join-Path $Rd 'plan.txt'))) {
  if (-not $l.Trim() -or $l.Trim().StartsWith('#')) { continue }
  $i = $l.IndexOf('=')
  if ($i -lt 1) { continue }
  $plan[$l.Substring(0, $i).Trim()] = $l.Substring($i + 1).Trim()
}
function P([string]$k, $def) { if ($plan.ContainsKey($k) -and $plan[$k] -ne '') { return $plan[$k] } else { return $def } }

$PHASE    = [string](P 'PHASE' 'ladder')
$FIXROOT  = [string](P 'FIXROOT' (Join-Path $env:USERPROFILE 'ntfwfix'))
$SLICE    = [int](P 'SLICE' 524288)
$NBLOCKS  = [int](P 'NBLOCKS' 3270)
$NMEM     = [int](P 'MEMBERS' 10)
$RECOVERY = [int](P 'RECOVERY' 29000)
$THREADS  = [int](P 'THREADS' 8)
# The CREATE is not a timed leg, so it gets the whole box; the LADDER's own
# thread count is held at 8 for comparability with sections 8.12, 8.14 and 8.15.
$CTHREADS = [int](P 'CTHREADS' $THREADS)
$MARG     = [string](P 'MARG' '30000')
$SSTAR    = [int](P 'SSTAR' 2096)
$SEED     = [int](P 'SEED' 2001)
$REPS     = [int](P 'REPS' 1)
$REP0     = [int](P 'REP0' 0)
$ARENA_C  = [long](P 'ARENA_C' 2304000)
$RTAG     = [string](P 'TAG' '')
$OUT      = Join-Path $Rd ([string](P 'OUT' 'legs.jsonl'))
$Id       = [string](P 'ID' 'ntt-depth1-tile-second-class-17sep')
$Coord    = Join-Path $Root ([string](P 'COORD' 'COORDINATION-intel-i5-10600kf.txt'))
$PRIST    = Join-Path $FIXROOT 'pristine'
$WORK     = Join-Path $FIXROOT 'work'
$LEGDIR   = Join-Path $Rd 'legs'
$BIN      = Join-Path $Rd 'parfast.exe'
$BIN_AA   = Join-Path $Rd 'parfast_aa.exe'

function Stamp { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Coord([string]$verb, [string]$text) { Add-Content $Coord ("$verb " + (Stamp) + " $Id $text") }
$RLOG = Join-Path $Rd ('round-' + $PHASE + '.log')
Set-PlibLog $RLOG
function Say([string]$s) {
  $line = (Stamp) + ' ' + $s
  Write-Host $line
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { Add-Content -LiteralPath $RLOG -Value $line -ErrorAction Stop } catch { }
  $ErrorActionPreference = $prev
}

# Duration Debug ({:.2?}) prints ns / us (micro) / ms / s. Any unit that is not
# one of the three named ones is micro - see the ASCII note in the header.
function AsSec([string]$v, [string]$u) {
  $x = [double]::Parse($v, [Globalization.CultureInfo]::InvariantCulture)
  switch ($u) { 'ns' { return $x / 1e9 } 'ms' { return $x / 1e3 } 's' { return $x } default { return $x / 1e6 } }
}

# The SHIPPED arena arithmetic, `FlatPlan::scratch_bytes(needed, 512)` times the
# worker count. ARENA_C is the class-dependent additive half and is MEASURED by
# -Phase probe, never assumed (8.14.9).
function Arenas([int]$m) {
  $rows = 4369 + 5 * [math]::Min($m, 4369) + 3 * [math]::Min($m, 21845) + $m
  return [long]$THREADS * ([long]$rows * 1024 + $ARENA_C)
}
# The budget that gives every FULL window exactly SSTAR sources.
function BudgetFor([int]$m) { return [long]$SSTAR * [long]$SLICE + (Arenas $m) }
# `ntt_admit_within` holds W=512 only while S* * block >= arenas.
function HoldsW512([int]$m) { return ([long]$SSTAR * [long]$SLICE) -ge (Arenas $m) }

function Parse-Leg([string]$errpath) {
  $err = [IO.File]::ReadAllText($errpath)
  $pts = @()
  foreach ($mm in [regex]::Matches($err, 'ntt syndromes \(m=(\d+), needed=(\d+), n=(\d+), W=(\d+), threads=(\d+)\): ([0-9.]+)([^\s)]+)')) {
    $pts += New-Object psobject -Property @{
      n = [int]$mm.Groups[3].Value; needed = [int]$mm.Groups[2].Value
      W = [int]$mm.Groups[4].Value; threads = [int]$mm.Groups[5].Value
      t = [math]::Round((AsSec $mm.Groups[6].Value $mm.Groups[7].Value), 4)
    }
  }
  $slabs = 1; $slabw = $SLICE
  $sm = [regex]::Match($err, 'in (\d+) slab\(s\) of (\d+) B')
  if ($sm.Success) { $slabs = [int]$sm.Groups[1].Value; $slabw = [int]$sm.Groups[2].Value }
  function Term([string]$pat) {
    $t = [regex]::Match($err, $pat + ': \+?([0-9.]+)([^\s)]+)')
    if ($t.Success) { return [math]::Round((AsSec $t.Groups[1].Value $t.Groups[2].Value), 4) } else { return $null }
  }
  function Total([string]$pat) {
    $s = 0.0; $any = $false
    foreach ($t in [regex]::Matches($err, $pat + ': \+?([0-9.]+)([^\s)]+)')) { $s += (AsSec $t.Groups[1].Value $t.Groups[2].Value); $any = $true }
    if ($any) { return [math]::Round($s, 4) } else { return $null }
  }
  $syn = 0.0; foreach ($p in $pts) { $syn += $p.t }
  New-Object psobject -Property @{
    path = $(if ($pts.Count) { 'ntt' } else { 'fold' })
    slabs = $slabs; slab_width = $slabw
    win_points = $pts
    win_n = @($pts | ForEach-Object { $_.n })
    win_sources = ( @($pts | ForEach-Object { $_.n }) | Measure-Object -Sum ).Sum
    syn_total = [math]::Round($syn, 4)
    ntt_w = @($pts | ForEach-Object { $_.W } | Sort-Object -Unique)
    ntt_threads = @($pts | ForEach-Object { $_.threads } | Sort-Object -Unique)
    back_sub = (Total 'back-substitution \([^)]*\)')
    patch = (Term '\bpatch')
    verify_targets = (Term 'verify targets \+ volume scan')
    final_verify = (Term 'final verify')
    load_recovery = (Term 'load recovery')
    feed_fold_solve = (Term 'feed\+fold\+solve')
  }
}

$members = @(0..($NMEM - 1) | ForEach-Object { 'm{0:d2}.bin' -f $_ })

function Load-Gold {
  $g = @{}
  foreach ($l in (Get-Content (Join-Path $FIXROOT 'gold.sha'))) {
    if (-not $l.Trim()) { continue }
    $p = $l -split '\s+', 2
    $g[$p[1].Trim()] = $p[0].Trim()
  }
  return $g
}

# ---------------------------------------------------------------- fixture
if ($PHASE -eq 'fixture') {
  Take-RigLock $PSCommandPath
  try {
    Say ("FIXTURE root=$FIXROOT slice=$SLICE members=$NMEM blocks=$NBLOCKS recovery=$RECOVERY")
    New-Item -ItemType Directory -Force -Path $PRIST, $WORK, $LEGDIR | Out-Null
    $bytes = [long]$NBLOCKS * [long]$SLICE
    $i = 0
    foreach ($nm in $members) {
      $p = Join-Path $PRIST $nm
      if ((Test-Path $p) -and (Get-Item $p).Length -eq $bytes) { Say "KEEP  $nm"; $i++; continue }
      $rng = New-Object Random($SEED + 7919 * $i)
      $buf = New-Object byte[] (8MB)
      $fs = [IO.File]::Open($p, 'Create', 'Write', 'None')
      $left = $bytes
      while ($left -gt 0) {
        $rng.NextBytes($buf)
        $n = [int][math]::Min([long]$buf.Length, $left)
        $fs.Write($buf, 0, $n); $left -= $n
      }
      $fs.Close()
      # ASSERT the size. The unix half of this family built its fixture twice
      # because `dd bs=1M count=N` from a pipe counts a SHORT READ as a whole
      # block; there is no pipe here, but the assertion is the cheap half of
      # that lesson and it stays.
      $got = (Get-Item $p).Length
      if ($got -ne $bytes) { throw "member $nm is $got B, wanted $bytes" }
      Say ("MADE  $nm $got B"); $i++
    }
    foreach ($nm in $members) { Copy-Item (Join-Path $PRIST $nm) (Join-Path $WORK $nm) -Force }
    # The par2 set is created INSIDE work/, so no `set.par2*` glob can miss a
    # `set.volNNN+NN.par2` (8.15.2). Nothing is copied, so nothing can be missed.
    Say 'CREATE par2'
    $r = @(Invoke-Leg $BIN ("c -s$SLICE -c$RECOVERY -t$CTHREADS -m$MARG set.par2 " + ($members -join ' ')) $WORK (Join-Path $LEGDIR 'create')) |
           Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    Say ("CREATE rc=$($r.rc) wall=$($r.wall) cpu=$($r.cpu) peak=$($r.peakmb)MB")
    if ($r.rc -ne 0) { throw 'create failed' }
    $par = @(Get-ChildItem $WORK -File | Where-Object { $_.Name -like 'set*.par2' } | ForEach-Object { $_.Name })
    Say ("PAR2  " + $par.Count + " file(s)")
    if ($par.Count -lt 2) { throw "only $($par.Count) par2 file(s) - the set did not build" }
    $gold = @()
    foreach ($nm in $members) { $gold += ((Get-Sha256Fast (Join-Path $PRIST $nm)) + ' ' + $nm) }
    Set-Content (Join-Path $FIXROOT 'gold.sha') $gold
    Set-Content (Join-Path $Rd 'keep.txt') (@($members) + @($par))
    Say 'FIXTURE DONE'
  } finally { Release-RigLock (Get-RigLockPath) }
  exit 0
}

# ------------------------------------------------------------- leg runner
$gold = Load-Gold
$keep = @(Get-Content (Join-Path $Rd 'keep.txt'))
$picksCache = @{}
function Picks-For([int]$m) {
  if (-not $picksCache.ContainsKey($m)) {
    $picksCache[$m] = Get-DamagePicks $WORK $members $SLICE $m $SEED
    Say ("PLAN  m=$m over " + $picksCache[$m].bymember.Keys.Count + ' member(s)')
  }
  return $picksCache[$m]
}

function Run-Leg {
  param([int]$rep, [string]$rung, [int]$m, [long]$budget, [string]$label, [string]$exe,
        [int]$order, [hashtable]$extraEnv, [string]$margpin)
  $tag = "$rung-$label-r$rep" + $(if ($RTAG) { "-$RTAG" } else { '' })
  $logbase = Join-Path $LEGDIR $tag
  $picks = Picks-For $m
  $null = Invoke-DamagePicks $WORK $members $SLICE $picks $SEED
  $env2 = @{ 'NZBFAST_REPAIR_TIMING' = '1' }
  if ($budget -gt 0) { $env2['NZBFAST_NTT_BUDGET'] = [string]$budget }
  if ($extraEnv) { foreach ($k in $extraEnv.Keys) { $env2[$k] = [string]$extraEnv[$k] } }
  $mm = if ($margpin) { $margpin } else { $MARG }
  $res = @(Invoke-Leg $exe ("r -t$THREADS -q -m$mm set.par2") $WORK $logbase $env2) |
           Where-Object { $_ -isnot [string] } | Select-Object -Last 1
  $g = Test-RestoredFast $WORK $members $gold
  $ok = ($res.rc -eq 0) -and (@($g.bad).Count -eq 0)
  Restore-Slices $WORK $PRIST $members $SLICE $picks
  $g2 = Test-RestoredFast $WORK $members $gold
  if (@($g2.bad).Count -ne 0) { throw ("restore failed at $tag : " + ($g2.bad -join ',')) }
  $strays = Remove-Strays $WORK $members $keep
  $d = Parse-Leg ($logbase + '.err')
  $rec = New-Object psobject -Property @{
    tag = $RTAG; rung = $rung; m = $m; rep = $rep; arm = $label; bin = $exe; order = $order
    slice = $SLICE; threads = $THREADS; marg = $mm; sstar = $SSTAR
    ntt_budget = $budget; env = ($env2.Keys -join ','); ok = $ok; bad = @($g.bad)
    rc = $res.rc; wall = $res.wall; cpu = $res.cpu; peak_mb = $res.peakmb
    foreign_cpu = $res.foreign; foreign_after = $res.foreignAfter
    strays_removed = $strays; utc = (Stamp)
    path = $d.path; slabs = $d.slabs; slab_width = $d.slab_width
    win_n = $d.win_n; win_points = $d.win_points; win_sources = $d.win_sources
    syn_total = $d.syn_total; ntt_w = $d.ntt_w; ntt_threads = $d.ntt_threads
    back_sub = $d.back_sub; patch = $d.patch; verify_targets = $d.verify_targets
    final_verify = $d.final_verify; load_recovery = $d.load_recovery
  }
  Add-Content $OUT ($rec | ConvertTo-Json -Depth 6 -Compress)
  Say ("LEG {0,-24} rc={1} ok={2} wall={3,8:N2} cpu={4,9:N2} peak={5,8:N1}MB slabs={6} path={7} W={8} thr={9} syn={10,7:N2} n={11} fgn={12:N1}/{13:N1}" -f `
      $tag, $res.rc, $ok, $res.wall, $res.cpu, $res.peakmb, $d.slabs, $d.path, ($d.ntt_w -join '/'), ($d.ntt_threads -join '/'), $d.syn_total, ($d.win_n -join '+'), $res.foreign, $res.foreignAfter)
  if (-not $ok) { throw "NOT byte-exact at $tag - that is damage, not data" }
  # Dispatch assertions. A rung that re-strikes its stripe is not on the ladder.
  if ($d.path -ne 'ntt') { throw "DISPATCH $tag took the fold" }
  if ($d.slabs -ne 1) { throw "DISPATCH $tag ran $($d.slabs) slabs" }
  if (@($d.ntt_w).Count -ne 1 -or $d.ntt_w[0] -ne 512) { throw "DISPATCH $tag ran W=$($d.ntt_w -join '/')" }
  if (@($d.ntt_threads).Count -ne 1 -or $d.ntt_threads[0] -ne $THREADS) { throw "DISPATCH $tag ran threads=$($d.ntt_threads -join '/')" }
  return $rec
}

# ------------------------------------------------------------------ probe
if ($PHASE -eq 'probe') {
  Take-RigLock $PSCommandPath
  try {
    Write-BoxFacts
    # The HARNESS's own provenance, and the round-start twin of the per-leg
    # `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath is THIS driver;
    # plib.ps1 adds itself. Without it a banked log cannot be traced to the
    # harness revision that wrote it (census
    # an internal note).
    Write-HarnessFacts @($PSCommandPath)
    Write-BinFacts $Rd @('parfast', 'parfast_aa')
    Wait-FixtureSettle
    # A budget that is DELIBERATELY not derived from the arena form, so the
    # first window's own `n` backs the arenas out rather than confirming them:
    #   arenas = budget - S_first * block_size
    $rungs = @([string](P 'RUNGS' '1000,6000,15000,26500')) -split ',' | ForEach-Object { [int]$_.Trim() }
    foreach ($m in $rungs) {
      $bud = [long]$SSTAR * [long]$SLICE + [long]1100000000   # over any plausible arena
      $r = Run-Leg 1 ("probe_m$m") $m $bud 'a' $BIN 0 $null ''
      $s1 = $r.win_points[0].n
      $ar = $bud - [long]$s1 * [long]$SLICE
      $rows = 4369 + 5 * [math]::Min($m, 4369) + 3 * [math]::Min($m, 21845) + $m
      Say ("ARENA m=$m S_first=$s1 arenas_total=$ar per_worker=" + [math]::Round($ar / $THREADS) + " rows=$rows implied_C=" + [math]::Round($ar / $THREADS - [long]$rows * 1024))
    }
  } finally { Release-RigLock (Get-RigLockPath) }
  exit 0
}

# ----------------------------------------------------------------- ladder
if ($PHASE -eq 'ladder') {
  $rungs = @(([string](P 'RUNGS' '')) -split ',' | Where-Object { $_.Trim() } | ForEach-Object { [int]$_.Trim() })
  if (-not $rungs.Count) { throw 'no RUNGS in plan.txt' }
  # REFUSE AT THE DERIVATION, never at the reading (8.14.8's lost rung).
  $present0 = $NBLOCKS * $NMEM
  foreach ($m in $rungs) {
    if (-not (HoldsW512 $m)) {
      throw ("RUNG-REFUSED m=$m - S*=$SSTAR at $SLICE B is " + ([long]$SSTAR * [long]$SLICE) + " B against arenas " + (Arenas $m) + " B: ntt_admit_within would narrow the stripe")
    }
    if (($present0 - $m) -lt $SSTAR) {
      throw ("RUNG-REFUSED m=$m - present " + ($present0 - $m) + " is under one full window of $SSTAR")
    }
  }
  Take-RigLock $PSCommandPath
  try {
    Write-BoxFacts
    # The HARNESS's own provenance, and the round-start twin of the per-leg
    # `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath is THIS driver;
    # plib.ps1 adds itself. Without it a banked log cannot be traced to the
    # harness revision that wrote it (census
    # an internal note).
    Write-HarnessFacts @($PSCommandPath)
    Write-BinFacts $Rd @('parfast', 'parfast_aa')
    Say ("SHAPE slice=$SLICE N=$present0 sstar=$SSTAR threads=$THREADS marg=$MARG arena_C=$ARENA_C reps=$REPS rep0=$REP0")
    foreach ($m in $rungs) {
      $bud = BudgetFor $m
      $margin = [math]::Round(100.0 * ([long]$SSTAR * [long]$SLICE) / (Arenas $m) - 100.0, 1)
      Say ("RUNG  m=$m present=" + ($present0 - $m) + " budget=$bud arenas=" + (Arenas $m) + " w512_margin=$margin pct  k_full=" + [math]::Floor(($present0 - $m) / $SSTAR))
    }
    Wait-FixtureSettle
    for ($rep = $REP0 + 1; $rep -le $REP0 + $REPS; $rep++) {
      $rot = ($rep - 1) % $rungs.Count
      $order = @($rungs[$rot..($rungs.Count - 1)]) + @($(if ($rot -gt 0) { $rungs[0..($rot - 1)] } else { @() }))
      if ($rep % 2 -eq 0) { [array]::Reverse($order) }
      for ($i = 0; $i -lt $order.Count; $i++) {
        $m = $order[$i]
        $arms = @(@('a', $BIN), @('a_aa', $BIN_AA))
        if ((($rep + $i) % 2) -eq 1) { [array]::Reverse($arms) }
        foreach ($arm in $arms) {
          $null = Run-Leg $rep ("m$m") $m (BudgetFor $m) $arm[0] $arm[1] $i $null ''
        }
      }
    }
    Say 'LADDER DONE'
  } finally { Release-RigLock (Get-RigLockPath) }
  exit 0
}

# --------------------------------------------------------------- controls
if ($PHASE -eq 'ctl') {
  # The BACK-SUBSTITUTION control (`bsub`): at a fixed m, moving the window
  # count from one to two must not move it - that is what licenses reading any
  # difference between rungs as tree charge.
  # The SPLIT control (`split`): a narrow tail window paying less than a full
  # one would make the charge fall SHORT of the middle line, which is the shape
  # of a second knee - so the confound points the same way as the result and
  # must be bounded at a HIGH rung rather than inherited from a low one.
  # The RETENTION control (`retain`): retain.rs's verify-pass cache falls back
  # to the same ntt_budget_within_published, so a pair's two rungs differ in
  # cache by construction; pin it above the whole present corpus on both arms.
  $ctl = [string](P 'CTL' 'bsub')
  $m = [int](P 'CTLM' 23000)
  $present = $NBLOCKS * $NMEM - $m
  Take-RigLock $PSCommandPath
  try {
    Write-BoxFacts
    # The HARNESS's own provenance, and the round-start twin of the per-leg
    # `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath is THIS driver;
    # plib.ps1 adds itself. Without it a banked log cannot be traced to the
    # harness revision that wrote it (census
    # an internal note).
    Write-HarnessFacts @($PSCommandPath)
    Wait-FixtureSettle
    $arena = Arenas $m
    for ($rep = $REP0 + 1; $rep -le $REP0 + $REPS; $rep++) {
      if ($ctl -eq 'bsub') {
        # k = 1 (whole present corpus in one window) against k = 2 (a 62/38
        # split), at one m. The transform moves; nothing else may.
        $k1 = [long]$present * [long]$SLICE + $arena + [long]$SLICE
        $s1 = [int][math]::Floor($present * 0.62 / 16) * 16
        $k2 = [long]$s1 * [long]$SLICE + $arena
        $null = Run-Leg $rep 'bsub_k1' $m $k1 'a' $BIN 0 $null ''
        $null = Run-Leg $rep 'bsub_k2' $m $k2 'a' $BIN 1 $null ''
      } elseif ($ctl -eq 'split') {
        foreach ($frac in @(0.62, 0.50, 0.34)) {
          $s1 = [int][math]::Floor($present * $frac / 16) * 16
          $b = [long]$s1 * [long]$SLICE + $arena
          $null = Run-Leg $rep ('split_' + [int]($frac * 100)) $m $b 'a' $BIN 0 $null ''
        }
      } elseif ($ctl -eq 'width') {
        # c_l ON THIS CLASS AT THIS BLOCK, measured rather than carried over -
        # the per-window charge is `c_l * S + T(m)` at a fixed m, so three
        # WIDTHS at one rung give the leaf term's slope directly. It is what
        # the ladder's residual width drift is corrected with, and it prices
        # the leaf term the family's other estimator has to cancel.
        # REFUSE AT THE DERIVATION, never at the reading. A width under
        # `arenas / block_size` is one `ntt_admit_within` step 3 narrows the
        # stripe for, and a narrowed stripe is a different transform: the
        # 1,200-source rung at m = 23,000 ran at W = 256 on 17 Sep 2026 and was
        # caught by the per-leg assertion, which is one step too late to be the
        # guard. The threshold is printed so the rung set can be read back.
        $floor = [math]::Ceiling($arena / $SLICE)
        Say ("WIDTH-ARM m=$m arenas=$arena needs S* >= $floor sources to hold W=512")
        foreach ($sw in @(1200, 2096, 3200)) {
          if ([long]$sw * [long]$SLICE -lt $arena) {
            Say ("WIDTH-REFUSED S*=$sw - under the $floor the narrowing rule needs at this m")
            continue
          }
          $b = [long]$sw * [long]$SLICE + $arena
          $null = Run-Leg $rep ('width_' + $sw) $m $b 'a' $BIN 0 $null ''
        }
      } elseif ($ctl -eq 'retain') {
        $s1 = [int][math]::Floor($present * 0.62 / 16) * 16
        $b = [long]$s1 * [long]$SLICE + $arena
        $pin = [long]($present + 64) * [long]$SLICE
        $null = Run-Leg $rep 'retain_pin' $m $b 'a' $BIN 0 @{ 'NZBFAST_REPAIR_RETAIN' = $pin } ''
        $null = Run-Leg $rep 'retain_free' $m $b 'a' $BIN 1 $null ''
      }
    }
    Say 'CTL DONE'
  } finally { Release-RigLock (Get-RigLockPath) }
  exit 0
}

throw "unknown PHASE '$PHASE'"
