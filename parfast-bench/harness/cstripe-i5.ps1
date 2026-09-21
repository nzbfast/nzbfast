# cstripe-i5.ps1 - the CREATE's NTT stripe width on the x86 nibble arm
# (lane parfast-create-stripe-width-1mib-x86-15sep): 512 against 1,024 words
# at 1 MiB and 4 MiB blocks, at the 10 GiB leaf fill the rule was set on
# (6 Sep 2026, cc48e8d2e) and at a fill near PAR2's 32,768-block ceiling that
# no create has ever been measured at.
#
# WHY A CREATE HARNESS RATHER THAN nttwork-i5.ps1. That script measures the
# REPAIR: it builds a set once and then times `parfast r` over damage it
# re-applies per leg. A create round has no damage and no repair - the timed
# tool IS the thing that produces the output, so the gate is not "the members
# came back" but "every arm wrote byte-identical recovery volumes", and the
# payload is written once per cell and never touched again. The arms, the rig
# lock, the load guard, the mirroring and the leg record are the same, and come
# from the same plib.ps1.
#
# KEEP THIS FILE PURE ASCII. PowerShell 5.1 reads a BOM-less script as ANSI, so
# a non-ASCII literal in a regex silently matches nothing.
#
# DRIVEN BY A PLAN FILE, plan.txt in the ROUND DIRECTORY (the directory this
# script sits in), because wlaunch.ps1 passes no arguments. One cell per line:
#
#     <label> <block_bytes> <n_slices> <rows> <members> <reps> <arm>[,<arm>...]
#
# an arm being `w<words>` (NZBFAST_NTT_W pinned to that width) or `auto`
# (nothing pinned - on this box at 1 MiB and up that IS W 1,024, so an
# auto/w1024 pair is this round's A/A floor), EITHER of which may carry an
# optional `t<threads>` suffix (`w1024t4`, `w512t4`, `autot4`) that pins
# NZBFAST_NTT_THREADS for that leg. Arms run in plan order on odd reps and
# reversed on even ones, on ONE corpus and ONE binary. A SOURCE TARBALL
# src.tgz sits beside the plan (git archive of the tree under test); the round
# builds parfast from it under the rig lock and refuses a binary older than
# the build start.
#
# **THE THREAD COUNT RIDES THE ARM AND NOT THE CELL, deliberately.** It was
# added to cstripe-mac.py 16 Sep 2026 by lane
# `neon-create-width-thread-count-16sep` to test the idle-cores hypothesis in
# an internal note, and ported here 17 Sep 2026 by
# `cstripe-thread-arm-windows-half-16sep`, whose whole subject is that the two
# halves of this family must take the same plan. The obvious design - an
# optional eighth column on the cell line - was rejected. A thread count on
# the CELL forces one round per thread count, which puts the A/A floor and the
# effect it licenses in different rounds over different corpora; and this
# family is judged on whether arms SEPARATE, so a floor measured somewhere
# else is not a floor. On the ARM, `w1024t4 w512t4 autot4` mirror within ONE
# cell over ONE corpus exactly as `w1024 w512 auto` do, the floor is measured
# at the SAME thread count as the effect, and `cstripesum.py` groups by `arm`
# already, so it reduces a thread round with no change at all. The cost is
# that a plan line carrying two thread counts would interleave them - which is
# a feature here, not a bug, and any cell may still carry exactly one.
#
# **AND THE FLOOR PAIR MUST BE AT THE SAME THREAD COUNT.** On THIS arm the
# floor is `auto` against `w1024` - the OPPOSITE of the aarch64 and GFNI
# rounds, where `default_stripe_words` returns 512 and the floor is against
# `w512` - so with thread pins that is `autot4` against `w1024t4`, never
# `autot4` against `w1024`. `cstripesum.py --ref w1024t4`.
#
# An arm with NO `t` suffix pins nothing, which is what every plan file
# written before this change means and still means:
# an internal note parses and runs
# exactly as it did.
#
# WHAT EVERY LEG ASSERTS, or the round aborts:
#   - rc 0 from the create;
#   - the create took the TRANSFORM (a `create ntt rows` or `create
#     stripe-first:` line), because a width A/B over a fold is nothing;
#   - the width the transform actually ran at equals the arm's pin, read off
#     that same line, and EVERY span in a multi-batch leg agrees - a pin the
#     binary ignored must never bank as a measurement of that pin;
#   - and the THREAD COUNT the transform actually ran at equals the arm's
#     thread pin, on exactly the same terms and for exactly the same reason.
#     That line has always carried `threads=`, and this driver has always
#     parsed it into $ranT and banked it as `ntt_threads` - but until 17 Sep
#     2026 NOTHING CHECKED IT, so a thread pin the binary ignored would have
#     banked silently as a measurement of that pin. The requested count is
#     banked beside the observed one as `ntt_threads_req` (null when the arm
#     pinned none) so a reader can see the two agree without re-deriving
#     either. The two halves of this family emit the SAME field name, which is
#     what lets one reducer read both;
#   - the recovery volumes are byte-identical to the cell's first leg, file
#     set and all.
# And every leg line carries the plan's LEAF FILL (`NZBFAST_NTT_FILL=1`), for
# the reason par2ntt's LeafFill docstring gives: a flat result from a kernel
# the fill gate refused looks exactly like a kernel that ran and bought
# nothing, and this family has paid for that confusion once already.
#
# NZBFAST_NTT_PAIRED_CAPW IS DELIBERATELY NOT SET. It pins the paired leaf's
# packed-source scratch, which since fa121666a follows the stripe width - so
# pinning it would hold one leaf kernel's shape still while the arm moves the
# other, and the A/B would no longer be the width's.
#
# LAUNCH (detached; a Start-Process dies with the ssh session):
#     powershell -File <rig>\wlaunch.ps1 -Script <rig>\cstr\cstripe-i5.ps1 -Tag cstr -Root <rig>\cstr
# $Root IS intel-i5-10600kf'S RIG ROOT AND ONLY intel-i5-10600kf HAS IT. This box is not the
# only x86 part this round shape runs on: intel-core-ultra-9-386h, the fleet's one
# GFNI-256 part, has NO D: DRIVE AT ALL, and `Join-Path '<rig>' ...` there
# does not return a bad path, it THROWS DriveNotFoundException - so $Coord came
# back $null and the round died in its first Coord call, before a single leg.
# Fall back to the user profile when <rig> is absent; intel-i5-10600kf is unchanged.
$Root = if (Test-Path '<rig>') { '<rig>' } else { $env:USERPROFILE }
$Cs = Split-Path -Parent $PSCommandPath
if (-not $Cs) { $Cs = Join-Path $Root 'cstr' }
$Fix = Join-Path $env:USERPROFILE ((Split-Path $Cs -Leaf) + 'fix')   # C: (TLC); D: is QLC
# AND THE COORDINATION FILE IS NAMED PER BOX, not by a convention you can
# compute. The i5's live one is COORDINATION-intel-i5-10600kf.txt under its rig root;
# the GFNI-256 laptop's is COORDINATION-coreultra9.txt under the user profile,
# which is neither the same directory nor the same spelling of the box. Both
# differ in case and in wording from $env:COMPUTERNAME, so deriving the name
# from the hostname gets one of them wrong, and a queue post to a name nobody
# reads is worse than no post at all. So the round directory NAMES its
# coordination file in coord.txt, the way it already names its claim in
# claim.txt; the i5 default stands when that file is absent.
$Coord = Join-Path $Root 'COORDINATION-intel-i5-10600kf.txt'
$coordFile = Join-Path $Cs 'coord.txt'
if (Test-Path $coordFile) { $Coord = (Get-Content $coordFile -Raw).Trim() }
$Id = 'parfast-create-stripe-width-1mib-x86-15sep'
$ClaimText = '(opus lane, <user>) - the CREATE NTT stripe width at 1 and 4 MiB on x86 nibble: 512 vs 1,024 at the 10 GiB fill and near the 32,768-block ceiling. Holds ~\.parfast-rig.lock. Will post DONE.'
$claimFile = Join-Path $Cs 'claim.txt'
if (Test-Path $claimFile) {
  $claimLines = @(Get-Content $claimFile)
  $Id = $claimLines[0].Trim()
  if ($claimLines.Count -gt 1) { $ClaimText = ($claimLines[1..($claimLines.Count - 1)] -join ' ').Trim() }
}
# THE ROUND'S OWN plib.ps1, beside this script, NOT <rig>\plib.ps1. This box
# holds two parfast rig roots with their own copies of that library and
# nothing keeps them equal (.claude/MACHINES.md, the intel-i5-10600kf entry); a round
# directory that carries the copy it was written against cannot be given a
# third one by whoever edits either root next. Falls back to the root's copy
# so a hand launch from <rig> still works.
$libLocal = Join-Path $Cs 'plib.ps1'
if (Test-Path $libLocal) { . $libLocal } else { $libLocal = Join-Path $Root 'plib.ps1'; . $libLocal }
$ErrorActionPreference = 'Stop'
# Every knob an arm may pin, cleared from the DRIVER's environment: a child
# inherits it, and an inherited pin would turn the `auto` arm into a pinned one.
foreach ($knob in @('NZBFAST_NTT', 'NZBFAST_NTT_W', 'NZBFAST_NTT_THREADS', 'NZBFAST_NTT_PAIRED_CAPW',
                    'NZBFAST_NTT_ADDITIVE', 'NZBFAST_NTT_ADDITIVE_MIN', 'NZBFAST_CREATE_STRIPE_FIRST',
                    'NZBFAST_CREATE_NTT_MIN_ROWS', 'NZBFAST_CREATE_NTT_MIN_PRESENT')) {
  Remove-Item "Env:$knob" -ErrorAction SilentlyContinue
}

function Stamp { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Coord([string]$verb, [string]$text) { Add-Content $Coord ("$verb " + (Stamp) + " $Id $text") }
function AsSec([string]$v, [string]$u) {
  $x = [double]::Parse($v, [Globalization.CultureInfo]::InvariantCulture)
  switch ($u) { 'ms' { return $x / 1e3 } 's' { return $x } 'ns' { return $x / 1e9 } default { return $x / 1e6 } }
}

# THE ARM GRAMMAR, IN ONE PLACE so the plan validator and the leg both read the
# same rule: a width (`w1024`) or `auto`, either optionally carrying a thread
# pin (`w1024t4`, `autot4`). cstripe-mac.py holds it as ARM_RE/parse_arm and
# this is that pair; a second copy of the rule is how a validator and a leg
# come to disagree about what a plan says. See the header for why the thread
# count is a property of the ARM rather than of the cell.
#
# `\A` AND `\z`, NOT `^` AND `$`, AND THAT IS THE ONE CHARACTER IN THIS RULE
# THAT IS NOT COSMETIC. .NET's `$` matches at the end of the string OR JUST
# BEFORE A TRAILING NEWLINE, so an `^...$` copy of this rule accepts
# "w1024t4\n" and would bank a leg under an arm name carrying a line
# terminator. cstripe-mac.py's half uses `ARM_RE.fullmatch`, which consumes the
# whole string and refuses that, and the two halves of this family must refuse
# the same strings or a plan is not portable between them. `\z` is the
# absolute end of input and restores the parity. Measured on pwsh 7.6.6: `$`
# accepts it, `\z` does not.
$script:ArmRe = '\A(auto|w(\d+))(?:t(\d+))?\z'

function Get-ArmPins([string]$arm, [string]$label) {
  # -> @{ w = <words> or $null; t = <threads> or $null }. Throws on anything
  # else. A bad arm is a PLAN-FAIL and not a warning: the arm string is what
  # names the leg file, the leg record and every reducer grouping, so a typo
  # that fell through to `auto` would bank a leg under a name that is not what
  # ran.
  $m = [regex]::Match($arm, $script:ArmRe)
  if (-not $m.Success) { throw "PLAN-FAIL bad arm '$arm' in cell $label - expected w<words>, auto, or either with a t<threads> suffix" }
  $pw = $null; if ($m.Groups[2].Success) { $pw = [int]$m.Groups[2].Value }
  $pt = $null; if ($m.Groups[3].Success) { $pt = [int]$m.Groups[3].Value }
  if ($null -ne $pt -and $pt -lt 1) { throw "PLAN-FAIL arm '$arm' in cell $label pins $pt threads" }
  return @{ w = $pw; t = $pt }
}

# NO COORDINATION-FILE MATCHER LIVES IN THIS FILE, AND THAT IS THE FINDING
# RATHER THAN THE ABSENCE OF ONE (18 Sep 2026, claim
# `riglock-matcher-copy-gate-18sep`). This driver was named in
# an internal note section 1 as one of
# two LIVE harness drivers "carrying their own keyword list", to be repointed
# at plib's `Get-OpenClaimants` / `Get-CoordFoldedState`. Re-derived on main:
# it is not. Its only `DONE` / `ABORTED` / `CLAIM` literals are the `$done`
# status variable and the `Coord` POSTS below, it already dot-sources plib,
# and its only read of `$coordFile` is of the POINTER file that names the
# coordination file - never of that file's contents. There was nothing to
# repoint, and tools/coord-matcher-gate.py reports it clean.
#
# WHAT IT DOES HAVE is the blindness that handoff's section 1 is about, one
# mechanism over: the ahead-list below is a list of PIDS read once from
# wait.txt, so a lane that posts a CLAIM after this wait starts is invisible
# to it, and `Take-RigLock` is called AFTER the loop exits, which is the gap
# both dated instances happened in. plib's `Get-OpenClaimants` (no ahead-list
# fixed at arm time) and `Take-RigLockWhenFree` (acquire FIRST, then ask
# every other question with the handle already open) are the fix.
#
# DELIBERATELY NOT APPLIED HERE, and the reason is the rule this whole family
# of incidents came from: this is a LIVE driver whose stand-down decides
# whether a round takes a contended box, the change would make it refuse to
# run where it now proceeds, and that path cannot be exercised from a Mac -
# plib's selftest covers the FUNCTIONS (224 cases) and nothing covers this
# call site. It wants a Windows box nobody is measuring on, which is the same
# follow-on that handoff already names for the library's own Windows arm.
# WAITING FOR A FREE BOX, when wait.txt sits beside the plan: line 1 a UTC
# deadline, every further line the pid of a process queued AHEAD of this round.
# Same rule and the same reasons as nttwork-i5.ps1's block: the lock alone is
# not "busy" enough, because a queued lane runs ~10-20 minutes of cargo BEFORE
# it takes the lock, so busy is the lock OR any parfast / cargo / rustc OR a
# listed pid still alive and older than this wait - and free must read free
# twice, a minute apart. Past the deadline: exit 5, no lock taken.
$waitFile = Join-Path $Cs 'wait.txt'
if (Test-Path $waitFile) {
  $waitLines = @(Get-Content $waitFile | Where-Object { $_.Trim() })
  $waitUntil = [datetime]::Parse($waitLines[0].Trim()).ToUniversalTime()
  $ahead = @()
  if ($waitLines.Count -gt 1) { $ahead = @($waitLines[1..($waitLines.Count - 1)] | ForEach-Object { [int]$_.Trim() }) }
  $waitStart = Get-Date
  # BUSY IS A HOLDER, NOT A FILE. This was `Test-Path $lockProbe` until 16 Sep
  # 2026, so an ORPHAN - a lock whose holder died without releasing - read as
  # 'lock' on every poll and parked this round here until its deadline, exit 5,
  # on a box that was free (an internal note).
  # plib's Test-RigLockHeld puts the question to the holder's own pid, and plib
  # is already dot-sourced above. THE OTHER TWO ARMS STAY: a round that never
  # took the lock is still load, which is what the parfast/cargo/rustc test
  # catches, and the queued-ahead pids are this round's own turn-taking.
  function Test-BoxBusy {
    if (Test-RigLockHeld) { return 'lock' }
    if (Get-Process parfast, cargo, rustc -ErrorAction SilentlyContinue) { return 'parfast/cargo/rustc running' }
    foreach ($aheadPid in $ahead) {
      $q = Get-Process -Id $aheadPid -ErrorAction SilentlyContinue
      if ($q -and $q.StartTime -lt $waitStart) { return "queued-ahead pid=$aheadPid alive" }
    }
    return ''
  }
  "WAIT until=$($waitLines[0].Trim()) ahead=$($ahead -join ',') ts=$(Stamp)"
  $lastWhy = ''
  while ($true) {
    $why = Test-BoxBusy
    if (-not $why) {
      Start-Sleep -Seconds 60
      $why = Test-BoxBusy
      if (-not $why) { break }
    }
    if ($why -ne $lastWhy) { "WAIT-BUSY $why ts=$(Stamp)"; $lastWhy = $why }
    if ((Get-Date).ToUniversalTime() -gt $waitUntil) { "WAIT-DEADLINE the box never came free ts=$(Stamp)"; exit 5 }
    Start-Sleep -Seconds 60
  }
  "WAIT-FREE ts=$(Stamp)"
}

Take-RigLock (Join-Path $Cs 'cstripe.lock')
$done = 'ABORTED'
try {
  Coord 'CLAIM' $ClaimText
  "BOX host=$env:COMPUTERNAME cpu=$((Get-CimInstance Win32_Processor).Name) cores=$env:NUMBER_OF_PROCESSORS"
  "RAM-GB $([math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1))"
  "ROUND dir=$Cs fixture=$Fix id=$Id"
  # Registers both files, so every LEG line's rig= re-reads what ran.
  Write-HarnessFacts @($PSCommandPath)

  # --- build ----------------------------------------------------------------
  $src = Join-Path $Cs 'src'
  $exe = Join-Path $src 'target\release\parfast.exe'
  $tgz = Join-Path $Cs 'src.tgz'
  $stampFile = Join-Path $Cs 'src.tgz.built'
  $tgzHash = (Get-FileHash $tgz -Algorithm SHA256).Hash
  $prev = if (Test-Path $stampFile) { (Get-Content $stampFile -Raw).Trim() } else { '' }
  if ($prev -ne $tgzHash -or -not (Test-Path $exe)) {
    if (Test-Path $src) {
      Get-ChildItem $src -Exclude target | Remove-Item -Recurse -Force
    } else { New-Item -ItemType Directory -Force $src | Out-Null }
    Push-Location $src; & tar -xzf $tgz; Pop-Location
    $buildStart = Get-Date
    Push-Location $src
    $env:CARGO_INCREMENTAL = '0'
    # crates/parfast/build.rs stamps `-VV` from NZBFAST_BUILD_COMMIT when the
    # tree is an export with no .git; without it the binary reads `built from
    # unknown`. Write the commit beside the tarball:
    #     git rev-parse origin/main > src.commit
    $commitFile = Join-Path $Cs 'src.commit'
    if (Test-Path $commitFile) { $env:NZBFAST_BUILD_COMMIT = (Get-Content $commitFile -Raw).Trim() }
    $ErrorActionPreference = 'Continue'
    & cargo build --release -p parfast --locked 2>&1 | Select-Object -Last 4 | ForEach-Object { "BUILD $_" }
    $ErrorActionPreference = 'Stop'
    Pop-Location
    if (-not (Test-Path $exe)) { throw "parfast.exe was not produced" }
    if ((Get-Item $exe).LastWriteTime -lt $buildStart) { throw "parfast.exe predates the build start - a stale build is a failed round" }
    Set-Content $stampFile $tgzHash
    "BUILD-SECS $([math]::Round(((Get-Date) - $buildStart).TotalSeconds))"
  }
  $ver = (& $exe -VV 2>&1 | Select-Object -First 2) -join ' / '
  "BIN parfast.exe sha256=$((Get-FileHash $exe -Algorithm SHA256).Hash.Substring(0,16)) $ver"

  # `create ntt rows 0+1024 (n=10240, mapped, 0 tail(s) padded, W=1024, 2
  # stripe(s), threads=12, probe ok): 1.23s` - the batched mapped arm; and
  # `create stripe-first: 3277 rows in 8 chunk(s) of 64 stripes (n=32768,
  # bands, W=512, threads=12, probe ok): 1.23s` - the one-pass arm. Either is
  # the transform; both carry the width this leg actually ran at.
  # `.*?` and not `[^)]*?` between the two anchors on each: both lines carry
  # parentheses of their own inside that span - `0 tail(s) padded` on the
  # batched arm, `bands of N B over copies, read 1.2s, probe 3ms, 6 reader(s)`
  # on the band arm - so a class that stops at the first `)` matches neither.
  $nttRe = 'create ntt rows (\d+)\+(\d+) \(n=(\d+),.*?W=(\d+), (\d+) stripe\(s\), threads=(\d+), probe ok\): ([0-9.]+)([^0-9.\s]+)'
  $sfRe = 'create stripe-first: (\d+) rows in (\d+) chunk\(s\) of (\d+) stripes \(n=(\d+), (.*?), W=(\d+), threads=(\d+), probe ok\): ([0-9.]+)([^0-9.\s]+)'
  $fillRe = '\[ntt-fill\] needed (\d+) leaves (\d+) sources (\d+) fill min (\d+) median (\d+) max (\d+) kernels dense (\d+) paired (\d+) additive (\d+) gate (\S+)'

  New-Item -ItemType Directory -Force $Fix | Out-Null
  foreach ($planLine in (Get-Content (Join-Path $Cs 'plan.txt'))) {
    if ($planLine -match '^\s*(#|$)') { continue }
    $f = $planLine.Trim() -split '\s+'
    if ($f.Count -lt 7) { throw "PLAN-FAIL short line '$planLine'" }
    $label = $f[0]; $B = [int]$f[1]; $nslices = [int]$f[2]; $rows = [int]$f[3]
    $nmem = [int]$f[4]; $reps = [int]$f[5]
    $armnames = @($f[6] -split ',')
    foreach ($a in $armnames) { Get-ArmPins $a $label | Out-Null }
    # ${label}, not $label: a colon directly after a variable reference in a
    # double-quoted string is PowerShell's scope qualifier ($env:, $script:),
    # which is a PARSE error here and killed this round's first launch.
    if ($nslices % $nmem -ne 0) { throw "PLAN-FAIL ${label}: $nslices slices do not divide into $nmem members" }
    $armnamesRev = @($armnames); [array]::Reverse($armnamesRev)
    $out = Join-Path $Cs "legs-$label.jsonl"
    $legdir = Join-Path $Cs "legs-$label"
    New-Item -ItemType Directory -Force $legdir | Out-Null
    "ARMS label=$label " + (($armnames | ForEach-Object {
      $ap = Get-ArmPins $_ $label
      $pins = @()
      if ($ap.w) { $pins += "NZBFAST_NTT_W=$($ap.w)" }
      if ($ap.t) { $pins += "NZBFAST_NTT_THREADS=$($ap.t)" }
      $_ + '{' + ($pins -join ',') + '}'
    }) -join ' ')

    # --- corpus: the payload, written ONCE and never touched by a leg ------
    # One random buffer per member, rewritten with a counter in its first
    # eight bytes per block. The transform's cost does not depend on the
    # bytes (GF arithmetic is data independent) and this box writes at about
    # 1 GB/s, so drawing 128 GiB from System.Random - which runs at a small
    # fraction of that - would cost more than the round's legs.
    $work = Join-Path $Fix "c-$label"
    if (Test-Path $work) { Remove-Item -Recurse -Force $work }
    New-Item -ItemType Directory -Force $work | Out-Null
    $members = @(1..$nmem | ForEach-Object { "m$_.bin" })
    $permem = $nslices / $nmem
    $t0 = Get-Date
    # [int64] on the multiply, then fold into Int32's range: at the 32,768
    # slice ceiling $nslices * 100003 + $B is 3,277,946,880, which PowerShell
    # widens to Int64 and Random's Int32 constructor then refuses. That threw
    # ROUND-ERROR at h1m on the 16 Sep 01:37Z launch, after the two control
    # cells had banked. The fold leaves every seed below 2^31-1 unchanged, so
    # smk, c1m and c4m keep the exact corpora they were measured on.
    $rnd = [System.Random]::new([int](([int64]$nslices * 100003 + $B) % 2147483647))
    $buf = New-Object byte[] $B
    $rnd.NextBytes($buf)
    $blk = 0
    foreach ($nm in $members) {
      $fs = New-Object IO.FileStream((Join-Path $work $nm), [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 1048576, [IO.FileOptions]::SequentialScan)
      for ($k = 0; $k -lt $permem; $k++) {
        [BitConverter]::GetBytes([int64]$blk).CopyTo($buf, 0)
        $fs.Write($buf, 0, $B)
        $blk++
      }
      $fs.Close()
    }
    $payGB = [math]::Round(($nslices * [int64]$B) / 1GB, 2)
    "CORPUS label=$label block=$B slices=$nslices rows=$rows members=$nmem payload_gb=$payGB write_s=$([math]::Round(((Get-Date)-$t0).TotalSeconds,1)) free_gb=$([math]::Round((Get-PSDrive C).Free/1GB,1))"
    $memlen = @{}
    foreach ($nm in $members) { $memlen[$nm] = (Get-Item (Join-Path $work $nm)).Length }

    $gold = $null
    $goldNames = @()
    for ($rep = 1; $rep -le $reps; $rep++) {
      $order = if ($rep % 2) { @($armnames) } else { @($armnamesRev) }
      foreach ($arm in $order) {
        # A leg starts from payload only: any volume a previous leg left is
        # an input the create would refuse or reuse.
        foreach ($x in Get-ChildItem $work -File) { if (-not $memlen.ContainsKey($x.Name)) { Remove-Item -Force $x.FullName } }
        $envx = @{ NZBFAST_REPAIR_TIMING = '1'; NZBFAST_NTT_FILL = '1'; NZBFAST_NO_ENRICH = '1' }
        # The pins go into the CHILD's environment only. NZBFAST_NTT_THREADS is
        # cleared from THIS process's environment at the top of the file and
        # must stay on that list: an inherited pin would turn the `auto` arm
        # into a pinned one, which is exactly what a floor must not be.
        $ap = Get-ArmPins $arm $label
        $pinW = $ap.w; $pinT = $ap.t
        if ($pinW) { $envx['NZBFAST_NTT_W'] = "$pinW" }
        if ($pinT) { $envx['NZBFAST_NTT_THREADS'] = "$pinT" }
        $tag = "$label-r$rep-$arm"
        $lb = Join-Path $legdir $tag
        $l0 = (Get-CimInstance Win32_Processor).LoadPercentage
        $r = Invoke-Leg $exe ("c -q -q -s$B -c$rows set.par2 " + ($members -join ' ')) $work $lb $envx
        $l1 = (Get-CimInstance Win32_Processor).LoadPercentage
        if ($r.rc -ne 0) { throw "GATE-FAIL $tag create rc=$($r.rc) - see $lb.err" }
        $e = [IO.File]::ReadAllText("$lb.err")

        # --- the output gate --------------------------------------------
        $vols = @(Get-ChildItem $work -File -Filter '*.par2' | Sort-Object Name | ForEach-Object { $_.Name })
        if ($vols.Count -eq 0) { throw "GATE-FAIL $tag wrote no par2 volumes" }
        $volbytes = 0
        foreach ($v in $vols) { $volbytes += (Get-Item (Join-Path $work $v)).Length }
        if ($null -eq $gold) {
          $gold = @{}
          foreach ($v in $vols) { $gold[$v] = Get-Sha256Fast (Join-Path $work $v) }
          $goldNames = $vols
          "GOLD label=$label volumes=$($vols.Count) bytes=$volbytes from=$tag"
        } else {
          if (($vols -join '|') -ne ($goldNames -join '|')) { throw "GATE-FAIL $tag volume SET differs from the cell's first leg" }
          $res = Test-RestoredFast $work $vols $gold
          if ($res.bad.Count -ne 0) { throw "GATE-FAIL $tag volumes differ: $($res.bad -join ',')" }
        }
        # The payload must be exactly what every other leg read.
        foreach ($nm in $members) {
          if ((Get-Item (Join-Path $work $nm)).Length -ne $memlen[$nm]) { throw "GATE-FAIL $tag payload $nm changed length" }
        }
        foreach ($v in $vols) { Remove-Item -Force (Join-Path $work $v) }

        # --- the path and the pin ---------------------------------------
        # ALL the matches, not the first: the batched arm prints one line per
        # BATCH, and a round that read only the first would bank a pin it had
        # checked on a fraction of the leg's transform work.
        $nttAll = @([regex]::Matches($e, $nttRe))
        $sfAll = @([regex]::Matches($e, $sfRe))
        if ($nttAll.Count -eq 0 -and $sfAll.Count -eq 0) { throw "PATH-FAIL $tag the create did not take the transform - a width A/B over the fold measures nothing" }
        $route = if ($sfAll.Count -gt 0) { 'stripe-first' } else { 'batched' }
        $wseen = @(); $tseen = @(); $nttS = 0.0; $corpus = 'mapped'
        foreach ($mm in $sfAll) {
          $wseen += [int]$mm.Groups[6].Value; $tseen += [int]$mm.Groups[7].Value
          $nttS += (AsSec $mm.Groups[8].Value $mm.Groups[9].Value)
          if ($mm.Groups[5].Value -like 'bands*') { $corpus = 'bands' } else { $corpus = $mm.Groups[5].Value }
        }
        foreach ($mm in $nttAll) {
          $wseen += [int]$mm.Groups[4].Value; $tseen += [int]$mm.Groups[6].Value
          $nttS += (AsSec $mm.Groups[7].Value $mm.Groups[8].Value)
        }
        $ranW = $wseen[0]; $ranT = $tseen[0]
        foreach ($wv in $wseen) { if ($wv -ne $ranW) { throw "PATH-FAIL $tag the transform ran two widths in one leg: $($wseen -join ',')" } }
        if ($pinW -and $ranW -ne $pinW) { throw "PIN-FAIL $tag NZBFAST_NTT_W=$pinW but the transform ran W=$ranW" }
        # THE THREAD PIN GETS THE WIDTH PIN'S TREATMENT, both halves of it. The
        # spans must agree with each other - a leg that ran two thread counts
        # is not a measurement of either - and the count that ran must be the
        # count the arm asked for. Without this the driver parsed `threads=`
        # and banked it and nothing ever compared it to the request, which is
        # precisely the shape the width gate exists to refuse. It is not inert:
        # fastpar.rs clamps the knob to the stripe count, so an arm asking for
        # more threads than the leg has stripes runs fewer and lands here.
        foreach ($tv in $tseen) { if ($tv -ne $ranT) { throw "PATH-FAIL $tag the transform ran two thread counts in one leg: $($tseen -join ',')" } }
        if ($pinT -and $ranT -ne $pinT) { throw "THREAD-PIN-FAIL $tag NZBFAST_NTT_THREADS=$pinT but the transform ran threads=$ranT - a pin the binary ignored must never bank as a measurement of that pin" }
        $fm = [regex]::Match($e, $fillRe)
        $fill = if ($fm.Success) { "min$($fm.Groups[4].Value)/med$($fm.Groups[5].Value)/max$($fm.Groups[6].Value)/d$($fm.Groups[7].Value)p$($fm.Groups[8].Value)a$($fm.Groups[9].Value)" } else { 'none' }
        $rig = Get-RigStamp
        $o = [ordered]@{
          label = $label; block = $B; slices = $nslices; rows = $rows; members = $nmem; rep = $rep; arm = $arm
          stripe_w = if ($pinW) { $pinW } else { 'default' }
          rig = $rig
          rc = $r.rc; route = $route; corpus = $corpus; wall = $r.wall; cpu = $r.cpu; peak_mb = $r.peakmb
          ntt_s = [math]::Round($nttS, 4); ntt_W = $ranW; ntt_threads = $ranT
          # The REQUESTED count beside the OBSERVED one, null when the arm
          # pinned none, so a reader sees the two agree without re-deriving the
          # arm. SAME FIELD NAME as cstripe-mac.py's, which is what makes one
          # reducer read both halves of the family.
          ntt_threads_req = $pinT
          ntt_spans = ($wseen.Count)
          vol_count = $vols.Count; vol_bytes = $volbytes
          fill_leaves = if ($fm.Success) { [int]$fm.Groups[2].Value } else { $null }
          fill_sources = if ($fm.Success) { [int]$fm.Groups[3].Value } else { $null }
          fill_min = if ($fm.Success) { [int]$fm.Groups[4].Value } else { $null }
          fill_median = if ($fm.Success) { [int]$fm.Groups[5].Value } else { $null }
          fill_max = if ($fm.Success) { [int]$fm.Groups[6].Value } else { $null }
          leaf_dense = if ($fm.Success) { [int]$fm.Groups[7].Value } else { $null }
          leaf_paired = if ($fm.Success) { [int]$fm.Groups[8].Value } else { $null }
          leaf_additive = if ($fm.Success) { [int]$fm.Groups[9].Value } else { $null }
          additive_gate = if ($fm.Success) { $fm.Groups[10].Value } else { $null }
          load_before = $l0; load_after = $l1; foreign_before = $r.foreign; foreign_after = $r.foreignAfter
        }
        Add-Content -Encoding ASCII $out ((New-Object psobject -Property $o) | ConvertTo-Json -Compress)
        "LEG $tag rc=$($r.rc) out=OK route=$route corpus=$corpus wall=$($r.wall) cpu=$($r.cpu) peak_mb=$($r.peakmb) ntt=$($o.ntt_s) W=$ranW T=$ranT/$(if ($pinT) { $pinT } else { '-' }) spans=$($wseen.Count) fill=$fill load=$l0/$l1 foreign=$($r.foreign)/$($r.foreignAfter) rig=$rig"
      }
      Coord 'CLAIM' "EXTENSION - still running: $label rep $rep of $reps"
    }
    Remove-Item -Recurse -Force $work
    "CELL-DONE $label ts=$(Stamp) free_gb=$([math]::Round((Get-PSDrive C).Free/1GB,1))"
  }
  $done = 'finished'
  "ALL DONE $(Stamp)"
} catch {
  "ROUND-ERROR $($_.Exception.Message)"
} finally {
  Coord 'DONE' "$done; rig lock released"
  Release-RigLock (Join-Path $Cs 'cstripe.lock')
}
