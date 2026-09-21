#!/usr/bin/env pwsh
#
# plib_selftest.ps1 - the selftest for plib.ps1's ROUND LOG SINK.
#
#     pwsh -NoProfile -File harness/plib_selftest.ps1
#
# Runs in CI on a macOS runner through `tools/rig-selftest-gate.py --run-plib`
# (job `plib-selftest` in .github/workflows/rig-selftest.yml), which is the
# real gate for this file: no Mac on this fleet runs the Windows drivers, so a
# parse error in plib.ps1 would otherwise reach a Windows box as "every round
# on this machine dies at dot-source time". It runs natively on Windows too and
# is worth a pass there after any edit to the sink.
#
# THIS BLOCK USED TO SAY "there is no pwsh on the dev box at all", and that has
# stopped being true - `/opt/homebrew/bin/pwsh` was there on 20 Sep 2026 and
# ran all 261 cases green. Re-tensed rather than deleted because the CONCLUSION
# it supported still holds and is the reason this file is gated in CI at all:
# a lane's local pass is not a fleet verdict either way. What changes is that
#   pwsh -NoProfile -File harness/plib_selftest.ps1
# is now a real local pre-push check on the dev Mac, where it used to be
# impossible - so an edit to this file no longer has to reach CI to be read.
# It is NOT a substitute for the Windows pass: on a macOS runner the console is
# already UTF-8, so the Invoke-Leg encoding arm at the foot of this file can
# only fail on a box whose codepage is not (the arm says so at the site).
#
# A SEPARATE FILE, NOT A `--selftest` SWITCH INSIDE plib.ps1, and the reason is
# specific rather than stylistic: plib.ps1 is DOT-SOURCED, and inside a
# dot-sourced script `$args` is the CALLER'S `$args`, so a switch parsed there
# would read whatever the driver was invoked with. A `param()` block cannot go
# there either - it has to be a file's first statement, which is
# `$ErrorActionPreference = 'Stop'`. Same arrangement as rig-lib-selftest.zsh
# beside rig-lib.sh, and rig_lock_selftest.py beside riglock_state.py.
#
# WHAT IT HOLDS. The sink was added 16 Sep 2026 because every status line in
# plib.ps1 was a bare PowerShell string - implicit `Write-Output`, so stdout
# and nothing else - while the round drivers that define their own `Log` bank a
# FILE. Read the ROUND LOG SINK block at the head of plib.ps1 for the incident.
# The three properties that block promises are the three this file pins, and
# each of them fails SILENTLY if it breaks:
#
#   1. with a sink set, a forced settle WAIT and a forced GAVE-UP both land in
#      the sink file (and so do the load guard's, the rig lock's and the
#      harness provenance lines);
#   2. with no sink set, NOTHING is written and stdout is unchanged - compared
#      transcript against transcript, not asserted;
#   3. an append that cannot succeed is swallowed, because a guard that kills
#      a round because it could not log is worse than the defect it reports.
#
# HERMETIC, AND IT NEVER TOUCHES A LIVE ROUND. `$env:USERPROFILE` is pointed at
# a fresh temp directory before plib is dot-sourced, so the rig lock arm
# contends for a lock file in that directory and not for the box's real
# `.parfast-rig.lock` - which matters on a native Windows run, where the real
# one may be held by a round in flight.
#
# AND SINCE 16 Sep 2026 IT ALSO HOLDS THE SAMPLER'S OWN ARITHMETIC, which is
# the one thing the stubs below cannot reach. `Get-ForeignCpu` is stubbed here
# in order to drive its callers, so the primitive had no test anywhere - and it
# was overstating a quiet box by 2-5x
# (an internal note). The arithmetic now lives
# in `Measure-ForeignDelta`, which takes two snapshots and a window and returns
# the percentage, so the last arm in this file feeds it SYNTHETIC snapshots and
# needs no Windows box, no Get-Process and no sleep. No stub arm was weakened or
# re-pointed to make room for it.
#
# THE STUBS ARE THE SELFTEST'S ONLY MECHANISM, on purpose: `$thresh` and
# `$capS` alone cannot drive both arms of Wait-FixtureSettle in seconds on a
# box that is busy for its own reasons, and a real `Get-ForeignCpu` reading is
# exactly the quantity this has to hold FIXED to compare two transcripts. So
# `Get-ForeignCpu` is fed a scripted sequence, `Get-Process` returns three
# fixed rows so the `top=[...]` field is deterministic, and `Start-Sleep`
# collapses plib's 10 s and 30 s waits to 50 ms so the guard's own clock still
# advances (the cap is measured on a real stopwatch, so a no-op sleep would
# spin the loop tens of thousands of times instead of ending it). Everything
# else - the guards' arithmetic, their thresholds, their line formats and the
# routing under test - is the real code.
param()
$ErrorActionPreference = 'Stop'

$script:cases = 0
$script:fails = 0
function Ok([string]$what)   { $script:cases++; "ok $what" }
function Bad([string]$what)  { $script:cases++; $script:fails++; "FAIL $what" }
function Check([bool]$cond, [string]$what) { if ($cond) { Ok $what } else { Bad $what } }

$script:tmp = Join-Path ([IO.Path]::GetTempPath()) ("plibself-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $script:tmp | Out-Null

# BEFORE the dot-source, and before anything asks for the rig lock path.
$script:oldprofile = $env:USERPROFILE
$script:oldpliblog = $env:PLIB_LOG
$env:USERPROFILE = $script:tmp
$env:PLIB_LOG = $null

try {
  . (Join-Path $PSScriptRoot 'plib.ps1')

  # --- the stubs ------------------------------------------------------------
  # A scripted CPU reading. The last value repeats, so a loop that samples
  # more times than the feed has entries keeps getting the same answer rather
  # than falling off the end.
  $script:feed = @(0.0)
  $script:feedat = 0
  function Set-Feed([double[]]$vals) { $script:feed = $vals; $script:feedat = 0 }
  function Get-ForeignCpu {
    if ($script:feed.Count -eq 0) { return -1.0 }
    if ($script:feedat -ge $script:feed.Count) { return [double]$script:feed[$script:feed.Count - 1] }
    $v = [double]$script:feed[$script:feedat]
    $script:feedat++
    return $v
  }

  # Three fixed rows, so `top=[...]` is the same string on every run and on
  # every platform. Two clear plib's `CPU -gt 1` filter and one does not, which
  # is also that filter under test.
  # AN OVERRIDE ON THE STUB, not a change to it: the three fixed rows above are
  # pinned by the `top=[stubidx(4242) stubav(4243)]` arm and must not move. The
  # census arms further down need a DIFFERENT process table - one with a
  # non-cargo tool in it, and one with nothing recognisable at all - so they
  # set $script:procrows for the length of one case and clear it again. Unset
  # is the old behaviour exactly, which is what leaves every existing arm alone.
  $script:procrows = $null
  function Get-Process {
    [CmdletBinding()] param()
    if ($null -ne $script:procrows) { return @($script:procrows) }
    @(
      [pscustomobject]@{ ProcessName = 'stubidx';  Id = 4242; CPU = 99.0 }
      [pscustomobject]@{ ProcessName = 'stubav';   Id = 4243; CPU = 50.0 }
      [pscustomobject]@{ ProcessName = 'stubtiny'; Id = 4244; CPU = 0.5  }
    )
  }

  # 50 ms rather than nothing: see the header. The fully-qualified name is what
  # reaches the real cmdlet from inside its own override.
  function Start-Sleep {
    [CmdletBinding()] param([int]$Seconds, [int]$Milliseconds)
    Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 50
  }

  # --- helpers --------------------------------------------------------------
  $script:n = 0
  function New-Sink {
    $script:n++
    Join-Path $script:tmp ("sink-$($script:n).log")
  }
  function Read-Sink([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    @(Get-Content -LiteralPath $path)
  }
  function Count-Match([string[]]$lines, [string]$pat) {
    @($lines | Where-Object { $_ -match $pat }).Count
  }
  # The two fields that legitimately differ between two runs of the same arm.
  # Everything else on a line is held fixed by the stubs, which is what makes
  # a transcript comparison a real check rather than a smoke test.
  function Normalise([string[]]$lines) {
    @($lines | ForEach-Object {
      ($_ -replace 'ts=\S+', 'ts=<T>') -replace 'waited_s=\d+', 'waited_s=<N>'
    })
  }

  "== sink set: a forced GAVE-UP reaches the file"
  # capS=0 rather than a small positive cap, and that is what makes this arm
  # and the no-sink arm below COMPARABLE: the settle loop's exit is on a real
  # stopwatch, so any positive cap gives a line count that depends on how many
  # 50 ms iterations the runner fits into it - which differs between two runs
  # of the same arm and would make the transcript comparison flaky. At 0 the
  # loop does not run, so the transcript is exactly the two verdict lines. The
  # WAIT line gets its own arm below, where nothing is compared.
  $sink = New-Sink
  Set-PlibLog $sink
  Set-Feed @(70.3, 29.7, 40.0)
  $out = @(Wait-FixtureSettle 'selftest-giveup' 25.0 0)
  $got = Read-Sink $sink
  Check ((Count-Match $got 'FIXTURE-SETTLE ok=0 GAVE-UP') -eq 1) 'the GAVE-UP verdict is in the sink'
  Check ((Count-Match $got 'FIXTURE-SETTLE-NOTE') -eq 1) 'the continues-anyway note is in the sink'
  Check ((Count-Match $got 'top=\[stubidx\(4242\) stubav\(4243\)\]') -eq 1) 'the GAVE-UP line names the busiest foreign processes'
  Check ((Count-Match $got 'stubtiny') -eq 0) 'a process under the CPU filter is not named'
  # THE SINK IS NOT A SECOND FORMAT. Whatever reached stdout reached the file,
  # in the same order, once each - which is the property a reader of the banked
  # log depends on and the one a reformatting helper would quietly break.
  Check (((Normalise $out) -join "`n") -eq ((Normalise $got) -join "`n")) 'the sink is byte-identical to stdout, in order'
  Check ($out.Count -eq 2) 'the capped arm emits exactly its two verdict lines'

  "== sink set: the WAIT lines of a settle that is still waiting reach the file"
  # A positive cap, so the loop runs: elapsed is ~0 on entry, so there is
  # always at least one iteration, and the first busy sample always satisfies
  # plib's `busy % every -eq 0`. How MANY lines follow is a clock question,
  # hence `-ge 1` and no comparison here.
  $sinkw = New-Sink
  Set-PlibLog $sinkw
  Set-Feed @(70.3, 29.7, 40.0)
  $null = @(Wait-FixtureSettle 'selftest-wait' 25.0 1)
  $gotw = Read-Sink $sinkw
  Check ((Count-Match $gotw 'FIXTURE-SETTLE-WAIT foreign_cpu=70.3 thresh=25') -eq 1) 'the first WAIT line is in the sink'
  Check ((Count-Match $gotw 'FIXTURE-SETTLE ok=0 GAVE-UP') -eq 1) 'and the verdict that followed it'

  "== sink set: a settle that WAITS and then succeeds"
  $sink2 = New-Sink
  Set-PlibLog $sink2
  Set-Feed @(70.3, 9.4, 9.4, 9.4)
  $out2 = @(Wait-FixtureSettle 'selftest-ok' 25.0 1200)
  $got2 = Read-Sink $sink2
  Check ((Count-Match $got2 'FIXTURE-SETTLE ok=1') -eq 1) 'the ok=1 verdict is in the sink'
  Check ((Count-Match $got2 'FIXTURE-SETTLE-WAIT foreign_cpu=70.3') -eq 1) 'the wait it did is in the sink'
  Check ((Count-Match $got2 'busy_samples=1') -eq 1) 'the ok=1 line still carries the busy sample count'
  Check (((Normalise $out2) -join "`n") -eq ((Normalise $got2) -join "`n")) 'the settled arm is byte-identical to stdout'

  "== sink set: the lost-counter arms still say so in the file"
  $sink3 = New-Sink
  Set-PlibLog $sink3
  Set-Feed @()
  $null = @(Wait-FixtureSettle 'selftest-nocounter' 25.0 1200)
  Check ((Count-Match (Read-Sink $sink3) 'FIXTURE-SETTLE skipped=no-counter') -eq 1) 'skipped=no-counter is in the sink'

  "== sink set: the load guard's wait line reaches the file"
  # Require-QuietBox's ceiling is max(100, cores*100*0.10), so it is 100 on a
  # macOS runner (NUMBER_OF_PROCESSORS is a Windows variable and reads as 0
  # there) and 160 on a 16-core Windows box. 5000 is busy and 9 is quiet on
  # anything either way, so the arm cannot depend on the runner's core count -
  # a 150 would have passed on the runner and read as QUIET on the box this
  # library actually ships to. The feed then goes quiet, so this never reaches
  # `exit 18`,
  # which would end the selftest process rather than fail a case.
  $sink4 = New-Sink
  Set-PlibLog $sink4
  Set-Feed @(5000.0, 9.0)
  $out4 = @(Require-QuietBox 'selftest-load')
  $got4 = Read-Sink $sink4
  Check ((Count-Match $got4 'BOX-BUSY-WAIT try=1 foreign_cpu=5000') -eq 1) 'BOX-BUSY-WAIT is in the sink'
  Check ((Count-Match $got4 'ABORT-LOAD') -eq 0) 'a box that went quiet did not abort'
  Check ($script:lastforeign -eq 9.0) 'the reading still comes back in $script:lastforeign, not as a return value'
  Check (((Normalise $out4) -join "`n") -eq ((Normalise $got4) -join "`n")) 'the load guard is byte-identical to stdout'

  "== sink set: the per-core arm's lines reach the file"
  # Require-QuietCore landed 16 Sep 2026 and never aborts, so its
  # BOX-ONE-CORE-BUSY line is the ONLY record that a leg ran on a box carrying
  # a saturated foreign core - which makes it the sharpest case of the defect
  # the sink exists for. Called directly rather than through Require-QuietBox:
  # that path samples twice before it gets here, and this arm is about what
  # this arm emits. It confirms by MINIMUM of three samples, so the feed has
  # to stay over the threshold for all three.
  $sinkc = New-Sink
  Set-PlibLog $sinkc
  Set-Feed @(40.0, 40.0, 40.0)
  $outc = @(Require-QuietCore 'selftest-onecore')
  $gotc = Read-Sink $sinkc
  Check ((Count-Match $gotc 'BOX-ONE-CORE-BUSY at=selftest-onecore foreign_1core=40') -eq 1) 'BOX-ONE-CORE-BUSY is in the sink'
  Check ((Count-Match $gotc 'BOX-ONE-CORE-NOTE') -eq 1) 'the leg-RUNS note is in the sink'
  Check ($script:lastforeign1core -eq 40.0) 'the per-core reading comes back in its own $script: variable'
  Check (((Normalise $outc) -join "`n") -eq ((Normalise $gotc) -join "`n")) 'the per-core arm is byte-identical to stdout'
  # And the quiet side emits nothing at all, which is what stops this arm
  # writing a line into every round on a clean box.
  $sinkq = New-Sink
  Set-PlibLog $sinkq
  Set-Feed @(9.0)
  $outq = @(Require-QuietCore 'selftest-onecore-quiet')
  Check ($outq.Count -eq 0) 'a quiet core emits nothing'
  Check (-not (Test-Path -LiteralPath $sinkq)) 'and writes no file'

  "== sink set: the rig lock and the harness provenance lines reach the file"
  # $env:USERPROFILE is the temp directory, so this contends for a lock file
  # there and never for the box's real one. See the header.
  $sink5 = New-Sink
  Set-PlibLog $sink5
  Try-TakeRigLock 'plibselftest' | Out-Null
  Check ($script:riglock_taken) 'the lock was taken in the temp profile'
  Release-RigLock 'plibselftest' | Out-Null
  Write-HarnessFacts @() | Out-Null
  $got5 = Read-Sink $sink5
  Check ((Count-Match $got5 'RIG-LOCK-TAKEN .*round=plibselftest') -eq 1) 'RIG-LOCK-TAKEN is in the sink'
  Check ((Count-Match $got5 'RIG-LOCK-RELEASED') -eq 1) 'RIG-LOCK-RELEASED is in the sink'
  Check ((Count-Match $got5 'HARNESS plib.ps1 sha256=') -eq 1) 'the HARNESS provenance line is in the sink'
  Check ((Count-Match $got5 'HARNESS-RIG plib.ps1:') -eq 1) 'the HARNESS-RIG token is in the sink'
  # `| Out-Null` at the three call sites above is dcladder.ps1's spelling, and
  # it suppresses STDOUT. The sink still has the lines, which is the point: a
  # driver that discards the output stream keeps the verdict.

  "== no sink: nothing is written, and stdout is unchanged"
  $unused = New-Sink
  Set-PlibLog ''
  $env:PLIB_LOG = $null
  Check ($null -eq (Get-PlibLog)) 'Get-PlibLog is null with neither route set'
  # A count taken before and after, rather than a list held by hand: this has
  # to refuse a file appearing ANYWHERE, not only at the path this arm guessed.
  $filesbefore = @(Get-ChildItem $script:tmp -File -Recurse).Count
  Set-Feed @(70.3, 29.7, 40.0)
  $bare = @(Wait-FixtureSettle 'selftest-giveup' 25.0 0)
  Check (-not (Test-Path -LiteralPath $unused)) 'no file was created at the un-set sink path'
  Check ((@(Get-ChildItem $script:tmp -File -Recurse).Count) -eq $filesbefore) 'no file appeared anywhere'
  # THE WHOLE POINT OF THE CHANGE, checked rather than asserted: the same arm
  # run with a sink and without it puts the SAME lines on stdout, in the same
  # order, with nothing added or dropped.
  Check (((Normalise $bare) -join "`n") -eq ((Normalise $out) -join "`n")) 'stdout with no sink matches stdout with a sink'

  "== the environment route, for a round nobody can edit a driver for"
  $sink6 = New-Sink
  $env:PLIB_LOG = $sink6
  Check ((Get-PlibLog) -eq $sink6) 'PLIB_LOG is the sink when no driver set one'
  Set-Feed @(9.4, 9.4, 9.4)
  $null = @(Wait-FixtureSettle 'selftest-env' 25.0 1200)
  Check ((Count-Match (Read-Sink $sink6) 'FIXTURE-SETTLE ok=1') -eq 1) 'the verdict reaches the PLIB_LOG file'
  $sink7 = New-Sink
  Set-PlibLog $sink7
  Check ((Get-PlibLog) -eq $sink7) 'Set-PlibLog wins over PLIB_LOG'
  Set-Feed @(9.4, 9.4, 9.4)
  $null = @(Wait-FixtureSettle 'selftest-both' 25.0 1200)
  Check ((Count-Match (Read-Sink $sink7) 'FIXTURE-SETTLE ok=1') -eq 1) 'the verdict reaches the Set-PlibLog file'
  Check ((Count-Match (Read-Sink $sink6) 'at=selftest-both') -eq 0) 'and not the overridden one'
  $env:PLIB_LOG = $null

  "== an append that cannot succeed must not kill the round"
  # A path under a directory that does not exist. $ErrorActionPreference is
  # 'Stop' throughout this library, so an unguarded Add-Content here would take
  # the round down at its own guard - the failure this arm exists to refuse.
  Set-PlibLog (Join-Path $script:tmp 'no-such-dir/deeper/round.log')
  Set-Feed @(70.3, 29.7, 40.0)
  $survived = $false
  $out8 = @()
  try { $out8 = @(Wait-FixtureSettle 'selftest-unwritable' 25.0 1); $survived = $true } catch { $survived = $false }
  Check $survived 'an unwritable sink is swallowed'
  Check ((Count-Match $out8 'FIXTURE-SETTLE ok=0 GAVE-UP') -eq 1) 'and stdout still carries the verdict'
  Set-PlibLog ''

  "== Measure-ForeignDelta: the sampler's own arithmetic"
  # THE ONE THING IN THIS LIBRARY THE STUBS ABOVE CANNOT REACH. Every arm so
  # far replaces `Get-ForeignCpu` with a scripted feed in order to drive its
  # CALLERS, which is what those arms are for and is why the primitive itself
  # had no test anywhere until 16 Sep 2026 - the day its arithmetic was found
  # to be overstating a quiet box by 2-5x
  # (an internal note). `Measure-ForeignDelta`
  # is the arithmetic split out of the sampler so it can be fed SYNTHETIC
  # snapshots: pure numbers, no Get-Process, no sleep, no Windows box, so this
  # runs on the macOS runner that gates this file.
  #
  # The stubs are untouched and no existing arm is re-pointed: this is a new
  # name the feed does not shadow.
  function Snap([hashtable]$rows) {
    # pid -> @{ Cpu; Start }, the shape Get-ForeignCpu's snapshot builds.
    $h = @{}
    foreach ($k in $rows.Keys) {
      $h[[int]$k] = [pscustomobject]@{ Cpu = [double]$rows[$k][0]; Start = $rows[$k][1] }
    }
    return ,$h
  }
  # Constructed rather than parsed from a string: a [datetime] cast of a string
  # goes through the CURRENT CULTURE, and this file is gated on a runner whose
  # culture nobody here chose.
  $t0   = New-Object DateTime 2026, 9, 16, 12, 0, 0
  $born = $t0.AddMilliseconds(300)   # inside the window
  $old  = $t0.AddHours(-9)           # long before it

  # A pid in BOTH snapshots is a plain delta, and the divisor is the window
  # that was actually measured rather than an assumed 1.000 s.
  $bef = Snap @{ 100 = @(10.0, $old) }
  $aft = Snap @{ 100 = @(10.5, $old) }
  Check ((Measure-ForeignDelta $bef $aft 1.0 $t0 12) -eq 50.0) 'a pid in both snapshots is a plain delta'
  Check ((Measure-ForeignDelta $bef $aft 1.4 $t0 12) -eq 35.7) 'the reading is divided by the measured window, not by 1.0'

  # THE DEFECT, PINNED. A pid absent from the before snapshot that was already
  # alive when the window opened contributes NOTHING. The old code charged its
  # whole lifetime to one second: 900 core-seconds would have read 90000.0.
  $befm = Snap @{ 100 = @(10.0, $old) }
  $aftm = Snap @{ 100 = @(10.5, $old); 777 = @(900.0, $old) }
  $gotm = Measure-ForeignDelta $befm $aftm 1.0 $t0 12
  Check ($gotm -eq 50.0) 'a pid missing from the before snapshot is not charged its lifetime'
  Check ($gotm -lt 900.0) 'and specifically not 90000 - the lifetime is not in the reading'

  # A process genuinely BORN inside the window IS charged in full, because all
  # of its CPU really was spent inside the window. This is the arm that keeps
  # the guard able to see a neighbouring round's freshly spawned parfast, which
  # a plain ignore-if-absent fix would have blinded it to.
  $aftb = Snap @{ 100 = @(10.5, $old); 778 = @(0.4, $born) }
  Check ((Measure-ForeignDelta $befm $aftb 1.0 $t0 12) -eq 90.0) 'a process born inside the window is charged in full'

  # An unreadable start time is treated as pre-existing - the conservative
  # direction, and the one a protected process lands in.
  $aftn = Snap @{ 100 = @(10.5, $old); 779 = @(500.0, $null) }
  Check ((Measure-ForeignDelta $befm $aftn 1.0 $t0 12) -eq 50.0) 'an unreadable start time is treated as pre-existing'

  # The sanity clamp: a birth cannot have burned more than window x cores.
  $aftc = Snap @{ 779 = @(9999.0, $born) }
  Check ((Measure-ForeignDelta (Snap @{}) $aftc 2.0 $t0 4) -eq 400.0) 'a birth is clamped at window x cores'

  # PID REUSE. Same pid, different start time, is a different process: its
  # predecessor's total is not a before reading for it.
  $befr = Snap @{ 200 = @(900.0, $old) }
  $aftr = Snap @{ 200 = @(0.3, $born) }
  Check ((Measure-ForeignDelta $befr $aftr 1.0 $t0 12) -eq 30.0) 'a reused pid is read as a birth, not as a negative delta'

  # A counter that went backwards is not subtracted from the total.
  $befd = Snap @{ 300 = @(5.0, $old); 301 = @(10.0, $old) }
  $aftd = Snap @{ 300 = @(5.2, $old); 301 = @(9.0,  $old) }
  Check ((Measure-ForeignDelta $befd $aftd 1.0 $t0 12) -eq 20.0) 'a backwards counter does not subtract from the total'

  # A window that did not advance is unmeasurable, and says so the way every
  # other no-reading path in this library does.
  Check ((Measure-ForeignDelta $bef $aft 0.0 $t0 12) -eq -1.0) 'a zero-length window reads as no-counter, not as a division'

  # An idle box is not a busy one. Ten pre-existing processes each ticking a
  # little, plus the svchost churn that produced the finding: four short-lived
  # children born in the window with a fifth of a second each.
  $idleb = @{}
  $idlea = @{}
  for ($i = 0; $i -lt 10; $i++) {
    # PARENTHESISED, and it has to be: PowerShell's comma binds TIGHTER than
    # `+`, so `@(100.0 + $i, $old)` is `100.0 + ($i, $old)` - a number plus an
    # array, which throws op_Addition rather than building a two-element row.
    $idleb[1000 + $i] = @((100.0 + $i), $old)
    $idlea[1000 + $i] = @((100.0 + $i + 0.01), $old)
  }
  for ($i = 0; $i -lt 4; $i++) { $idlea[2000 + $i] = @(0.02, $born) }
  $idle = Measure-ForeignDelta (Snap $idleb) (Snap $idlea) 1.4 $t0 12
  Check ($idle -lt 25.0) 'a quiet box with svchost churn reads under the per-core threshold'

  "== Resolve-OwnPidSet: the walk goes down AND up, and not sideways"
  # THE SECOND THING IN THIS LIBRARY THE STUBS CANNOT REACH, for the same
  # reason as the arm above: `Get-OwnPidTree` needs `Get-CimInstance`, which
  # does not exist on the runner that gates this file. The graph walk is split
  # out as `Resolve-OwnPidSet`, which takes a pid -> parent table, a pid ->
  # name table and a seed, so these cases are a SYNTHETIC process table - no
  # Get-CimInstance, no Get-Process, no process started, no sleep.
  #
  # WHAT THEY EXIST TO REFUSE. Adding the ancestors as SEEDS of the downward
  # closure is the one-line spelling of this fix and it excludes most of the
  # box: sshd, then services.exe, then everything services.exe ever started.
  # A guard that excludes the world reads ~0 forever and cannot fail, so most
  # of the cases below assert what is STILL FOREIGN rather than what is ours -
  # the sibling lane's session in particular, which is exactly what the
  # excludes-the-world implementation loses and a count of our own pids would
  # not notice.
  #
  # No existing arm is weakened or re-pointed: these are new names, and the
  # `Get-Process` stub above is not involved in any of them.
  function PidTable([hashtable]$rows) {
    # pid -> @(parent, name), split into the two tables the walk takes.
    $par = @{}
    $nam = @{}
    foreach ($k in $rows.Keys) {
      $par[[int]$k] = [int]$rows[$k][0]
      $nam[[int]$k] = [string]$rows[$k][1]
    }
    return , @($par, $nam)
  }
  # A box the shape of a real one under ssh: two lanes logged in through the
  # same listener, with services.exe carrying the usual service children.
  $boxrows = @{
    4   = @(0,   'System')
    500 = @(4,   'wininit.exe')
    600 = @(500, 'services.exe')
    700 = @(600, 'sshd.exe')          # the LISTENER, shared by both lanes
    710 = @(700, 'sshd-session.exe')  # our connection
    720 = @(710, 'cmd.exe')           # our login shell
    730 = @(720, 'powershell.exe')    # us
    740 = @(730, 'parfast.exe')       # our leg
    750 = @(740, 'conhost.exe')       # our leg's child
    711 = @(700, 'sshd-session.exe')  # ANOTHER lane's connection
    712 = @(711, 'powershell.exe')    # another lane's shell
    713 = @(712, 'parfast.exe')       # another lane's LEG - the whole point
    800 = @(600, 'svchost.exe')
    810 = @(600, 'MsMpEng.exe')
  }
  $bt = PidTable $boxrows
  $set = Resolve-OwnPidSet $bt[0] $bt[1] 730
  Check ($set.Contains(730) -and $set.Contains(740) -and $set.Contains(750)) 'our own pid and its descendants are still ours'
  Check ($set.Contains(720) -and $set.Contains(710)) 'our login shell and our own sshd-session are ours too'
  Check (-not $set.Contains(700)) 'the shared sshd LISTENER is NOT ours - the chain stops at it'
  Check (-not $set.Contains(600) -and -not $set.Contains(500) -and -not $set.Contains(4)) 'and nothing above it is'
  Check (-not $set.Contains(711) -and -not $set.Contains(712) -and -not $set.Contains(713)) 'ANOTHER LANE under the same listener stays foreign'
  Check (-not $set.Contains(800) -and -not $set.Contains(810)) 'svchost and the AV under services.exe stay foreign'
  Check ($set.Count -eq 5) 'five pids are ours out of fourteen - the ancestors are individual pids, not subtrees'

  # THE EXCLUDES-THE-WORLD CHECK, on a table wide enough for the difference to
  # be unmissable: 200 service children under the same services.exe our chain
  # passes through. The seed-the-ancestors implementation returns all of them.
  $widerows = @{ 4 = @(0, 'System'); 500 = @(4, 'wininit.exe'); 600 = @(500, 'services.exe')
                 700 = @(600, 'sshd.exe'); 710 = @(700, 'sshd-session.exe'); 730 = @(710, 'powershell.exe') }
  for ($i = 0; $i -lt 200; $i++) { $widerows[3000 + $i] = @(600, 'svchost.exe') }
  $wt = PidTable $widerows
  $wide = Resolve-OwnPidSet $wt[0] $wt[1] 730
  Check ($wide.Count -eq 2) 'a wide box excludes two pids, not the 206 under our ancestors'
  Check (-not $wide.Contains(3000) -and -not $wide.Contains(3199)) 'no service child of an ancestor is ours'

  # A scheduled round is a child of the Schedule service's svchost. The chain
  # stops there, because that svchost hosts services nothing to do with us.
  $schedrows = @{ 600 = @(4, 'services.exe'); 800 = @(600, 'svchost.exe'); 900 = @(800, 'powershell.exe') }
  $st = PidTable $schedrows
  $sched = Resolve-OwnPidSet $st[0] $st[1] 900
  Check ($sched.Count -eq 1 -and $sched.Contains(900)) 'a svchost-launched round excludes itself and stops'

  # A pid whose parent has been reaped: the parent id is stale and may already
  # belong to somebody else, so the walk stops rather than guessing.
  $gonerows = @{ 300 = @(299, 'powershell.exe'); 400 = @(300, 'parfast.exe') }
  $gt = PidTable $gonerows
  $gone = Resolve-OwnPidSet $gt[0] $gt[1] 300
  Check ($gone.Count -eq 2 -and $gone.Contains(400)) 'a reaped parent stops the upward walk and keeps the downward one'

  # Windows recycles pids, so a parent chain can close a loop. It must
  # terminate, and it must not walk the loop twice.
  $looprows = @{ 10 = @(20, 'a.exe'); 20 = @(10, 'b.exe') }
  $lt = PidTable $looprows
  $loop = Resolve-OwnPidSet $lt[0] $lt[1] 10
  Check ($loop.Count -eq 2) 'a parent-chain cycle terminates'

  # The hop cap, on a chain of plain processes that never reaches a root: eight
  # ancestors and no more, so an absurd table cannot walk the whole box.
  $deeprows = @{}
  for ($i = 0; $i -lt 20; $i++) { $deeprows[100 + $i] = @((100 + $i + 1), 'pwsh.exe') }
  $deeprows[120] = @(4, 'pwsh.exe')
  $dt = PidTable $deeprows
  $deep = Resolve-OwnPidSet $dt[0] $dt[1] 100
  Check ($deep.Count -eq 9) 'the upward walk stops after eight hops'
  Check (-not $deep.Contains(109)) 'and the ninth ancestor is still foreign'

  # A name the snapshot could not read is not a root: it costs at most one more
  # excluded pid and never stops a walk early in a way that hides anything.
  $namelessrows = @{ 600 = @(4, 'services.exe'); 700 = @(600, 'sshd.exe'); 710 = @(700, ''); 730 = @(710, 'powershell.exe') }
  $nt = PidTable $namelessrows
  $nameless = Resolve-OwnPidSet $nt[0] $nt[1] 730
  Check ($nameless.Count -eq 2 -and $nameless.Contains(710) -and -not $nameless.Contains(700)) 'an unreadable name is not a root, and the root above it still stops the walk'

  # An empty table is what a failed CIM enumeration hands the walk, and the
  # answer has to be the pre-ancestor behaviour: our own pid, alone.
  $empty = Resolve-OwnPidSet @{} @{} 730
  Check ($empty.Count -eq 1 -and $empty.Contains(730)) 'an empty process table returns our own pid alone'
  # And .Contains() resolves at all, which is the `,$mine` return idiom under
  # test: a bare return hands the caller an object[] and the guard silently
  # measures nothing for the rest of the round.
  Check ($set -is [System.Collections.Generic.HashSet[int]]) 'the walk returns a HashSet, not an enumerated array'

  "== Get-BoxHandover: the third token, and nothing else"
  # THE CASES ARE THE REAL TRAPS, taken line-for-line from
  # <rig>\COORDINATION-intel-i5-10600kf.txt on 16 Sep 2026 rather than invented:
  # three lanes hand-rolled `^(DONE|RELEASE).*<id>` that day and all three
  # fired on another lane's courteous ahead-list. Read the HANDOVER MATCHER
  # block in plib.ps1 for the incident. Every case below is a line the
  # substring predicate gets WRONG, plus the two it gets right, so a
  # regression to it fails here rather than on a shared box.
  #
  # NO STUB IS INVOLVED, and none is needed: the matcher takes a path and
  # reads it, so the fixture is a real file in the selftest's own temp
  # directory. It does not touch a coordination file anywhere on this box.
  $script:coord = Join-Path $script:tmp 'COORDINATION-selftest.txt'
  # A LIVE pid THAT IS NOT OURS, for the held-lock arms. It has to be live -
  # `Get-RigLockHolder` calls a pid that is gone an ORPHAN, which is the whole
  # point of that rule - and it has to be FOREIGN, because a lock held by our
  # own pid is deliberately not a busy box (see Get-BoxCensus). Our parent is
  # both, on every platform, and needs nothing started.
  # ASSIGN, THEN TRY - and the reason is no longer the one written here until
  # 18 Sep 2026. This comment said `$x = try {...} catch {...}` IS A PARSE
  # ERROR ON WINDOWS POWERSHELL 5.1, on the reasoning that try is a statement
  # there and not an expression. MEASURED THAT DAY on a windows-latest runner
  # under 5.1.26100.33296, the spelling both PARSES AND RUNS: the probe
  # printed `ok=[FROM-TRY] bad=[CAUGHT]`, so the catch arm binds too. The
  # belief was wrong and nothing in the repository could have said so, because
  # until that day no `.ps1` here had ever been EXECUTED under 5.1 anywhere,
  # by anything. `$b = switch (...) {...}` is valid 5.1 for the same reason
  # and four committed drivers already use it.
  #
  # THE HAZARD THE COMMENT NAMED IS STILL REAL, only the example was not one.
  # A 7-only GRAMMAR difference carries no 7-only OPERATOR token, so
  # ps1-parse-gate.py's dialect arm - a TOKEN test over `??`, `??=`, `&&`,
  # `||` and the ternary - structurally cannot see it, and pwsh 7 parses it
  # clean. The MEASURED member of that class is a `clean {}` block (7.3+):
  # 5.1 refuses it with `Missing closing '}' in statement block`, which is
  # fatal to the WHOLE FILE, so a driver carrying one dies at dot-source time
  # with "every round on this machine dies at launch" and pwsh 7 says nothing.
  # That is now caught: `tools/ps1-parse-gate.py --shell powershell.exe
  # --require-major 5` parses the whole roster under the real dialect on
  # nightly's `windows-one-process` job, and it was proved able to fail by a
  # positive control before it was believed.
  #
  # So this spelling stays assign-then-try, but as house style rather than as
  # a 5.1 requirement: it reads the same in both dialects and needs no reader
  # to know which one is running.
  $script:foreignpid = 0
  try { $script:foreignpid = [int](Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop).ParentProcessId }
  catch { $script:foreignpid = 0 }
  if (-not $script:foreignpid) {
    # Not reached on Windows, where the line above answers. `ps` is an ALIAS
    # for Get-Process there and would be handed flags it has no idea about,
    # which throws into the catch - correct, and never reached anyway.
    try { $script:foreignpid = [int]((& ps -o ppid= -p $PID) -join '').Trim() }
    catch { $script:foreignpid = 0 }
  }
  $coordlines = @(
    'CLAIM 2026-09-16T12:56:31Z digest-cache-small-core-intel-i5-10600kf-16sep gen=aaaa - taking the box for a ladder.'
    'CLAIM 2026-09-16T14:03:26Z nibble-crossover-quiet-box-confirm-16sep gen=bbbb - taking the box, ~5 h.'
    'DONE 2026-09-16T14:01:15Z parfast-cf-two-binary-control-16sep gen=cccc - THE BOX IS FREE. Handing over to nibble-crossover-quiet-box-confirm-16sep and then parfast-stripe-halving-nibble-number-16sep; my ahead-list is clear.'
    'NOTE 2026-09-16T14:40:52Z parfast-t6-1mib-nibble-smt gen=dddd - QUEUING FOURTH. MY AHEAD-LIST: (1) nibble-crossover-quiet-box-confirm-16sep, holding now.'
    'RELEASE 2026-09-16T15:35:00Z some-other-lane-16sep gen=eeee - standing down, the box is digest-cache-i5-width-ladder-16sep''s now.'
    'DONE 2026-09-16T18:41:21Z nibble-crossover-quiet-box-confirm-16sep gen=bbbb - THE BOX IS FREE AND THE RIG LOCK IS RELEASED. 72 legs, nothing of anyone else touched.'
  )
  Set-Content -LiteralPath $script:coord -Value $coordlines

  # THE ONE THAT COST NINE MINUTES OF A FREE BOX: a genuine DONE, with the id
  # as the third field, must fire.
  $genuine = Get-BoxHandover $script:coord 'nibble-crossover-quiet-box-confirm-16sep'
  Check ($null -ne $genuine) 'a genuine DONE with the id as the third token MATCHES'
  Check ($genuine -is [string]) 'and the verdict is the line itself, not an array of the line and a log line'
  Check ($genuine -like 'DONE 2026-09-16T18:41:21Z*') '...and it is the LANE OWN DONE, not the courteous one that merely named it'

  # THE COURTESY TRAP, which is the defect: parfast-cf-two-binary-control's
  # DONE names this lane in its prose and is not this lane handing over.
  # Deleting the ahead-list from that fixture line would make this case pass
  # against the broken predicate too, so it stays exactly as posted.
  Check ($null -eq (Get-BoxHandover $script:coord 'parfast-stripe-halving-nibble-number-16sep')) 'an id named inside ANOTHER lane DONE prose does NOT match'
  Check ($null -eq (Get-BoxHandover $script:coord 'digest-cache-i5-width-ladder-16sep')) 'an id named inside another lane RELEASE prose does NOT match'
  Check ($null -eq (Get-BoxHandover $script:coord 'parfast-t6-1mib-nibble-smt')) 'an id on a NOTE ahead-list does NOT match'

  # A CLAIM puts the id in field 2 as well, and it is the opposite of a
  # handover: the field test alone is not enough, field 0 has to be read too.
  Check ($null -eq (Get-BoxHandover $script:coord 'digest-cache-small-core-intel-i5-10600kf-16sep')) 'a CLAIM with the id in field 2 does NOT match'

  # PREFIX. `-eq` and not -like or .StartsWith(), because the -16sep suffix
  # habit makes one id a prefix of another routinely.
  Check ($null -eq (Get-BoxHandover $script:coord 'nibble-crossover-quiet-box-confirm')) 'an id that is a PREFIX of a finished lane id does NOT match'
  Check ($null -eq (Get-BoxHandover $script:coord 'some-other-lane')) 'nor a prefix of a RELEASE subject'

  # MULTI-LINE ENTRIES. A posted note can carry embedded newlines, so a
  # continuation line has an arbitrary first token - including, in the worst
  # case, the keyword itself with prose where the id belongs. Neither may
  # match and neither may throw.
  $multi = Join-Path $script:tmp 'COORDINATION-multiline.txt'
  Set-Content -LiteralPath $multi -Value @(
    'NOTE 2026-09-16T14:38:52Z parfast-nibble-windowed-ask-1mib-16sep gen=ffff - SECOND WAITER BUG, and this one is a trap for every lane that greps this file.'
    '  My cut-2 test required a line to start with DONE and to CONTAIN the id: that is'
    '  still wrong, because a courteous lane DONE line names the lanes behind it.'
    'DONE at 14:01:15Z parfast-cf-two-binary-control-16sep cleared three lanes off my ahead-list at once.'
    ''
    '   '
  )
  Check ($null -eq (Get-BoxHandover $multi 'parfast-nibble-windowed-ask-1mib-16sep')) 'a multi-line NOTE does not match on any of its lines'
  Check ($null -eq (Get-BoxHandover $multi 'parfast-cf-two-binary-control-16sep')) 'a continuation line starting with the KEYWORD does not match - its third token is prose'
  Check ($null -eq (Get-BoxHandover $multi 'nothing-here-16sep')) 'and blank and whitespace-only lines are skipped rather than thrown on'

  # RELEASE is a handover too, and so is a line with a fractional-second
  # timestamp or a tab between fields - both occur on the real file.
  $rel = Join-Path $script:tmp 'COORDINATION-release.txt'
  Set-Content -LiteralPath $rel -Value @(
    "RELEASE`t2026-09-16T21:00:23.4829174Z`tparfast-stripe-halving-nibble-i5-native-16sep - ABORTED, rig lock released."
  )
  $relhit = Get-BoxHandover $rel 'parfast-stripe-halving-nibble-i5-native-16sep'
  Check ($null -ne $relhit) 'a RELEASE with tab separators and a fractional-second timestamp MATCHES'

  # THE LAST ONE WINS. A lane that posts DONE and re-CLAIMs is holding the box
  # again - the strict reading the matcher header names as NOT its job - so the
  # caller needs the most recent line to compare, never the first.
  $again = Join-Path $script:tmp 'COORDINATION-again.txt'
  Set-Content -LiteralPath $again -Value @(
    'DONE 2026-09-16T10:00:00Z lane-a-16sep - first round finished.'
    'CLAIM 2026-09-16T11:00:00Z lane-a-16sep - second round, taking the box again.'
    'DONE 2026-09-16T12:00:00Z lane-a-16sep - second round finished.'
  )
  Check ((Get-BoxHandover $again 'lane-a-16sep') -like 'DONE 2026-09-16T12:00:00Z*') 'the LAST handover for an id is the verdict, not the first'

  # A FILE THAT IS NOT THERE READS AS NO HANDOVER, never as a throw and never
  # as a fire: a waiter that cannot read the file must keep waiting rather than
  # take a box whose state it cannot see.
  Check ($null -eq (Get-BoxHandover (Join-Path $script:tmp 'no-such-COORDINATION.txt') 'lane-a-16sep')) 'a missing coordination file is no handover, not an exception'
  # 19 Sep 2026: Get-BoxHandover goes through `Get-CoordMarkerEvent` too, so it
  # refuses prose and reads both field orders. One grammar, two readers.
  $bh_prose = Join-Path $script:tmp 'COORDINATION-bhprose.txt'
  Set-Content -LiteralPath $bh_prose -Value @(
    'CLAIM 2026-09-19T01:00:00Z prose-victim-19sep - measuring',
    'NOTE DONE prose-victim-19sep is what I will post when the ladder ends',
    'CLAIM 2026-09-19T01:00:00Z secondorder-lane-19sep - measuring',
    '2026-09-19T02:00:00Z DONE secondorder-lane-19sep - handed back')
  Check ($null -eq (Get-BoxHandover $bh_prose 'prose-victim-19sep')) 'a PROSE sentence naming a close keyword and a live id is not a handover - 19 Sep 2026, the same grammar the fold uses'
  Check ((Get-BoxHandover $bh_prose 'secondorder-lane-19sep') -like '2026-09-19T02:00:00Z DONE*') '...and the SECOND field order IS one now, which this function could not read before'
  Check ($null -eq (Get-BoxHandover $script:coord '')) 'an empty id never matches'
  Check ($null -eq (Get-BoxHandover '' 'lane-a-16sep')) 'an empty path never matches'

  # THE CLOSING VOCABULARY IS SIX WORDS, and the four beyond DONE/RELEASE are
  # the ones a matcher built from one box's file silently drops. A close it
  # does not recognise reads as NO CLOSE, which is the half of the defect that
  # left two waiters sitting through a free box for nine minutes - so each of
  # the six gets a case, and a marker that is NOT a close gets one too. The
  # list itself is held equal to `CLOSE_KW` in
  # `.claude/tools/bench-accounts-parse.py` by tools/rig-selftest-gate.py;
  # these cases pin the BEHAVIOUR, that gate pins the MEMBERSHIP.
  $vocab = Join-Path $script:tmp 'COORDINATION-vocab.txt'
  foreach ($kw in @('ABORTED', 'DONE', 'RELEASE', 'RELEASED', 'STAND-DOWN', 'WITHDRAWN')) {
    Set-Content -LiteralPath $vocab -Value @(
      "$kw 2026-09-16T12:00:00Z vocab-lane-16sep - the box is free."
    )
    Check ($null -ne (Get-BoxHandover $vocab 'vocab-lane-16sep')) "a $kw line is a handover"
  }
  foreach ($kw in @('CLAIM', 'QUEUED', 'NOTE', 'PROGRESS', 'LATE-CLAIM')) {
    Set-Content -LiteralPath $vocab -Value @(
      "$kw 2026-09-16T12:00:00Z vocab-lane-16sep - still mine, or never mine."
    )
    Check ($null -eq (Get-BoxHandover $vocab 'vocab-lane-16sep')) "a $kw line is NOT a handover"
  }
  # Lowercase, because the comparison is deliberately case-insensitive: a lane
  # that shouts less still means the box is free.
  Set-Content -LiteralPath $vocab -Value @('done 2026-09-16T12:00:00Z vocab-lane-16sep - free.')
  Check ($null -ne (Get-BoxHandover $vocab 'vocab-lane-16sep')) 'a lowercase close keyword still matches'
  # But a keyword that merely STARTS with one does not - the field test is
  # equality on token 0 as well as on token 2.
  Set-Content -LiteralPath $vocab -Value @('DONENESS 2026-09-16T12:00:00Z vocab-lane-16sep - not a marker.')
  Check ($null -eq (Get-BoxHandover $vocab 'vocab-lane-16sep')) 'a token that merely begins with a close keyword does NOT match'

  # ---------------------------------------------------------------------
  # THE BOX QUEUE: Enter-BoxQueue / Exit-BoxQueue
  # ---------------------------------------------------------------------
  # an internal note item 2, claim
  # harness-box-queue-reader-writer-18sep. The load-bearing check here is
  # not "does it run" - it is "does `.claude/tools/parfast-rigs-parse.py`,
  # the READER every other lane trusts, agree with what this WRITER just
  # posted". `Get-ReaderVerdict` below shells out to it over the real
  # file this pair wrote, so a divergence between the two (a marker this
  # pair spells differently, a field in the wrong column) fails here
  # rather than showing up as a phantom holder on a live rig box.
  # WHICH INTERPRETER, AND WHY IT IS PROBED RATHER THAN NAMED. `python3` is
  # the correct spelling on the macOS gate this file usually runs under, and
  # on Windows it is usually a LIE: Python for Windows ships no
  # `python3.exe`, so `python3` resolves to the WindowsApps App Execution
  # Alias stub, which answers `Access is denied` and exits non-zero. The only
  # test that separates the stub from an interpreter is RUNNING one -
  # `Get-Command python3` finds the stub and reports nothing wrong - so each
  # candidate is asked to print a number and is believed only if it does.
  # Before this, running this selftest natively on a Windows box cost the
  # lane the same ~20 minutes twice (intel-core-ultra-9-386h, 20 and 21 Sep 2026); the
  # remedy both times was a hand-placed `python3.exe` shim on PATH, which is
  # a change to somebody else's box for a defect that lives here.
  $script:pyexe = $null
  function Resolve-Python {
    if ($script:pyexe) { return $script:pyexe }
    foreach ($cand in @(
        @{ exe = 'python3'; pre = @() },
        @{ exe = 'python';  pre = @() },
        @{ exe = 'py';      pre = @('-3') })) {
      try {
        $out = & $cand.exe @($cand.pre + @('-c', 'print(42)')) 2>$null
        if ($LASTEXITCODE -eq 0 -and (($out -join '') -match '42')) {
          $script:pyexe = $cand
          return $script:pyexe
        }
      } catch { }
    }
    throw 'plib_selftest: no working python interpreter (tried python3, python, py -3)'
  }

  function Get-ReaderVerdict([string]$coordpath) {
    $parse = Join-Path $PSScriptRoot '../../.claude/tools/parfast-rigs-parse.py'
    $py = @'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("prp", sys.argv[1])
prp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prp)
lines = [l for l in open(sys.argv[2]).read().splitlines() if l.strip()]
extra = ["COORD\tpath=/h/C-x.txt\tstate=present\tlines=%d\troster=yes" % len(lines)]
extra += ["COORDLINE\tC-x.txt\t" + l for l in lines]
text = "NOW\t2026-09-16T15:00:00Z\nPLATFORM\tunix\n" + "\n".join(extra) + "\n"
rec = prp.parse_collection(text)["records"]
st, _why, _opens = prp.coord_state(rec)
print(st)
'@
    $pyfile = Join-Path $script:tmp 'reader_verdict.py'
    Set-Content -LiteralPath $pyfile -Value $py
    $p = Resolve-Python
    (& $p.exe @($p.pre + @($pyfile, $parse, $coordpath))).Trim()
  }

  # THE BOX QUEUE'S TAKE NOW GOES THROUGH `Take-RigLockWhenFree`, so from here
  # on these arms depend on the CENSUS as well as the lock - a change made
  # 18 Sep 2026 when `Enter-BoxQueue`'s dead `Get-Command Wait-LockFree` hook
  # was repointed at the function that actually landed. They passed on the feed
  # they inherited from the arm above, which is luck rather than a fixture, so
  # the quiet box is stated here instead of assumed.
  Set-Feed @(3.0)
  $script:procrows = @()

  "== box queue: Enter-BoxQueue takes an uncontested box, Exit-BoxQueue frees it"
  $bq1 = Join-Path $script:tmp 'COORDINATION-bq1.txt'
  Set-Content -LiteralPath $bq1 -Value @()
  $bqsink1 = New-Sink
  Set-PlibLog $bqsink1
  Enter-BoxQueue $bq1 'my-lane-18sep' 'ab12cd34' 'bq1-round' '2026-09-18T20:00:00Z' 1 5
  Check ($script:boxqueue_taken) 'nothing ahead of it: Enter-BoxQueue takes the box'
  Check (Test-RigLockHeld) '...and the REAL rig lock is actually held, not just the coordination line'
  Check ((Get-ReaderVerdict $bq1) -eq 'held') 'parfast-rigs-parse.py reads the box HELD after the CLAIM this pair posted'
  Exit-BoxQueue $bq1 'my-lane-18sep' 'ab12cd34'
  Set-PlibLog $null
  Check (-not (Test-RigLockHeld)) 'Exit-BoxQueue releases the real rig lock'
  Check ((Get-ReaderVerdict $bq1) -eq 'free') 'and parfast-rigs-parse.py agrees the box is FREE: QUEUED -> CLAIM -> DONE leaves no holder'
  $bq1lines = Get-Content -LiteralPath $bq1
  Check (@($bq1lines | Where-Object { $_ -match '^QUEUED ' }).Count -eq 1) 'exactly one QUEUED line was posted'
  Check (@($bq1lines | Where-Object { $_ -match '^CLAIM ' }).Count -eq 1) 'exactly one CLAIM line was posted'
  Check (@($bq1lines | Where-Object { $_ -match '^DONE ' }).Count -eq 1) 'exactly one DONE line was posted'
  Check (@($bq1lines | Where-Object { $_ -match '^NOTE ' }).Count -eq 0) 'never a NOTE - NOTE settles nothing for this reader'

  "== box queue: an ahead lane that already closed does not block the queue"
  $bq2 = Join-Path $script:tmp 'COORDINATION-bq2.txt'
  Set-Content -LiteralPath $bq2 -Value @(
    'CLAIM 2026-09-18T10:00:00Z ahead-lane-18sep - earlier round.'
    'DONE 2026-09-18T10:20:00Z ahead-lane-18sep - earlier round finished.'
  )
  $bqsink2 = New-Sink
  Set-PlibLog $bqsink2
  Enter-BoxQueue $bq2 'my-lane-18sep' 'ab12cd34' 'bq2-round' '' 1 5
  Set-PlibLog $null
  Check ($script:boxqueue_taken) 'an ahead lane with a real close does not block the queue'
  $bq2note = (Read-Sink $bqsink2 | Where-Object { $_ -like 'BOXQUEUE-POST *QUEUED*' })
  Check ($bq2note -like '*box appears free of any open CLAIM*') 'the QUEUED line correctly reports nobody ahead - the CLOSED lane is not counted'
  Exit-BoxQueue $bq2 'my-lane-18sep' 'ab12cd34'

  "== box queue: an ahead lane that never closes times out the wait, WITHOUT taking the box"
  $bq3 = Join-Path $script:tmp 'COORDINATION-bq3.txt'
  Set-Content -LiteralPath $bq3 -Value @(
    'CLAIM 2026-09-18T10:00:00Z stuck-lane-18sep - never posts a close.'
  )
  $bqsink3 = New-Sink
  Set-PlibLog $bqsink3
  Enter-BoxQueue $bq3 'my-lane-18sep' 'ab12cd34' 'bq3-round' '' 0 2
  Set-PlibLog $null
  Check (-not $script:boxqueue_taken) 'a lane ahead that never closes means this lane never takes the box'
  Check (-not (Test-RigLockHeld)) '...and the rig lock was never even asked for'
  Check ((@(Get-Content -LiteralPath $bq3) | Where-Object { $_ -match '^WITHDRAWN 2026\S* my-lane-18sep' }).Count -eq 1) 'a timed-out wait posts a close-class WITHDRAWN, never a bare NOTE - it must not read as a phantom holder to the next lane'
  Check ((Get-ReaderVerdict $bq3) -eq 'held') 'the box still correctly reads HELD - by stuck-lane-18sep, who never closed; my own withdrawal changed nothing about that'

  "== box queue: a lane that CLAIMS after the settle re-read is not run over"
  # THE ahead-list IS SNAPSHOTTED BEFORE THE WAIT, by `Get-CoordOpenIds`' own
  # design, so a lane arriving mid-wait can never join it - which is claim
  # `riglock-waiter-blind-to-late-arrivals` inside this pair rather than beside
  # it. The take goes through `Take-RigLockWhenFree` now, which re-reads with
  # the lock in hand, so the arrival is caught at the last possible moment
  # instead of not at all.
  #
  # THE WINDOW HAS TO BE THE RIGHT ONE, AND THERE ARE THREE. A rival landing
  # before the QUEUED line is caught by the ahead-list; one landing between the
  # CLAIM and the settle re-read is caught by that re-read (decision D, which
  # this pair already had). The window left over - and the only one this
  # change closes - is AFTER the settle re-read said clear and BEFORE the lock
  # is in hand. That is the one both 18 Sep instances happened in, so the rival
  # is appended from inside the SECOND `Get-CoordOpenIds`, which is that
  # re-read: it returns clear, and the rival lands on the next line.
  $bq6 = Join-Path $script:tmp 'COORDINATION-bq6.txt'
  Set-Content -LiteralPath $bq6 -Value @()
  $script:realgcoi = ${function:Get-CoordOpenIds}
  $script:gcoicalls = 0
  $script:lateposted = $false
  function Get-CoordOpenIds([string]$coordpath, [string]$excludeId) {
    $script:gcoicalls++
    $r = & $script:realgcoi $coordpath $excludeId
    if ($script:gcoicalls -eq 2 -and -not $script:lateposted) {
      $script:lateposted = $true
      Add-Content -LiteralPath $coordpath -Value 'CLAIM 2026-09-18T11:00:07Z late-lane-18sep - I claimed the instant after your settle re-read said this box was clear.'
    }
    return $r
  }
  $bqsink6 = New-Sink
  Set-PlibLog $bqsink6
  Enter-BoxQueue $bq6 'my-lane-18sep' 'ab12cd34' 'bq6-round' '' 0 1
  Set-PlibLog $null
  ${function:Get-CoordOpenIds} = $script:realgcoi
  Check ($script:lateposted -and $script:gcoicalls -ge 2) 'the rival really did arrive inside the window this arm exists to test - after the settle re-read said clear'
  Check ((@(Get-Content -LiteralPath $bq6) | Where-Object { $_ -match '^QUEUED ' }).Count -eq 1) '...and this lane had already declared nobody was ahead of it'
  $g6 = Read-Sink $bqsink6
  Check (-not $script:boxqueue_taken) 'a late CLAIM means this lane does not take the box'
  Check (-not (Test-RigLockHeld)) '...and the lock it briefly held to find out was given back'
  Check ((Count-Match $g6 'BOX-LATE-ARRIVAL .*open_claims=\[late-lane-18sep\]') -ge 1) '...and the round log names who beat it'
  Check ((@(Get-Content -LiteralPath $bq6) | Where-Object { $_ -match '^WITHDRAWN \S+ my-lane-18sep' }).Count -eq 1) 'our own CLAIM is closed with a WITHDRAWN, so we are not a second claimant on the file'
  Check ((@(Get-Content -LiteralPath $bq6) | Where-Object { $_ -like '*WITHDRAWN*late-lane-18sep*' }).Count -eq 1) '...and the WITHDRAWN says WHICH reason, not just that it failed'

  "== box queue: no cross-scope call to a function this repo does not define"
  # THE NEGATIVE CONTROL FOR THE HOOK THAT WAS REMOVED. It probed
  # `Get-Command -Name Wait-LockFree` and called whatever it found. That name is
  # hand-rolled inside three round drivers, all of which dot-source this
  # library, so in a real round it resolved THEIR function and called it with
  # plib's arguments. Defining one here proves it is never reached.
  $script:wlfcalled = $false
  function Wait-LockFree { param($a, $b) $script:wlfcalled = $true; $script:lockfree = $false }
  $bq7 = Join-Path $script:tmp 'COORDINATION-bq7.txt'
  Set-Content -LiteralPath $bq7 -Value @()
  Set-PlibLog $null
  Enter-BoxQueue $bq7 'my-lane-18sep' 'ab12cd34' 'bq7-round' '' 1 5
  Check ($script:boxqueue_taken) 'the box is taken with a rival Wait-LockFree in scope'
  Check (-not $script:wlfcalled) '...and that function was never called - the name hook is gone, not merely unused'
  Exit-BoxQueue $bq7 'my-lane-18sep' 'ab12cd34'
  Remove-Item -LiteralPath Function:\Wait-LockFree -ErrorAction SilentlyContinue

  "== box queue: Enter-BoxQueue refuses a coordination file that does not exist"
  $bqsink4 = New-Sink
  Set-PlibLog $bqsink4
  Enter-BoxQueue (Join-Path $script:tmp 'no-such-COORDINATION.txt') 'my-lane-18sep' 'ab12cd34' 'bq4-round' '' 1 2
  Set-PlibLog $null
  Check (-not $script:boxqueue_taken) 'a missing coordination file is refused, never treated as an empty/free one'
  Check ((Count-Match (Read-Sink $bqsink4) '^BOXQUEUE-REFUSE ') -eq 1) '...and the refusal is announced'

  "== box queue: Exit-BoxQueue refuses to post a marker outside the five-word close vocabulary"
  $bq5 = Join-Path $script:tmp 'COORDINATION-bq5.txt'
  Set-Content -LiteralPath $bq5 -Value @('CLAIM 2026-09-18T10:00:00Z my-lane-18sep - taking.')
  $threwBadKw = $false
  try { Exit-BoxQueue $bq5 'my-lane-18sep' 'ab12cd34' 'NOTE' } catch { $threwBadKw = $true }
  Check $threwBadKw 'NOTE (or any word outside DONE/RELEASED/WITHDRAWN/ABORTED/STAND-DOWN) is refused rather than posted - it would settle nothing for the reader'
  Check ((Get-Content -LiteralPath $bq5) -join "`n" -notlike '*NOTE*') 'and nothing was written for the refused call'

  "== box queue: Test-CoordStillHolds is the exact predicate Exit-BoxQueue's FAIL LOUDLY guard depends on"
  # A close that a LATER open re-opens (the shape a genuine race would leave
  # behind - see Exit-BoxQueue's header) must still read as a holder. This is
  # tested at the predicate directly, the same seam Get-BoxHandover /
  # Write-BoxHandoverNote are tested at elsewhere in this file: Exit-BoxQueue
  # has no way to manufacture that race deterministically against its own
  # single Add-Content call, but the guard it throws on is exactly this call.
  $bq6 = Join-Path $script:tmp 'COORDINATION-bq6.txt'
  Set-Content -LiteralPath $bq6 -Value @(
    'CLAIM 2026-09-18T10:00:00Z raced-lane-18sep - first round.'
    'DONE 2026-09-18T10:20:00Z raced-lane-18sep - first round finished.'
    'CLAIM 2026-09-18T10:25:00Z raced-lane-18sep - a later CLAIM landed after the close.'
  )
  Check (Test-CoordStillHolds $bq6 'raced-lane-18sep') 'a CLAIM after the DONE reads as a holder again - this is what Exit-BoxQueue checks for and throws on'
  Set-Content -LiteralPath $bq6 -Value @(
    'CLAIM 2026-09-18T10:00:00Z raced-lane-18sep - first round.'
    'DONE 2026-09-18T10:20:00Z raced-lane-18sep - first round finished.'
  )
  Check (-not (Test-CoordStillHolds $bq6 'raced-lane-18sep')) 'and with no later CLAIM, the same predicate says free - which is the case Exit-BoxQueue leaves behind on every normal exit'

  # --- the orphan note's coordination file ----------------------------------
  # WHERE THE NOTE GOES WAS WRONG ON ALL FOUR WINDOWS BOXES until 17 Sep 2026:
  # it looked only in `$env:USERPROFILE\bench-out` and took a match only when
  # exactly ONE was there. Three of the four have no bench-out directory at
  # all, so the note went nowhere and said nothing; the fourth had exactly one,
  # nine days dead, and it was taken on the strength of being single. These
  # cases pin all four shapes - zero, one, one-but-stale-against-a-newer, and
  # two - and they are hermetic: $env:USERPROFILE is already a temp directory
  # for the whole run, and this arm points it at a subdirectory OF ITS OWN for
  # the duration. Not $script:tmp itself, because the handover fixtures above
  # are called COORDINATION-*.txt and live there, so a fixture reset that swept
  # $script:tmp would delete another arm's evidence and couple the two.
  $script:chome = Join-Path $script:tmp 'coordhome'
  $script:bo = Join-Path $script:chome 'bench-out'
  New-Item -ItemType Directory -Force $script:chome | Out-Null

  # The bench-out DIRECTORY goes too, not just the files in it: three of the
  # four Windows boxes have no such directory at all, and a missing directory
  # under this file's `$ErrorActionPreference = 'Stop'` is the arm that has to
  # stay swallowed. New-CoordFile recreates it on demand.
  function Reset-CoordFixture {
    Remove-Item -Recurse -Force -LiteralPath $script:bo -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $script:chome -Filter 'COORDINATION-*.txt' -File -ErrorAction SilentlyContinue |
      Remove-Item -Force -ErrorAction SilentlyContinue
  }
  function New-CoordFile([string]$dir, [string]$name, [string]$utc) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $p = Join-Path $dir $name
    Set-Content -LiteralPath $p -Value @("CLAIM $utc some-lane-17sep - fixture.")
    # A FIXED mtime, not the write's own: the whole selection rule is an mtime
    # ranking, so a fixture whose files were all written in the same
    # millisecond would pass against a tie-break and prove nothing.
    (Get-Item -LiteralPath $p).LastWriteTimeUtc = [datetime]::ParseExact($utc, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
    return $p
  }
  # ALWAYS RE-WRAP THIS AT THE CALL SITE: `@(Get-NoteLines $s)[0]`. A function
  # that returns a one-element array UNROLLS it, so `(Get-NoteLines $s)[0]` on a
  # single match indexes the STRING and hands back its first CHARACTER - which
  # compares false against every pattern and reads as the feature being broken.
  # Ten of these cases failed that way on the first native run, with the lines
  # they were asserting about printed correctly one line above them.
  function Get-NoteLines([string]$sinkpath) {
    @(Read-Sink $sinkpath | Where-Object { $_ -like 'RIG-LOCK-ORPHAN-NOTE *' })
  }

  $script:oldcoordenv = $env:BOXGATE_COORD
  $env:BOXGATE_COORD = $null
  $env:USERPROFILE = $script:chome

  "== orphan note: zero candidates SAYS SO rather than going quiet"
  Reset-CoordFixture
  $csink = New-Sink
  Set-PlibLog $csink
  Write-RigLockOrphanNote (Join-Path $script:chome 'x.lock') 'round=dead pid=1' 'cleared by selftest'
  Set-PlibLog $null
  $cn = @(Get-NoteLines $csink)
  Check ($cn.Count -eq 1) 'a no-candidate clearing still emits a NOTE status line'
  Check ($cn[0] -like '*coord=NONE*') '...saying it found no coordination file'
  Check ($cn[0] -like '*bench-out*') '...and naming the directories it searched'
  Check ((Count-Match (Read-Sink $csink) '^RIG-LOCK-ORPHAN ') -eq 1) 'and the clearing itself is still announced'

  "== orphan note: one candidate is used, and the file gets the note"
  Reset-CoordFixture
  $one = New-CoordFile $script:bo 'COORDINATION-selfbox.txt' '2026-09-08T21:54:02Z'
  $csink2 = New-Sink
  Set-PlibLog $csink2
  Write-RigLockOrphanNote (Join-Path $script:chome 'x.lock') 'round=dead pid=1' 'cleared by selftest'
  Set-PlibLog $null
  $cn2 = @(Get-NoteLines $csink2)
  Check ($cn2[0] -like "*coord=$one*") 'the single candidate is the file it posts into'
  Check ($cn2[0] -like '*wrote=1*') 'and the append is reported as having happened'
  Check ((@(Get-Content -LiteralPath $one) | Where-Object { $_ -like 'NOTE * ORPHAN cleared at *' }).Count -eq 1) 'the NOTE really is in the coordination file'
  # THE AGE IS REPORTED, NEVER ENFORCED. mtime ranks; it does not refuse. A
  # threshold here would be the clock deciding liveness, which is the mistake
  # Get-RigLockHolder's header forbids for the lock - so a nine-day-old sole
  # candidate is still used, and the line says how old it is.
  Check ($cn2[0] -match 'age_d=\d+') 'the line carries the chosen file age, so a stale pick is visible'

  "== orphan note: the NEWEST candidate wins, not the only one"
  # The exact intel-i5-10600kf shape: a bench-out file that is the only thing the old
  # rule could see, and a newer one in the profile that it could not.
  Reset-CoordFixture
  $stale = New-CoordFile $script:bo 'COORDINATION-selfbox.txt' '2026-09-08T21:54:02Z'
  $fresh = New-CoordFile $script:chome 'COORDINATION-selfbox.txt' '2026-09-16T13:05:33Z'
  $csink3 = New-Sink
  Set-PlibLog $csink3
  Write-RigLockOrphanNote (Join-Path $script:chome 'x.lock') 'round=dead pid=1' 'cleared by selftest'
  Set-PlibLog $null
  $cn3 = @(Get-NoteLines $csink3)
  Check ($cn3[0] -like "*coord=$fresh*") 'the newer profile copy beats the older bench-out copy'
  Check ($cn3[0] -like '*src=newest-of-2*') '...and the line says it chose among two'
  Check ((Get-Content -LiteralPath $stale) -join "`n" -notlike '*ORPHAN cleared*') 'nothing was written to the stale one'

  "== orphan note: two candidates no longer mean silence"
  # The old rule took a match ONLY at Count -eq 1, so two candidates posted
  # nothing at all. Two files in the SAME directory, which the old arm's
  # `-eq 1` refused outright.
  Reset-CoordFixture
  $null = New-CoordFile $script:bo 'COORDINATION-selfbox.txt' '2026-09-08T21:54:02Z'
  $newer = New-CoordFile $script:bo 'COORDINATION-otherbox.txt' '2026-09-17T01:20:00Z'
  $csink4 = New-Sink
  Set-PlibLog $csink4
  Write-RigLockOrphanNote (Join-Path $script:chome 'x.lock') 'round=dead pid=1' 'cleared by selftest'
  Set-PlibLog $null
  Check ((@(Get-NoteLines $csink4))[0] -like "*coord=$newer*") 'two candidates resolve to the newer, instead of to nothing'

  "== orphan note: BOXGATE_COORD still wins outright"
  # It is the override that reaches a file on another volume, which no
  # derivation from a home directory can - the reason intel-i5-10600kf sets it.
  Reset-CoordFixture
  $null = New-CoordFile $script:bo 'COORDINATION-selfbox.txt' '2026-09-17T01:20:00Z'
  $pinned = Join-Path $script:chome 'pinned-COORD.txt'
  Set-Content -LiteralPath $pinned -Value @('CLAIM 2026-09-17T00:00:00Z lane - live file.')
  $env:BOXGATE_COORD = $pinned
  $csink5 = New-Sink
  Set-PlibLog $csink5
  Write-RigLockOrphanNote (Join-Path $script:chome 'x.lock') 'round=dead pid=1' 'cleared by selftest'
  Set-PlibLog $null
  $env:BOXGATE_COORD = $null
  $cn5 = @(Get-NoteLines $csink5)
  Check ($cn5[0] -like "*coord=$pinned src=BOXGATE_COORD*") 'BOXGATE_COORD beats every derived candidate'
  Check ((@(Get-Content -LiteralPath $pinned) | Where-Object { $_ -like '*ORPHAN cleared*' }).Count -eq 1) '...and that is the file the note lands in'

  "== orphan note: an unwritable target is reported, and never thrown"
  # Best effort in both directions - a round must never die because a
  # coordination file was unwritable - but it must not read as success either.
  # A DIRECTORY at the chosen path is the portable unwritable: it works on the
  # macOS runner that runs this in CI and on a Windows box alike, where a
  # permission bit does not.
  Reset-CoordFixture
  $baddir = Join-Path $script:chome 'unwritable-COORD.txt'
  New-Item -ItemType Directory -Force $baddir | Out-Null
  $env:BOXGATE_COORD = $baddir
  $csink6 = New-Sink
  Set-PlibLog $csink6
  $threw = $false
  try { Write-RigLockOrphanNote (Join-Path $script:chome 'x.lock') 'round=dead pid=1' 'cleared by selftest' } catch { $threw = $true }
  Set-PlibLog $null
  $env:BOXGATE_COORD = $null
  Check (-not $threw) 'an unwritable coordination file does not end the round'
  Check ((@(Get-NoteLines $csink6))[0] -like '*wrote=0*') '...and the failed append is reported rather than read as a success'

  Reset-CoordFixture
  $env:BOXGATE_COORD = $script:oldcoordenv
  $env:USERPROFILE = $script:tmp


  # THE REPORT HALF, which is the other half of the defect: a watcher that
  # prints only HANDOVER leaves the operator re-reading the file by hand. The
  # note carries the matched line, and it goes through the sink.
  $script:hsink = Join-Path $script:tmp 'handover.log'
  Set-PlibLog $script:hsink
  $noteout = Write-BoxHandoverNote 'nibble-crossover-quiet-box-confirm-16sep' $genuine
  Set-PlibLog $null
  Check ($noteout -like 'BOX-HANDOVER waiting_on=nibble-crossover-quiet-box-confirm-16sep *') 'the note names the id it was waiting on'
  Check ($noteout -like '*matched: DONE 2026-09-16T18:41:21Z nibble-crossover-quiet-box-confirm-16sep*') '...and QUOTES THE LINE IT MATCHED, so a misfire is visible'
  Check ((Get-Content -LiteralPath $script:hsink) -join "`n" -like '*BOX-HANDOVER*matched: DONE*') 'and the note reaches the round log sink, not just stdout'


  # =========================================================================
  # THE LATE ARRIVAL, AND THE CENSUS THAT CANNOT SEE ONE
  # =========================================================================
  # Both halves of claim `riglock-waiter-blind-to-late-arrivals`, 18 Sep 2026.
  # Every arm below is hermetic: a coordination file in the temp directory, the
  # rig lock in the temp profile, the CPU counter and the process table stubbed.
  $script:coord = Join-Path $script:tmp 'COORDINATION-selftest.txt'
  function Set-Coord([string[]]$lines) {
    Set-Content -LiteralPath $script:coord -Value $lines -Encoding ascii
  }

  "== late arrival: an open CLAIM posted after the waiter armed"
  # THE intel-i5-10600kf CASE, in four lines. `mine` armed and posted its own CLAIM;
  # `latelane` arrived afterwards and claimed. An ahead-list decided at arm time
  # holds only `oldlane`, and `oldlane` is done - so every waiter on this fleet
  # read this file as a free box and took it.
  Set-Coord @(
    'CLAIM 2026-09-17T19:06:50Z oldlane - the lane I armed behind',
    'DONE 2026-09-17T23:40:00Z oldlane - finished',
    'CLAIM 2026-09-18T00:50:00Z mine - my own claim',
    'CLAIM 2026-09-18T00:57:00Z latelane - 90 s of ISCC, posted 3 s after your FREE-1'
  )
  $lc = (Get-OpenClaimants $script:coord 'mine')
  Check ($lc.Count -eq 1) 'exactly one lane is holding the box'
  Check ($lc[0] -eq 'latelane') '...and it is the one that arrived after the waiter armed'
  Check ((Get-OpenClaimants $script:coord 'mine') -notcontains 'oldlane') 'a lane whose DONE came after its CLAIM is not holding'
  Check ((Get-OpenClaimants $script:coord 'mine') -notcontains 'mine') 'my own open claim is never counted against me'
  # AND WITH NO SELF ID, MY OWN CLAIM BLOCKS ME TOO, which is the safe
  # direction: a caller that cannot name itself gets the whole truth.
  Check (((Get-OpenClaimants $script:coord '')).Count -eq 2) 'a caller with no id of its own sees every open claim'

  "== late arrival: a lane that re-claims after its own DONE is holding again"
  Set-Coord @(
    'CLAIM 2026-09-18T01:00:00Z relane - first sitting',
    'DONE 2026-09-18T02:00:00Z relane - first sitting finished',
    'CLAIM 2026-09-18T03:00:00Z relane - second sitting, box is mine again'
  )
  Check (((Get-OpenClaimants $script:coord 'mine')) -contains 'relane') 'the STRICT reading: the last marker wins, not the presence of a DONE'

  "== late arrival: both field orders, because both are in these files"
  Set-Coord @(
    '2026-09-18T01:00:00Z CLAIM kwsecond - keyword in field 2',
    'CLAIM 2026-09-18T01:00:00Z kwfirst - keyword in field 1',
    '2026-09-18T02:00:00Z RELEASE kwfirst - closed with the keyword in field 2'
  )
  $of = (Get-OpenClaimants $script:coord 'mine')
  Check ($of.Count -eq 1 -and $of[0] -eq 'kwsecond') 'a claim and a close are read in either field order'

  "== late arrival: the open vocabulary is EIGHTEEN words, not one"
  # THE ARM THAT BOTH HAND-ROLLED COPIES FAILED. g4winrun2.ps1 matched
  # `^(DONE|CLAIM)` and cfwait.ps1 matched `CLAIM`, so a lane posting any of
  # the other seventeen was invisible to both - a round started on a box
  # somebody else had said, in the file, that they were holding.
  foreach ($kw in $script:handover_open) {
    Set-Coord @("$kw 2026-09-18T01:00:00Z vocablane - holding the box")
    $v = (Get-OpenClaimants $script:coord 'mine')
    Check ($v.Count -eq 1 -and $v[0] -eq 'vocablane') "$kw reads as an open claim"
  }
  foreach ($kw in $script:handover_close) {
    Set-Coord @('CLAIM 2026-09-18T01:00:00Z vocablane - holding the box',
                "$kw 2026-09-18T02:00:00Z vocablane - and handing it back")
    Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) "$kw closes an open claim"
  }

  # AND ONE MEMBER SPELLED OUT, because the loop above walks the library's own
  # list and would pass over a narrowed one by simply running fewer cases. This
  # word is the one both hand-rolled matchers missed by name.
  Set-Coord @('TAKEOVER 2026-09-18T01:00:00Z takelane - I am taking this box over')
  $tk = (Get-OpenClaimants $script:coord 'mine')
  Check ($tk.Count -eq 1 -and $tk[0] -eq 'takelane') 'TAKEOVER, which g4winrun2.ps1 and cfwait.ps1 both read as nothing, is an open claim'

  "== one fold, two policies: the box queue keeps its CLAIM-only rule"
  # THE FOLD IS SHARED SINCE 18 Sep 2026 and the vocabulary is a parameter, so
  # this pins the half that must NOT have moved: `Get-CoordOpenIds` is the box
  # queue's ahead-list and item 2's rule for it is "only a CLAIM is a hold". A
  # TAKEOVER is an open claim to the waiter next door and is not a hold here.
  Set-Coord @('TAKEOVER 2026-09-18T01:00:00Z takelane - taking this box over')
  Check ((@(Get-CoordOpenIds $script:coord 'mine')).Count -eq 0) 'the box queue default vocabulary is CLAIM alone, unchanged'
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 1) '...while the late-arrival waiter passes the roster and sees it'
  # And the field-order widening reaches the box queue's own callers, which is
  # the one behaviour change the shared fold made to what landed: a close
  # posted `<ts> DONE <id>` used to read as no close at all.
  Set-Coord @('CLAIM 2026-09-18T01:00:00Z bqlane - holding',
              '2026-09-18T02:00:00Z DONE bqlane - handed back')
  Check ((@(Get-CoordOpenIds $script:coord 'mine')).Count -eq 0) 'a close with the keyword in field 2 closes for the box queue too'
  Check (-not (Test-CoordStillHolds $script:coord 'bqlane')) '...and Test-CoordStillHolds agrees'

  "== late arrival: prose, NOTEs and short lines are not claims"
  Set-Coord @(
    'NOTE 2026-09-18T01:00:00Z notelane - I am thinking about this box',
    'QUEUED 2026-09-18T01:00:00Z queuelane - in line, not holding',
    'CLAIM 2026-09-18T01:10:00Z',
    '  an indented wrapped line from the middle of somebody else note',
    ''
  )
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) 'a file of prose and half-lines yields no claimant'
  # THIS USED TO BE A STATED LIMIT AND IS NOW A FIX, 19 Sep 2026. The roster has
  # eighteen open words in it and some are ordinary English (CONTINUATION,
  # PROGRESS, RESULT, START, LIVE, HOLD), so a wrapped prose line whose SECOND
  # token was one of them and whose third was a word read as a claim on that
  # word. The pin that stood here called that a false positive costing a WAIT.
  # IT COSTS MORE THAN A WAIT: the subject it mints is a word no lane will ever
  # post a close for, on an append-only file, so it is a PERMANENT stand-down
  # for every caller on that box - which is what line 8 of windows-gaming-pc-b's file
  # (`ROUTE CLAIM CHECKED MECHANICALLY, ...`) did to a correct round on 19 Sep.
  # And the same code path reads a prose sentence as a CLOSE, which frees a
  # held box. `Get-CoordMarkerEvent` is the fix and its header carries the
  # corpus measurement; these cases are its acceptance.
  Set-Coord @('  ah CONTINUATION of the note above, wrapped by the editor')
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) 'an English open keyword in wrapped prose is not a claim - no stamp beside it'

  "== late arrival: the windows-gaming-pc-b phantom, and the prose CLOSE that is the other half of it"
  # THE LINE ITSELF, from `%USERPROFILE%\COORDINATION-windows-gaming-pc-b.txt`. Under the old
  # rule field 1 is `CLAIM` and field 2 is the subject, so this held an open
  # claim named `CHECKED` that nothing could ever close.
  Set-Coord @('ROUTE CLAIM CHECKED MECHANICALLY, not by eye: every rig on the list answered.')
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) 'the windows-gaming-pc-b sentence mints no subject at all'
  Check ($null -eq (Get-CoordMarkerEvent 'ROUTE CLAIM CHECKED MECHANICALLY, not by eye' $script:handover_open)) '...and the parser says so directly, rather than the fold papering over it'
  # THE DANGEROUS DIRECTION. A live lane, then a sentence that names a close
  # keyword in field 1 and that lane in field 2. Under the old rule this FREED
  # the box; six instances of the shape are on the fleet's files today.
  Set-Coord @('CLAIM 2026-09-19T01:00:00Z realdocs-lane-19sep - measuring',
              'NOTE DONE realdocs-lane-19sep is what I will post when the ladder ends')
  Check (((Get-OpenClaimants $script:coord 'mine')) -contains 'realdocs-lane-19sep') 'a prose sentence does NOT close a live lane - this is the half that puts two rounds on one box'
  Set-Coord @('CLAIM 2026-09-19T01:00:00Z realdocs-lane-19sep - measuring',
              'the RELEASE realdocs-lane-19sep note above was about the OTHER box')
  Check (((Get-OpenClaimants $script:coord 'mine')) -contains 'realdocs-lane-19sep') '...and neither does one whose first word is English and whose second is a close keyword'
  # ...and the close that IS marker-shaped still lands, or the fix above would
  # simply have replaced one phantom with another.
  Set-Coord @('CLAIM 2026-09-19T01:00:00Z realdocs-lane-19sep - measuring',
              'DONE 2026-09-19T02:00:00Z realdocs-lane-19sep - box free')
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) 'a real DONE still closes it'

  "== late arrival: the three marker shapes the fleet actually writes"
  # S1, S2 and S3 out of `Get-CoordMarkerEvent`'s header, each measured on the
  # 19 Sep 2026 corpus. A shape dropped from here is a live writer going
  # invisible, which is the polarity that costs somebody's round.
  Set-Coord @('CLAIM 2026-09-19T01:00:00Z s1-lane-19sep - the Write-CoordMarker shape')
  Check (((Get-OpenClaimants $script:coord 'mine')) -contains 's1-lane-19sep') 'S1: <KEYWORD> <stamp> <subject>'
  Set-Coord @('2026-09-19T01:00:00Z CLAIM s2-lane-19sep - the intel-i5-10600kf shape')
  Check (((Get-OpenClaimants $script:coord 'mine')) -contains 's2-lane-19sep') 'S2: <stamp> <KEYWORD> <subject>'
  Set-Coord @('[2026-08-14T02:01:10Z] CLAIM s2-bracketed-lane - two of these are on apple-m1-ultra-64gb')
  Check (((Get-OpenClaimants $script:coord 'mine')) -contains 's2-bracketed-lane') 'S2 with the stamp in brackets, which is the only thing between those lines and being read'
  # S3, THE LIVE ONE. The rarkit fleet gate-tip driver posts no stamp in field 1
  # at all, and the subject is the VALUE of `claim=` so it is the real claim id.
  Set-Coord @('CLAIM gate-tip-19sep claim=rarkit-gate-tip-fleet-19sep box=a round=gate-tip-19sep pid=1 started=2026-09-19T22:49:09Z')
  Check (((Get-OpenClaimants $script:coord 'mine')) -contains 'rarkit-gate-tip-fleet-19sep') 'S3: the subject is the VALUE of claim=, not the token'
  Set-Coord @('CLAIM gate-tip-19sep claim=rarkit-gate-tip-fleet-19sep box=a round=gate-tip-19sep pid=1 started=2026-09-19T22:49:09Z',
              'DONE gate-tip-19sep claim=rarkit-gate-tip-fleet-19sep rc=0 at=2026-09-19T22:49:27Z')
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) '...and its DONE closes the same subject'
  # AND THE KEY THAT IS NOT A SUBJECT. Ten lines of the M5's coordination file
  # carry `ACCOUNTS=none` in field 2; reading it as a subject is how that file
  # grew an open claim called `ACCOUNTS=none`.
  Set-Coord @('CLAIM rar5-wide-horizons-7sep ACCOUNTS=none 103 external archives verified')
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) 'ACCOUNTS= is not one of the three keys that name a subject'

  "== late arrival: the degenerate stamps the fleet has actually written"
  # `MARKER_TS_RE` refuses these and says why: there the stamp is the only
  # guard. Here it is one of three anchors, and refusing them costs REAL
  # CLOSES - `codex-par2-create-race` on apple-m1-ultra-64gb is closed by a line whose
  # stamp is an unexpanded `$TS` and nothing else.
  foreach ($stamp in @('10:35Z', '03:0*Z', '2026-08-02', '09/09/2026', '2026-09-03T~18:25Z', '$TS', '%Y-%m-%dT%H:%M:%SZ')) {
    Set-Coord @("CLAIM $stamp degen-lane-19sep - a stamp somebody really wrote")
    Check (((Get-OpenClaimants $script:coord 'mine')) -contains 'degen-lane-19sep') "a $stamp stamp still opens"
    Set-Coord @('CLAIM 2026-09-19T01:00:00Z degen-lane-19sep - holding',
                "DONE $stamp degen-lane-19sep - handed back")
    Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) "...and still closes"
  }

  "== late arrival: a third token that was never a subject"
  # Both shapes are on the live files. `CLAIM 23:16Z 6 Aug <id>` put the DAY
  # in field 2 and minted `6`; three intel-i5-10600kf lines put the TIME there. A
  # subject has a letter in it and is not itself a stamp.
  Set-Coord @('CLAIM 23:16Z 6 Aug mock-ceiling-AB (session tracking-benchmarks)')
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) 'a numeric third token is not a subject'
  Set-Coord @('CLAIM 09/09/2026 3:22:07.91 par2-additive-leaf-ladder-9sep (<user>)')
  Check (((Get-OpenClaimants $script:coord 'mine')).Count -eq 0) 'and neither is a second stamp'

  "== late arrival: an UNREADABLE file is not an EMPTY one"
  # THE ONE PLACE IN THIS LIBRARY WHERE A FAILED READ CHANGES THE VALUE rather
  # than only the log line. "No open claim" reads as TAKE THE BOX, so the usual
  # $null-means-keep-waiting convention would turn a missing file into a green
  # light. The pseudo-id blocks every caller and says why in the text a
  # stand-down NOTE quotes.
  $gone = Join-Path $script:tmp 'no-such-COORDINATION.txt'
  $u = (Get-OpenClaimants $gone 'mine')
  Check ($u.Count -eq 1) 'an unreadable coordination file yields a blocking answer'
  Check ($u[0] -like '(unreadable:*)') '...and it says so, rather than reading as a free box'
  Check (((Get-OpenClaimants '' 'mine')).Count -eq 0) 'but an EMPTY path is the caller opting out, and yields nothing'

  "== late arrival: the matcher RETURNS and the note LOGS, and never both"
  # The seam Require-QuietBox's header is about: a status line inside the
  # matcher would reach the caller as part of the answer.
  Set-Coord @('CLAIM 2026-09-18T00:57:00Z latelane - holding')
  $sinkla = New-Sink
  Set-PlibLog $sinkla
  $quiet = (Get-OpenClaimants $script:coord 'mine')
  Check ($quiet.Count -eq 1 -and $quiet[0] -eq 'latelane') 'the matcher returns ids and nothing else'
  Check (-not (Test-Path -LiteralPath $sinkla)) '...and writes no line of its own'
  $lanote = Write-LateArrivalNote 'selftest-late' @('latelane')
  Set-PlibLog $null
  Check ($lanote.Contains('open_claims=[latelane]') -and $lanote.StartsWith('BOX-LATE-ARRIVAL at=selftest-late ')) 'the note NAMES the lane, so a misfire is visible'
  Check (((Get-Content -LiteralPath $sinkla) -join "`n") -like '*BOX-LATE-ARRIVAL*') 'and it reaches the round log sink'

  "== census: a NON-CARGO holder is not invisible any more"
  # THE SECOND HALF OF THE 18 Sep FINDING. An ISCC compile is not parfast,
  # cargo or rustc and takes no rig lock, so the box read genuinely free on two
  # samples sixty seconds apart while a lane was actively compiling on it.
  Set-Feed @(4.0)
  $script:procrows = @([pscustomobject]@{ ProcessName = 'ISCC'; Id = 5150; CPU = 40.0 })
  $ci = Get-BoxCensus 50.0
  $script:procrows = $null
  Check (-not $ci.Free) 'an ISCC compile makes the box busy'
  Check ($ci.Names -like '*ISCC(5150)*') '...and the census names it'
  Check ($ci.Why -like '*tools=*') '...and says that is why'

  "== census: the PRIMARY arm is CPU attribution, not the name list"
  # A name list cannot be complete, which is the whole finding - so a tool in
  # NO list at all still has to make the box busy.
  Set-Feed @(220.0)
  $script:procrows = @([pscustomobject]@{ ProcessName = 'somebodyelsestool'; Id = 6001; CPU = 220.0 })
  $cc = Get-BoxCensus 50.0
  $script:procrows = $null
  Check (-not $cc.Free) 'a tool nobody listed still makes the box busy'
  Check ($cc.Names -eq '') '...with nothing in the name list at all'
  Check ($cc.Why -like '*foreign_cpu=220*over ceiling=50*') '...on the CPU attribution alone'

  "== census: a free box REPORTS ITS READING, which is what made 18 Sep re-readable"
  Set-Feed @(21.7)
  $script:procrows = @()
  $cf = Get-BoxCensus 50.0
  $sinkbc = New-Sink
  Set-PlibLog $sinkbc
  $bcnote = Write-BoxCensusNote 'selftest-free' $cf
  Set-PlibLog $null
  $script:procrows = $null
  Check ($cf.Free) 'a quiet box with no lock and no tools is free'
  Check ($bcnote -like '*free=1*foreign_cpu=21.7*') 'the FREE line still carries the figure a later reader needs'
  Check (((Get-Content -LiteralPath $sinkbc) -join "`n") -like '*BOX-CENSUS*free=1*') 'and it reaches the sink'

  "== census: an unmeasurable counter is NOT busy, and says the arm was blind"
  Set-Feed @()
  $script:procrows = @()
  $cu = Get-BoxCensus 50.0
  $script:procrows = $null
  Check ($cu.Free) 'a box with no CPU counter does not livelock every waiter'
  Check ($cu.ForeignCpu -eq -1.0) '...and the reading says the arm was blind rather than quiet'

  "== census: a HELD lock is busy, by the hold rule and never by Test-Path"
  # FAILING TO FIND IS FAILING: without a live foreign pid the two arms below
  # would be testing an ORPHAN and passing for the wrong reason, so the absence
  # is a named failure rather than a quiet one.
  Check ($script:foreignpid -gt 0) 'a live foreign pid was found for the held-lock arms'
  $lkp = Get-RigLockPath
  Set-Content -LiteralPath $lkp -Value "round=someoneelse pid=$($script:foreignpid) started=2026-09-18T00:00:00Z" -Encoding ascii
  Set-Feed @(1.0)
  $script:procrows = @()
  $ch = Get-BoxCensus 50.0
  $script:procrows = $null
  Check (-not $ch.Free) 'a lock naming a live pid makes the box busy'
  Check ($ch.Why -like '*lock held by live pid*') '...and the census quotes the hold rule verdict'
  # An ORPHAN - a lock naming a pid that is gone - is NOT a hold, which is the
  # 16 Sep defect and the reason Test-Path was never the right question.
  Set-Content -LiteralPath $lkp -Value 'round=dead pid=999999' -Encoding ascii
  Set-Feed @(1.0)
  $script:procrows = @()
  $co = Get-BoxCensus 50.0
  $script:procrows = $null
  Check ($co.Free) 'an ORPHANED lock does not block a waiter forever'
  Remove-Item -LiteralPath $lkp -Force -ErrorAction SilentlyContinue

  # =========================================================================
  # THE ACQUIRE IS THE PROBE
  # =========================================================================
  # The case a census CANNOT close, and the reason this function exists: on
  # 18 Sep a lane read `lock_held=False` at 13:26 and another lane took the
  # lock at 13:28:19. The lock was free when asked. Below, every question is
  # asked with our own exclusive handle already open.
  "== take: a clean file and a quiet box is a take"
  Set-Coord @('DONE 2026-09-18T00:00:00Z oldlane - finished and gone')
  Set-Feed @(3.0)
  $script:procrows = @()
  $sinkt1 = New-Sink
  Set-PlibLog $sinkt1
  Take-RigLockWhenFree -round 'selftest-take' -coordpath $script:coord -selfid 'mine' -maxwaits 0 -polls 1 | Out-Null
  Set-PlibLog $null
  $script:procrows = $null
  Check ($script:riglock_taken) 'the box was taken'
  Check (Test-Path -LiteralPath (Get-RigLockPath)) '...and our lock file is on disk'
  Check ((Count-Match (Read-Sink $sinkt1) 'BOX-TAKE-CONFIRMED round=selftest-take .*open_claims=none') -eq 1) '...and the confirmation names the round'
  Release-RigLock '' | Out-Null

  "== take: a LATE ARRIVAL is caught with the lock in hand, and the lock is GIVEN BACK"
  # THE HEADLINE ARM. The acquire succeeds - nothing that respects the lock can
  # take the box now - and only THEN is the file re-read. A claimant that is
  # not ours means the lock is released rather than run under, which is the
  # half a probe-then-act driver cannot do because by then it is already
  # running.
  Set-Coord @('CLAIM 2026-09-18T00:57:00Z latelane - I claimed while you were building')
  Set-Feed @(3.0)
  $script:procrows = @()
  $sinkt2 = New-Sink
  Set-PlibLog $sinkt2
  Take-RigLockWhenFree -round 'selftest-late' -coordpath $script:coord -selfid 'mine' -maxwaits 0 -polls 1 -standdownonclaim | Out-Null
  Set-PlibLog $null
  $script:procrows = $null
  $gt2 = Read-Sink $sinkt2
  Check (-not $script:riglock_taken) 'the box was NOT taken'
  Check (-not (Test-Path -LiteralPath (Get-RigLockPath))) '...and the lock we briefly held was given back, not sat on'
  Check ((Count-Match $gt2 'RIG-LOCK-TAKEN') -eq 1) 'the acquire really happened - it is the probe'
  Check ((Count-Match $gt2 'RIG-LOCK-RELEASED') -eq 1) '...and was released in the same breath'
  Check ((Count-Match $gt2 'BOX-LATE-ARRIVAL .*open_claims=\[latelane\]') -eq 1) 'the late arrival is named in the round log'
  Check ((Count-Match $gt2 'BOX-TAKE-STANDDOWN round=selftest-late') -eq 1) 'and the stand-down says whose box it is'
  # THE ORDER IS THE WHOLE CLAIM, and it is the one thing that separates this
  # from every waiter that came before: the ACQUIRE is logged BEFORE the
  # coordination re-read. A probe-then-act driver reads the file first and
  # acquires minutes later, and the gap between those two lines is where both
  # 18 Sep instances happened.
  $itake = [array]::FindIndex($gt2, [Predicate[string]]{ param($l) $l -match 'RIG-LOCK-TAKEN' })
  $ilate = [array]::FindIndex($gt2, [Predicate[string]]{ param($l) $l -match 'BOX-LATE-ARRIVAL' })
  Check ($itake -ge 0 -and $ilate -gt $itake) 'the lock was acquired BEFORE the file was re-read - the acquire IS the probe'
  Check ($script:boxtake_why -like '*latelane*') 'the reason comes back in $script:boxtake_why, not as a return value'

  "== take: a BUSY box is released and waited out, never run under"
  Set-Coord @('DONE 2026-09-18T00:00:00Z oldlane - finished')
  Set-Feed @(900.0)
  $script:procrows = @([pscustomobject]@{ ProcessName = 'ISCC'; Id = 5150; CPU = 900.0 })
  $sinkt3 = New-Sink
  Set-PlibLog $sinkt3
  Take-RigLockWhenFree -round 'selftest-busy' -coordpath $script:coord -selfid 'mine' -maxwaits 0 -polls 1 | Out-Null
  Set-PlibLog $null
  $script:procrows = $null
  $gt3 = Read-Sink $sinkt3
  Check (-not $script:riglock_taken) 'a busy box is not taken'
  Check (-not (Test-Path -LiteralPath (Get-RigLockPath))) '...and our lock is not left behind'
  Check ((Count-Match $gt3 'BOX-CENSUS at=take:selftest-busy free=0') -eq 1) 'the census that refused it is in the round log'
  Check ((Count-Match $gt3 'BOX-TAKE-GAVE-UP round=selftest-busy .*cap_s=0') -eq 1) 'and the give-up names its own cap'

  "== take: another round HOLDING the lock is waited out, and NEVER cleared"
  $lkp2 = Get-RigLockPath
  Set-Content -LiteralPath $lkp2 -Value "round=someoneelse pid=$($script:foreignpid) started=2026-09-18T00:00:00Z" -Encoding ascii
  Set-Coord @('DONE 2026-09-18T00:00:00Z oldlane - finished')
  Set-Feed @(3.0)
  $script:procrows = @()
  $sinkt4 = New-Sink
  Set-PlibLog $sinkt4
  Take-RigLockWhenFree -round 'selftest-held' -coordpath $script:coord -selfid 'mine' -maxwaits 0 -polls 1 | Out-Null
  Set-PlibLog $null
  $script:procrows = $null
  Check (-not $script:riglock_taken) 'a held box is not taken'
  Check ((Get-Content -LiteralPath $lkp2) -like '*round=someoneelse*') 'and the holder lock file is untouched - we clear nothing of anyone else'
  Check ((Count-Match (Read-Sink $sinkt4) 'LOCK-BUSY') -ge 1) 'the refusal is in the round log'
  Remove-Item -LiteralPath $lkp2 -Force -ErrorAction SilentlyContinue
  $script:riglock_taken = $false

  # ---------------------------------------------------------------------
  # INVOKE-LEG DECODES A CHILD'S STREAMS AS UTF-8
  # ---------------------------------------------------------------------
  # an internal note. `Invoke-Leg` redirects
  # both of a child's streams and reads them with `ReadToEndAsync()`, and until
  # 20 Sep 2026 set no encoding on either - so on Windows the bytes were decoded
  # in the CONSOLE CODEPAGE and re-encoded as UTF-8 by `WriteAllText`, turning
  # parfast's U+00B7 field separator (`C2 B7`) into a valid-UTF-8 two-character
  # mojibake, which a driver then echoed into a redirected round log where the
  # codepage could not represent it and emitted `?`. That second stage is not
  # reversible and cost a post-hoc rewrite of two banked round logs.
  #
  # TWO ARMS, AND NEITHER IS SUFFICIENT ALONE. The behavioural one below can
  # only FAIL on a box whose console codepage is not already UTF-8, which is
  # every Windows rig and none of the macOS runners this file is gated on - so
  # on the runner it proves the technique and pins nothing. The source arm is
  # what holds the two lines in place everywhere, and it is a source check
  # rather than a stub because `Invoke-Leg` builds its `ProcessStartInfo`
  # inline, with no seam to interpose on.
  "== Invoke-Leg: both child streams are decoded as UTF-8"
  $plibsrc = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'plib.ps1')
  # Anchored INSIDE Invoke-Leg, not merely somewhere in the file: the whole
  # point is which ProcessStartInfo gets them.
  $legblock = ''
  $mleg = [regex]::Match($plibsrc, '(?s)function Invoke-Leg\b.*?\$null = \$proc\.Start\(\)')
  if ($mleg.Success) { $legblock = $mleg.Value }
  Check ($legblock -ne '') 'the Invoke-Leg block up to Start() is locatable in plib.ps1'
  Check ($legblock -match '\$psi\.StandardOutputEncoding\s*=\s*\[Text\.Encoding\]::UTF8') 'Invoke-Leg sets StandardOutputEncoding to UTF8 before Start()'
  Check ($legblock -match '\$psi\.StandardErrorEncoding\s*=\s*\[Text\.Encoding\]::UTF8') 'Invoke-Leg sets StandardErrorEncoding to UTF8 before Start()'
  # And NOT the per-driver half, which belongs to whoever owns the console and
  # must not be reached into from a dot-sourced library.
  Check ($legblock -notmatch '\[Console\]::OutputEncoding\s*=') 'Invoke-Leg does NOT set [Console]::OutputEncoding - that half is per-driver'

  # The behavioural arm. A child that writes the two raw bytes `C2 B7` to its
  # stderr and stdout handles, read back through a ProcessStartInfo configured
  # the way Invoke-Leg configures one, must come back as ONE U+00B7.
  $hostexe = $null
  try { $hostexe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName } catch { $hostexe = $null }
  if (-not $hostexe -or -not (Test-Path -LiteralPath $hostexe)) {
    # A skip and not a failure: this arm needs to be able to name its own host
    # binary, and the source arms above are the ones that hold the rule.
    Ok 'child round-trip SKIPPED - this host binary could not be named'
  } else {
    $kid = Join-Path $script:tmp 'dotchild.ps1'
    Set-Content -LiteralPath $kid -Encoding ascii -Value @(
      '$b = [byte[]]@(0x6D,0x66,0x3A,0xC2,0xB7,0x6F,0x6B)',
      '$e = [Console]::OpenStandardError(); $e.Write($b,0,$b.Length); $e.Flush()',
      '$o = [Console]::OpenStandardOutput(); $o.Write($b,0,$b.Length); $o.Flush()')
    $kpsi = New-Object Diagnostics.ProcessStartInfo
    $kpsi.FileName = $hostexe
    $kpsi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$kid`""
    $kpsi.UseShellExecute = $false
    $kpsi.RedirectStandardOutput = $true
    $kpsi.RedirectStandardError = $true
    $kpsi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $kpsi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $kpsi.CreateNoWindow = $true
    $kid_proc = New-Object Diagnostics.Process
    $kid_proc.StartInfo = $kpsi
    $null = $kid_proc.Start()
    $kto = $kid_proc.StandardOutput.ReadToEndAsync()
    $kte = $kid_proc.StandardError.ReadToEndAsync()
    $kid_proc.WaitForExit()
    $kerr = $kte.Result
    $kout = $kto.Result
    $kid_proc.Dispose()
    # `mf:<U+00B7>ok` - one character where the codepage decode leaves two.
    Check ($kerr -match "mf:$([char]0x00B7)ok") 'a child writing C2 B7 to stderr reads back as one U+00B7'
    Check ($kout -match "mf:$([char]0x00B7)ok") 'and the same on stdout'
    # The shape of the damage this exists to refuse, named rather than implied:
    # a CP437 decode gives U+252C U+2556, a CP850 one U+00C2 U+00B7.
    Check ($kerr -notmatch "$([char]0x252C)|$([char]0x2556)") 'and carries no CP437 round-trip of those two bytes'
  }

  if ($script:fails -eq 0) { "plib_selftest: all cases pass ($($script:cases) cases)" }
  else { "plib_selftest: $($script:fails) of $($script:cases) cases FAILED" }
}
finally {
  $env:USERPROFILE = $script:oldprofile
  $env:PLIB_LOG = $script:oldpliblog
  # The orphan-note arm pins this one for six cases; restore it here as well as
  # inline, so a failure part-way through that arm cannot leak it into whatever
  # dot-sources this next.
  if ($null -ne $script:oldcoordenv) { $env:BOXGATE_COORD = $script:oldcoordenv }
  Remove-Item -Recurse -Force $script:tmp -ErrorAction SilentlyContinue
}
exit $(if ($script:fails -eq 0) { 0 } else { 1 })
