#!/usr/bin/env pwsh
#
# plib_selftest.ps1 - the selftest for plib.ps1's ROUND LOG SINK.
#
#     pwsh -NoProfile -File harness/plib_selftest.ps1
#
# Runs in CI on a macOS runner through `tools/rig-selftest-gate.py --run-plib`
# (job `plib-selftest` in .github/workflows/rig-selftest.yml), which is the
# real gate for this file: no Mac on this fleet runs the Windows drivers, and
# there is no pwsh on the dev box at all, so a parse error in plib.ps1 would
# otherwise reach a Windows box as "every round on this machine dies at
# dot-source time". It runs natively on Windows too and is worth a pass there
# after any edit to the sink.
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
  function Get-Process {
    [CmdletBinding()] param()
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
