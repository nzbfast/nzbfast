param(
  [string]$Wcomb = (Join-Path $PSScriptRoot 'wcomb.ps1'),
  [string]$Parse = '',                           # also AST-parse this file (default: $Wcomb)
  [string]$Src = ''                              # repo root - also check the log ANCHORS still exist in the Rust that emits them
)
# wcombcheck.ps1 - THE acceptance suite for wcomb.ps1, added 16 Sep 2026 for
# lane avx512-bare-metal-row-gate-16sep and extended the same day by lane
# nibble-block-size-row-gate-16sep. It covers three things:
#
#   * an AST parse of wcomb.ps1 (PARSE-OK);
#   * the log ANCHORS wcomb.ps1's regexes rest on, in wcomb.ps1 AND, with
#     -Src, in the Rust that emits them (ANCHORS-OK);
#   * the -Residency assertion, 11 cases (RESCHECK-OK);
#   * the RUNG-BOUND guard, 11 cases (RUNGCHECK-OK).
#
# THE LAST OF THOSE LIVED IN A SECOND FILE, `wcombrungcheck.ps1`, until 16 Sep
# 2026. Two files doing one job, left apart because the alternative was
# refactoring a working suite in the half hour before a timing round on a
# borrowed box. Merged here; there is nothing left to run separately.
#
# WHY THIS EXISTS AND NOT A COMMENT. The dev Mac has NO PowerShell, so every
# edit to this harness family lands UNRUN unless it is deliberately exercised
# on a Windows box (memory topic nzbfast-parfast-leg-rig-stamp: "a plib.ps1
# edit lands UNRUN"). This is the kind of code that has to be right the first
# time - it runs once per leg on a box that is available only in a window the maintainer
# arranges per occasion, and a syntax error or an inverted comparison there
# costs the window, not a retry.
#
# AND IT HAS EARNED ITS KEEP BY DISAGREEING WITH ITS AUTHOR, three times, about
# three different things. A suite that has never failed has not been tested.
#   * The first cut of the -RESIDENCY assertion compared the syndrome line's
#     `n=` against the FIXTURE's n; `n=` is `present.len()`, so that cut would
#     have refused every leg it ever saw. A parse check would have passed it.
#   * The first cut of the RUNG-BOUND GUARD used `-ge`, refusing m = recovery.
#     m missing blocks are repairable from EXACTLY m recovery blocks (the
#     matrix is square and solvable), so that is the LAST LEGAL rung and not
#     the first illegal one - and as written it would have refused a default
#     `-Phase measure` ladder against the very -c4096 fixture the guard exists
#     to protect.
#   * One of the rung CASES was wrong, not the guard: the k lane's own fix
#     (rungs to 2,048 against a -c2048 fixture) was written here as a refusal,
#     copying their framing rather than thinking. It is legal, and now expects
#     accept.
#
# IT EXTRACTS EACH BLOCK FROM wcomb.ps1 RATHER THAN COPYING IT, so an edit to
# an assertion is exercised by this file instead of drifting away from a
# private copy of it - the "one rule, one copy" rule, applied to a check. If a
# future edit ends up with the assertion logic pasted in here, the value is
# gone and only the lines are left. `exit 9` is rewritten to `throw` and
# `Fail-Leg` is stubbed (the refusal sites call it since 16 Sep 2026, and it
# restores work\ from pristine\ before exiting - a refused leg is not a no-op)
# so a refusal can be OBSERVED rather than ending this process.
#
# RUN IT on any reachable Windows box. It needs no fixture, no rig lock and no
# parfast: it loads nothing, builds nothing, opens no fixture and writes
# nothing into a round root, so it is milliseconds of one core and does not
# disturb a round in flight. That is written down in .claude/MACHINES.md
# ("A HARNESS PARSE CHECK IS NOT A TIMED LEG") - stay inside it. Put scratch in
# the profile you log in as, and remove it by LISTING the names as their own
# command and deleting BY NAME; the rig lock lives in that same directory and a
# sweep wider than *.ps1 reaches a live round's lock.
#
#   scp harness/wcomb.ps1 harness/wcombcheck.ps1 box:C:<rig>/
#   ssh box 'powershell -NoProfile -ExecutionPolicy Bypass -File <rig>\wcombcheck.ps1 -Wcomb <rig>\wcomb.ps1'
#
# -Src <repo root> ADDS THE ANCHOR CHECK, and it covers the exposure one level
# up from the assertions. Extracting a block out of wcomb.ps1 stops the CHECK
# drifting from the ASSERTION, but both of them rest on wcomb.ps1's regexes
# still matching parfast's own log wording - and a rename in the Rust leaves
# the harness and this suite agreeing with each other while every real leg
# reads as though the line was never printed. So each anchor is asserted in
# BOTH places: the escaped form in wcomb.ps1 and the plain form in the source
# that logs it. Without -Src this prints ANCHORS-UNCHECKED rather than implying
# a coverage it does not have. The idea is the oramxcheck.ps1 lane's
# (an internal note); both anchors here
# happen to live in one file, which is why this takes a repo root and not a
# file list.
#
# THE -RESIDENCY CASE THAT MATTERS is 'resident, windows absent but n short'.
# `windows=0` is an ABSENCE, and an absence is also what this harness reports
# when a wording change makes a regex miss - so on `windows=` alone a windowed
# leg would PASS after a rename of parfast's `ntt window (...)` line. The
# syndrome line's `n=` is the positive half, and the two together are what make
# the assertion mean anything.
#
# THE RUNG-BOUND BUG, for the same reason. A rung above the fixture's recovery
# count cannot be repaired, and that does not surface as a clear error: the
# fold leg returns rc=2 restored=0/16 and the FORCE leg at that rung silently
# falls back to the fold path. wcomb.ps1's path assertion does catch the second
# half and refuse - correctly, and at the first wrong leg - but by then the
# fixture is built and a queue slot on a shared box is spent. The
# parfast-k-1mib-nibble-16sep lane lost a launch to exactly this on 16 Sep
# (`-Phase measure` defaults top out at m = 4,096; its 1 MiB fixture was
# created -c2048).
#
# TWO MECHANICAL TRAPS in this family, both of which have cost a lane real
# time. PowerShell names are CASE-INSENSITIVE, so `$h` and `$H` are one
# variable - which is why the extracted source text below is `$wtext` and not
# `$src`, a name the -Src parameter already owns. And `Tee-Object` writes
# UTF-16LE, which matters if you compare captured output.
$ErrorActionPreference = 'Stop'
if (-not $Parse) { $Parse = $Wcomb }

$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($Parse, [ref]$t, [ref]$e)
if ($e.Count -ne 0) {
  "PARSE-ERRORS count=$($e.Count)"
  $e | ForEach-Object { "  line $($_.Extent.StartLineNumber): $($_.Message)" }
  exit 1
}
"PARSE-OK tokens=$($t.Count) file=$Parse"

$wtext = [IO.File]::ReadAllText($Wcomb)

# ---------------------------------------------------------------- anchors ---
# Each is (label, the form wcomb.ps1's regex must contain, the form the
# emitting source must contain). Both halves matter: the first catches this
# suite drifting from the harness, the second catches the harness drifting from
# parfast.
$anchors = @(
  @{ label = 'ntt syndromes'; ps = 'ntt syndromes \(m='; rust = 'ntt syndromes (m='; file = 'crates/nzbkit-base/src/par2repair/reconstruct.rs' },
  @{ label = 'ntt window';    ps = 'ntt window \(';      rust = 'ntt window (';      file = 'crates/nzbkit-base/src/par2repair/reconstruct.rs' }
)
$afail = 0
foreach ($a in $anchors) {
  if ($wtext.IndexOf($a.ps) -lt 0) { "ANCHOR-FAIL $($a.label): wcomb.ps1 no longer contains the regex '$($a.ps)'"; $afail++ }
}
if ($Src) {
  foreach ($a in $anchors) {
    $f = Join-Path $Src $a.file
    if (-not (Test-Path $f)) { "ANCHOR-FAIL $($a.label): $($a.file) not found under -Src $Src"; $afail++; continue }
    if (([IO.File]::ReadAllText($f)).IndexOf($a.rust) -lt 0) { "ANCHOR-FAIL $($a.label): '$($a.rust)' is gone from $($a.file) - wcomb.ps1's regex will match nothing and every leg will read as if the line was never printed"; $afail++ }
  }
  if (-not $afail) { "ANCHORS-OK $($anchors.Count) checked in wcomb.ps1 and in the Rust that logs them" }
} else {
  if (-not $afail) { "ANCHORS-UNCHECKED (pass -Src <repo root> to check them against the Rust that logs them; the wcomb.ps1 halves passed)" }
}
if ($afail) { "WCOMBCHECK-FAIL $afail anchor(s)"; exit 1 }

# --------------------------------------------------------------- plumbing ---
# ONE runner for both families. It takes the block EXTRACTED from wcomb.ps1,
# rewrites `exit 9` to a throw and prepends a Fail-Leg stub, then reports
# whether the block refused. The stub is harmless to a block that does not call
# it; rewriting only `exit 9` left the residency block calling an undefined
# function after the Fail-Leg refactor, and this suite caught that on the first
# run after it, which is what it is for.
function Invoke-Block([string]$block, [ref]$refused) {
  $b = "function Fail-Leg([string]`$msg) { `$msg; throw 'EXIT9' }`n" + ($block -replace 'exit 9', 'throw "EXIT9"')
  $refused.Value = $false
  try { return (& ([scriptblock]::Create($b))) }
  catch { if ("$_" -match 'EXIT9') { $refused.Value = $true; return @() } else { throw } }
}
$fails = 0

# ------------------------------------------------- the -Residency assertion --
$i = $wtext.IndexOf('if ($Residency -and ($arm -like ''force*''')
$j = if ($i -ge 0) { $wtext.IndexOf("`n    }", $i) } else { -1 }
if ($i -lt 0 -or $j -lt 0) { "RESCHECK-FAIL could not locate the assertion block in $Wcomb"; exit 1 }
$resblock = $wtext.Substring($i, $j - $i + 6)
"extracted residency block: $($resblock.Split([char]10).Count) lines"

function Case-Res($name, $Residency, $arm, $wincount, $ns, $n, $m, $want) {
  $script:Residency = $Residency; $script:arm = $arm; $script:n = $n; $script:m = $m
  $script:wins = @(1..$wincount | Where-Object { $wincount -gt 0 })
  $script:ns = $ns; $script:tag = 'testleg'
  $exited = $false
  $out = Invoke-Block $script:resblock ([ref]$exited)
  $got = if ($exited) { 'refuse' } else { 'accept' }
  if ($got -ne $want) { "RESCHECK-FAIL $name want=$want got=$got out=$out"; $script:fails++ }
  else { "ok   res  $name -> $got" }
}

Case-Res 'resident, clean resident leg'        'resident' 'force'  0 @('16064') 16384 320 'accept'
Case-Res 'resident, but the arm WINDOWED'      'resident' 'force'  2 @('2000')  16384 320 'refuse'
Case-Res 'resident, windows absent but n short' 'resident' 'force' 0 @('2000')  16384 320 'refuse'
Case-Res 'resident, A/A copy arm force2'       'resident' 'force2' 0 @('16064') 16384 320 'accept'
Case-Res 'resident, multi-call one short'      'resident' 'force'  0 @('16064','2048') 16384 320 'refuse'
Case-Res 'windowed, windowed leg'              'windowed' 'force'  3 @('2000')  16384 320 'accept'
Case-Res 'windowed, but ran RESIDENT'          'windowed' 'force'  0 @('16064') 16384 320 'refuse'
Case-Res 'fold arm is never asserted'          'resident' 'fold'   0 @()        16384 320 'accept'
Case-Res 'unset means no assertion'            ''         'force'  9 @('2000')  16384 320 'accept'
Case-Res 'bad -Residency value refuses'        'sideways' 'force'  0 @('16064') 16384 320 'refuse'
Case-Res 'resident at another rung m=352'      'resident' 'force'  0 @('16032') 16384 352 'accept'

# ------------------------------------------------- the RUNG-BOUND guard ------
$ri = $wtext.IndexOf('$shapef = Join-Path $fix ')
$rk = $wtext.IndexOf('RUNG-BOUND ok')
$rj = if ($rk -ge 0) { $wtext.IndexOf("`n  }`n", $rk) } else { -1 }
if ($ri -lt 0 -or $rj -lt 0) { "RUNGCHECK-FAIL could not locate the guard in $Wcomb"; exit 1 }
$rungblock = $wtext.Substring($ri, $rj - $ri + 5)
"extracted rung block: $($rungblock.Split([char]10).Count) lines"

function Case-Rung($name, $Phase, $Rungs, $Recovery, $shapeRec, $want) {
  $d = Join-Path $env:TEMP ("rc" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force $d | Out-Null
  if ($null -ne $shapeRec) { [IO.File]::WriteAllText((Join-Path $d 'shape.txt'), "slice=65536 members=16 membermib=64 recovery=$shapeRec`n") }
  $script:fix = $d; $script:Phase = $Phase; $script:Rungs = $Rungs; $script:Recovery = $Recovery
  $exited = $false
  $out = Invoke-Block $script:rungblock ([ref]$exited)
  Remove-Item $d -Recurse -Force -EA SilentlyContinue
  $got = if ($exited) { 'refuse' } else { 'accept' }
  if ($got -ne $want) { "RUNGCHECK-FAIL $name want=$want got=$got :: $($out -join ' / ')"; $script:fails++ }
  else { "ok   rung $name -> $got   [$($out -join ' / ')]" }
}
# the k lane's actual bug: measure defaults top at 4096 against a -c2048 fixture
Case-Rung 'measure defaults vs c2048 fixture' 'measure' '' 2048 2048 'refuse'
Case-Rung 'measure defaults vs c4096 fixture' 'measure' '' 4096 4096 'accept'
# m = recovery is the LAST LEGAL rung, not the first illegal one, so the k
# lane's fix is accepted. This expectation was 'refuse' when written and was
# the AUTHOR's error, not the guard's - the second of the three disagreements
# in the header.
Case-Rung 'their fix: explicit rungs to 2048' 'measure' '192,512,1024,2048' 2048 2048 'accept'
Case-Rung 'my round A 64k'  'rowgate' '192,224,256,288,352'     4096 4096 'accept'
Case-Rung 'my round B 1m'   'rowgate' '256,288,320,352,384'     1024 1024 'accept'
Case-Rung 'my round C 256k' 'rowgate' '224,256,288,320,352,384' 1024 1024 'accept'
Case-Rung 'rowgate defaults (max 640) vs c1024' 'rowgate' '' 1024 1024 'accept'
Case-Rung 'rowgate defaults vs c512'            'rowgate' '' 512  512  'refuse'
Case-Rung 'shape.txt WINS over a wrong -Recovery' 'rowgate' '' 4096 512 'refuse'
Case-Rung 'no shape.txt falls back to -Recovery' 'rowgate' '' 1024 $null 'accept'
Case-Rung 'create phase is exempt' 'create' '4096' 1024 1024 'accept'

if ($fails) { "WCOMBCHECK-FAIL $fails case(s)"; exit 1 } else { 'WCOMBCHECK-OK all 22 cases, the parse and the anchors' }
