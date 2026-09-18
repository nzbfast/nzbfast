param([string]$P = '', [string]$Src = '')
# oramxcheck.ps1 - parse-check oramx.ps1 and exercise its member-count knob,
# on any Windows box, WITHOUT running a leg or taking the rig lock. Added
# 16 Sep 2026 with the knob itself (section 3.1 of
# an internal note).
# KEEP THIS FILE PURE ASCII: PowerShell 5.1 reads a BOM-less script as ANSI.
#
# There is no pwsh on the Miami Macs, so a .ps1 edited there is UNRUN until it
# reaches a Windows box - and an over-RAM round is a 45-second fixture write
# plus tens of minutes of legs, which is an expensive place to find a typo.
# This is the cheap gate in front of that: seconds, no lock, no fixture.
#
# It does NOT copy oramx.ps1's logic. It pulls the REAL `Get-MemberSpec` out
# of the script's AST and invokes that, so a copy cannot drift from the
# original - the failure mode that a hand-written twin of a harness function
# has every time.
# -Src <repo root> closes the ONE loop the AST trick cannot: Get-Route is the
# real function, but the four log lines it is fed are a COPY of parfast's own
# wording, so a rename in the Rust would leave both this check and the script
# agreeing with each other while every real leg read UNPARSED. With -Src, the
# anchors are asserted against the Rust sources themselves. The Miami Macs have
# no PowerShell and a bench box gets the tree as a `git archive` tarball for
# its build, so -Src is available exactly where this runs; without it the check
# says so rather than implying a coverage it does not have.
if (-not $P) { $P = Join-Path $PSScriptRoot 'oramx.ps1' }
$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($P, [ref]$toks, [ref]$errs)
if ($errs.Count -ne 0) {
  foreach ($x in $errs) { "PARSE-ERR line=$($x.Extent.StartLineNumber) $($x.Message)" }
  exit 1
}
"PARSE-OK $P tokens=$($toks.Count)"
$bytes = [IO.File]::ReadAllBytes($P)
$non = @($bytes | Where-Object { $_ -gt 126 }).Count
"ASCII-CHECK nonascii=$non bytes=$($bytes.Length)"
if ($non -ne 0) { "CHECK-FAIL oramx.ps1 is not pure ASCII"; exit 1 }

$fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-MemberSpec' }, $true)
if ($fn.Count -ne 1) { "CHECK-FAIL Get-MemberSpec found $($fn.Count) times, expected 1"; exit 1 }
Invoke-Expression $fn[0].Extent.Text

$script:fail = 0
function Check($label, $got, $want) {
  if ("$got" -ne "$want") { "CHECK-FAIL $label got=[$got] want=[$want]"; $script:fail++ }
  else { "ok $label = $got" }
}

# One member is EXACTLY the pre-knob cell: the historical flat fixture name and
# the whole set in one file, so a 45g.bin an earlier round wrote is reused.
$m = Get-MemberSpec 45 1
Check 'n1 count' $m.Count 1
Check 'n1 name' $m[0][0] 'f45g.bin'
Check 'n1 size' $m[0][1] (45L * 1073741824L)

# 60 members of 90 GiB divide exactly: 1,536 MiB each.
$m = Get-MemberSpec 90 60
Check 'n60/90 count' $m.Count 60
Check 'n60/90 first name' $m[0][0] 'f90g-n60-000.bin'
Check 'n60/90 last name' $m[59][0] 'f90g-n60-059.bin'
Check 'n60/90 first size' $m[0][1] 1610612736L
Check 'n60/90 last size' $m[59][1] 1610612736L
Check 'n60/90 distinct names' (@($m | ForEach-Object { $_[0] } | Select-Object -Unique)).Count 60
$sum = 0L; foreach ($x in $m) { $sum += [int64]$x[1] }
Check 'n60/90 total' $sum (90L * 1073741824L)

# 60 of 24 GiB do not: 59 x 410 MiB and a SHORT tail, the shape a rar set has.
$m = Get-MemberSpec 24 60
Check 'n60/24 first size' $m[0][1] (410L * 1048576L)
Check 'n60/24 last size' $m[59][1] (24L * 1073741824L - 410L * 1048576L * 59L)
$sum = 0L; foreach ($x in $m) { $sum += [int64]$x[1] }
Check 'n60/24 total' $sum (24L * 1073741824L)
if ([int64]$m[59][1] -le 0) { "CHECK-FAIL n60/24 tail is not positive"; $script:fail++ }
if ([int64]$m[59][1] -gt [int64]$m[0][1]) { "CHECK-FAIL n60/24 tail is the LONGEST member"; $script:fail++ }

# The create argument a leg builds. Every member is named explicitly because
# these boxes have no shell glob, so the 32 KB command-line limit is a real
# ceiling on the member count and is worth printing.
$names = @((Get-MemberSpec 90 60) | ForEach-Object { $_[0] })
$argstr = "c -q -b32768 -r15 k.par2 $($names -join ' ')"
"ARGLEN members=60 chars=$($argstr.Length)"
if ($argstr.Length -gt 30000) { "CHECK-FAIL argstr too long for one command line"; $script:fail++ }

# Get-Route reads the admission gate off a leg's stderr. Its four cases are
# exercised against text taken VERBATIM from
# crates/nzbkit-base/src/par2gen/stripe_first.rs, so a wording change there
# shows up here as a CHECK-FAIL rather than as `route=UNPARSED` on a leg line
# in the middle of a box window.
$rfn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Route' }, $true)
if ($rfn.Count -ne 1) { "CHECK-FAIL Get-Route found $($rfn.Count) times, expected 1"; exit 1 }
Invoke-Expression $rfn[0].Extent.Text

$tmp = Join-Path $env:TEMP "oramxcheck-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
function RouteCase($label, $lines, $wantroute, $wantcorpus, $wantmapgate) {
  $f = Join-Path $tmp "$label.err"
  [IO.File]::WriteAllText($f, ($lines -join "`r`n"))
  $r = Get-Route $f
  Check "route [$label]" $r[0] $wantroute
  Check "corpus [$label]" $r[1] $wantcorpus
  Check "mapgate [$label]" $r[2] $wantmapgate
}
RouteCase 'bands' @(
  ' INFO repair-timing: create map refused: payload 96636764160 B over available 60000000000 B - the copied windows take it',
  ' INFO repair-timing: create stripe-first admitted: 4 batch(es), 1638 rows, n=32768, bands of up to 1918130000 B over copies'
) 'bands' 1918130000L 'refused'
RouteCase 'mapped' @(
  ' INFO repair-timing: create stripe-first admitted: 4 batches, 1638 rows, n=32768'
) 'mapped' -1 'silent'
RouteCase 'refused' @(
  ' INFO repair-timing: create map refused: payload 96636764160 B over available 60000000000 B - the copied windows take it',
  ' INFO repair-timing: create stripe-first refused: the members are read through copies (not mapped, or the payload would not stay resident - see mapped_payload_fits_memory) and bands are off (NZBFAST_CREATE_STRIPE_BANDS=0) (4 batch(es), 1638 rows, n=32768, fused=false)'
) 'refused' -1 'refused'
# A leg whose timing block says nothing about the gate must read UNPARSED, not
# a route. This is the case the field exists for.
RouteCase 'silent' @(' INFO repair-timing: create scan + fold 41.2 s') 'UNPARSED' -1 'silent'
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

if ($Src) {
  # Two files, because the two gates log from two places: the stripe-first
  # admission is in stripe_first.rs and the mapping-fits refusal is in its
  # parent par2gen.rs. A lane that checks only the first would miss `mapgate`
  # going blind.
  $srcs = @{
    'create stripe-first admitted:'         = 'crates/nzbkit-base/src/par2gen/stripe_first.rs'
    'bands of up to {bytes} B over copies'  = 'crates/nzbkit-base/src/par2gen/stripe_first.rs'
    'create stripe-first refused:'          = 'crates/nzbkit-base/src/par2gen/stripe_first.rs'
    'create map refused:'                   = 'crates/nzbkit-base/src/par2gen.rs'
  }
  foreach ($anchor in $srcs.Keys) {
    $f = Join-Path $Src $srcs[$anchor]
    if (-not (Test-Path $f)) { "CHECK-FAIL anchor source missing $f"; $script:fail++; continue }
    if ([IO.File]::ReadAllText($f).Contains($anchor)) { "ok anchor [$anchor]" }
    else { "CHECK-FAIL anchor [$anchor] no longer in $($srcs[$anchor]) - Get-Route will read UNPARSED"; $script:fail++ }
  }
} else {
  "ANCHORS-UNCHECKED pass -Src <repo root> to assert the log wording against the Rust"
}

if ($script:fail -eq 0) { "CHECK-ALL-OK" } else { "CHECK-FAILURES $script:fail"; exit 1 }
