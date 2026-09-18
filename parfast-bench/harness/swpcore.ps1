# swp.ps1 - the CREATE sweep on Intel: set size x redundancy, parfast against
# par2cmdline-turbo, plus a MEMORY-CONSTRAINED parfast arm.
#
# The published create figures are RAW performance with memory unconstrained -
# parfast sizes its accumulators from the process budget, which defaults to
# half the machine, and that is the number a reader should compare against a
# rival's default. But "fast because it used all your RAM" is a fair objection,
# so this round answers it in its own data rather than in a footnote: a third
# arm runs the identical create under `-m`, and the CC lines carry both the
# wall and the peak for each. `-m` binds the accumulator formula above a
# 256 MiB floor (crates/parfast/src/lib.rs), so a budget under that is a
# ceiling the create still overshoots; the arm here is well above it.
#
# Sizes are hardlinked out of one payload, so growing the set costs no disk and
# no copy time, and every size is built from the same bytes.
#
# THE ARM ORDER ROTATES ONE STEP PER CELL, and that is not tidiness. This sweep
# runs ONE leg per (size, redundancy, arm) - there is no rep loop for an ABBA to
# alternate over - so before 17 Sep 2026 `parfast` was first in all eighteen
# cells, `parfast-mcap` second in all eighteen and `turbo` third. Two things
# then land on the same arm every time. There is NO warm between the arms of a
# cell, so the first arm reads a freshly hard-linked src dir COLD and the other
# two read it warm; and any drift inside the cell - a shared box's load, a
# thermal ramp - accumulates in one direction. Measured over zswp2.log's 54
# legs, the second-position arm carried a median `foreign_cpu` of 33.5% of one
# core against the first's 24.2, systematically. That bounded out at well under
# 1% of wall there against a 12-16% effect, so the banked round stands - but a
# fixed order on a single-shot sweep has no defence at all, and rotating across
# the cells costs NOTHING because the legs are run either way.
# `arm_pos` is banked on every CC line so a later reader can test a round for a
# position effect instead of re-running it, which is what catwin.ps1 does and
# what no banked sweep before this one allows.
# Census and ranking: an internal note (this sweep is
# its #1). The incident: an internal note
# sections 6-8. Never replace this with `[array]::Reverse` - reversing three
# arms leaves the middle one in the middle forever (jcross.ps1, 12 Sep 2026).
param(
  [string]$root  = '<rig>',
  [int[]] $sizes = @(10,15,20,23,30,40),
  [int[]] $reds  = @(10,15,20),
  [int]   $threads = 16,
  [int]   $membudget_mb = 2048,
  [string]$round = 'zenswp'
)
# plib does not always live beside the round: intel-i5-10600kf keeps it in the user
# profile and runs the round off D:. Try beside first, then the known home.
$plib = Join-Path $root 'plib.ps1'
if (-not (Test-Path $plib)) { $plib = Join-Path $env:USERPROFILE 'pub\plib.ps1' }
if (-not (Test-Path $plib)) { throw "plib.ps1 not found for root $root" }
. $plib

$bin   = Join-Path $root 'bin'
$pay   = Join-Path $root 'paysweep'
$rig   = Join-Path $root 'swp'
$lock  = Join-Path $root 'swp.lock'
$GIB   = 1073741824
$BASE_SLICE = 768000
$SLICE_CAP  = 32768
$maxsize = ($sizes | Measure-Object -Maximum).Maximum

function Get-SliceFor([int]$g) {
  # 750 KiB where the whole set fits under PAR2's 32,768-slice cap, otherwise
  # the smallest 4-byte-aligned slice that does. A slice must be a multiple of 4.
  if ($g * [math]::Ceiling($GIB / $BASE_SLICE) -le $SLICE_CAP) { return $BASE_SLICE }
  $per = [math]::Floor($SLICE_CAP / $g)
  $s = [math]::Ceiling($GIB / $per)
  return [int]([math]::Ceiling($s / 4) * 4)
}

New-Item -ItemType Directory -Force -Path $root | Out-Null
Take-RigLock $lock
try {
  "SWP-START $((Get-Date).ToUniversalTime().ToString('o'))"
  Write-BoxFacts
  Write-BinFacts $bin @('parfast','par2turbo')
  $armbase = @('parfast','parfast-mcap','turbo')
  $cellno = 0
  "PROTOCOL sizes_gib=[$($sizes -join ', ')] redundancy_pct=[$($reds -join ', ')] threads=$threads recovery=in-place slice_cap=$SLICE_CAP base_slice=$BASE_SLICE mem_arm_mb=$membudget_mb arms=$($armbase -join '/') arm_order=rotating-by-cell"

  New-Item -ItemType Directory -Force -Path $pay | Out-Null
  for ($i = 0; $i -lt $maxsize; $i++) {
    $f = '{0}\p{1:d2}.bin' -f $pay, $i
    if ((Test-Path $f) -and ((Get-Item $f).Length -eq $GIB)) { continue }
    $buf = New-Object byte[] (64MB)
    $rng = New-Object Random(20260910 + $i * 7919)
    $fs = [IO.File]::Create($f)
    for ($k = 0; $k -lt 16; $k++) { $rng.NextBytes($buf); $fs.Write($buf, 0, $buf.Length) }
    $fs.Close()
  }
  "PAYLOAD-READY members=$(@(Get-ChildItem $pay -Filter *.bin).Count) bytes=$(((Get-ChildItem $pay -Filter *.bin)|Measure-Object Length -Sum).Sum)"

  foreach ($g in $sizes) {
    $bs = Get-SliceFor $g
    $blocks = $g * [int][math]::Ceiling($GIB / $bs)
    Remove-Item $rig -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path "$rig\src","$rig\logs" | Out-Null
    $members = @()
    for ($i = 0; $i -lt $g; $i++) {
      $nm = 'p{0:d2}.bin' -f $i
      # a hard link, so N sizes share one copy of the bytes on disk
      $null = New-Item -ItemType HardLink -Path "$rig\src\$nm" -Target "$pay\$nm" -ErrorAction SilentlyContinue
      if (-not (Test-Path "$rig\src\$nm")) { Copy-Item "$pay\$nm" "$rig\src\$nm" }
      $members += $nm
    }
    $memarg = ($members -join ' ')
    $tcap = [math]::Min($threads, $members.Count)

    foreach ($r in $reds) {
      # A NEW array every cell, rotated one step - not a reverse, and not a
      # rotate-in-place on $armbase, which would mutate the round's own arm list.
      $k = $cellno % $armbase.Count
      $armorder = @(); for ($ai = 0; $ai -lt $armbase.Count; $ai++) { $armorder += $armbase[($ai + $k) % $armbase.Count] }
      $cellno++
      $o = 0
      foreach ($arm in $armorder) {
        $o++
        Get-ChildItem "$rig\src\pub*.par2" -EA 0 | Remove-Item -Force -EA SilentlyContinue
        switch ($arm) {
          'parfast'      { $exe = "$bin\parfast.exe";   $extra = '' }
          'parfast-mcap' { $exe = "$bin\parfast.exe";   $extra = "-m$membudget_mb " }
          'turbo'        { $exe = "$bin\par2turbo.exe"; $extra = '' }
        }
        $argstr = "c -q -t$threads -T$tcap $extra-s$bs -r$r pub.par2 $memarg"
        $res = Invoke-Leg $exe $argstr "$rig\src" "$rig\logs\cc-$g-$r-$arm"
        $pf = @(Get-ChildItem "$rig\src\pub*.par2" -EA 0)
        $mb = [math]::Round((($pf | Measure-Object Length -Sum).Sum) / 1MB)
        "CC round=$round size=$g red=$r bs=$bs blocks=$blocks arm=$arm arm_pos=$o arm_order=rotating-by-cell argv='$argstr' wall=$($res.wall) cpu=$($res.cpu) cpu_over_wall=$([math]::Round($res.cpu/[math]::Max($res.wall,0.001),2)) peak_mb=$($res.peakmb) recovery_mb=$mb files=$($pf.Count) rc=$($res.rc) foreign_cpu=$($res.foreign) errlen=$($res.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
        if ($res.rc -ne 0 -or $pf.Count -eq 0) { "SWP-WARN size=$g red=$r arm=$arm rc=$($res.rc) files=$($pf.Count)" }
        # the recovery volume must be the size the redundancy asked for, or the
        # arm did not do the work the wall is being credited with
        $lo = $g * 1024 * $r / 100 * 0.90; $hi = $g * 1024 * $r / 100 * 1.25
        if ($mb -lt $lo -or $mb -gt $hi) { "SWP-WARN size=$g red=$r arm=$arm recovery_mb=$mb outside [$([int]$lo),$([int]$hi)]" }
      }
    }
    "SIZE-DONE $g $((Get-Date).ToUniversalTime().ToString('o'))"
  }
  "SWP-END $((Get-Date).ToUniversalTime().ToString('o'))"
}
finally { Release-RigLock $lock }
