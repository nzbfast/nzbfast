param(
  [string]$root = '<rig>',
  [int]   $pct,                       # parity percentage for THIS phase
  # ONE COMMA-SEPARATED STRING, NOT AN ARRAY. `powershell -File script.ps1
  # -rungs @(1,2,3)` does not bind an [int[]] - the first value binds and the
  # rest spill into whatever parameter comes next, which here produced
  # "cannot convert 8192 to Hashtable" and NOT a wrong benchmark, but only
  # because the next parameter happened to be strongly typed. It cost this
  # campaign a round on 10 Sep in the form where it binds silently. The
  # production caller dot-sources and would have been fine; a human debugging
  # this file over ssh would not.
  [string]$rungs,                     # depths to rebuild, in blocks: "1399,4096,8192"
  [string]$round,                     # names the log lines
  [int]   $createBudget = 0,          # 0 = no create budget; else seconds
  [hashtable]$createRef = $null,      # tool -> seconds at a known pct, for projecting
  # PER-TOOL DEPTH CEILING. par2cmdline and phpar2 are roughly fifty times
  # parfast at this job, so carrying them to the set's ceiling costs hours per
  # leg for bars whose only message is "this tool is very slow", which the
  # shallow rungs already say. They stop where they stop, the log records the
  # ceiling, and the chart note says why rather than leaving a reader to wonder.
  [hashtable]$toolMaxRung = $null,    # tool -> deepest rung it may attempt
  [hashtable]$toolReps    = $null     # tool -> how many repetitions it gets
)
# fieldcore.ps1 - one phase of the seven-tool comparison.
#
# WHAT WENT WRONG IN ITS PREDECESSOR, because this file exists to make that
# impossible rather than unlikely. fld2.ps1 ran a 10 GiB set at 15% parity -
# 13,990 source blocks, 2,098 recovery blocks - and asked it to rebuild 4,096,
# 8,192, 16,384 and 32,177 blocks. You cannot rebuild more blocks than you have
# parity for, so four of its five depths were arithmetically impossible.
#
# Nothing stopped it, either. The budget skip only records a tool's cost after a
# leg that FULLY RESTORES, so each impossible depth left the projection stale
# and the next was attempted anyway: six readers, four dead depths, two
# repetitions, two tools at twenty minutes an attempt. A whole night producing
# nothing, with every leg exiting cleanly.
#
# THE GUARD IS AT THE TOP, deliberately - refuse before the fixture is built,
# not on the deepest leg an hour in. The same check already existed in the
# python harness this family descends from; it simply lived in a file this
# script did not inherit from.
# The shared harness library: the rig lock, the timed leg, the damage picks and
# the SHA gate all live there. It was dropped when this file was assembled from
# its predecessor - the slice that took the body started one line below it - and
# the script then ran all the way through its own guard before failing on
# `Take-RigLock`. The guard test caught it; nothing else would have, because a
# missing lock does not announce itself until two rounds collide.
. (Join-Path $root 'plib.ps1')

$bin   = '<rig>\bin'
$pay   = '<rig>\pay-distinct'
$rig   = Join-Path $root "field-$pct"
$lock  = Join-Path $root 'field.lock'
$slice = 768000
$SRCBLK = 13990                       # 10 x 1 GiB at 750 KiB slices
$recovery = [int]($SRCBLK * $pct / 100)
# THE GUARD. A depth past the parity the set holds is not slow, it is
# impossible, and every leg at it fails while exiting cleanly.
$rungList = @($rungs.Split(',') | Where-Object { $_ } | ForEach-Object { [int]$_.Trim() })
$tooDeep = @($rungList | Where-Object { $_ -gt $recovery })
if ($tooDeep.Count) {
  "FIELD-FAIL round=$round pct=$pct source_blocks=$SRCBLK recovery_blocks=$recovery"
  "FIELD-FAIL depth(s) beyond the parity this set holds: $($tooDeep -join ', ')"
  "FIELD-HINT you cannot rebuild more blocks than you have parity for. Raise -pct or lower the depths."
  exit 11
}
"GUARD-OK round=$round pct=$pct source_blocks=$SRCBLK recovery_blocks=$recovery deepest_rung=$(($rungList | Measure-Object -Maximum).Maximum)"
$creators = @('parfast','par2turbo','par2classic','phpar2','par2j64','parpar','rarpar')
$readers  = @('parfast','par2turbo','par2classic','phpar2','par2j64','rarpar')
$reps  = @(1,2)
$budget = 4000                                # seconds; a projected leg over this is skipped
$script:lastleg = @{}                         # tool -> @{ m = <rung>; wall = <seconds> }

New-Item -ItemType Directory -Force -Path '<rig>' | Out-Null
Take-RigLock $lock
try {
  "FIELD-START $((Get-Date).ToUniversalTime().ToString('o'))"
  Write-BoxFacts
  Write-BinFacts $bin $creators
  "PROTOCOL slice=$slice redundancy_pct=$pct source_blocks=13990 damage=delete-p00.bin missing_blocks=1399 reps=2 gate=sha256-all-members prewarm=full-read-of-work-dir"

  Remove-Item $rig -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path "$rig\pristine","$rig\work","$rig\set","$rig\logs" | Out-Null
  $members = @(Get-ChildItem $pay -Filter *.bin | Sort-Object Name | ForEach-Object { $_.Name })
  foreach ($nm in $members) { Copy-Item "$pay\$nm" "$rig\pristine\$nm" }
  $gold = @{}
  foreach ($nm in $members) { $gold[$nm] = Get-Sha256Fast "$rig\pristine\$nm" }
  $uniq = ($gold.Values | Sort-Object -Unique).Count
  "FIXTURE members=$($members.Count) distinct_member_sha=$uniq/$($members.Count) bytes=$(((Get-ChildItem "$rig\pristine" -Filter *.bin)|Measure-Object Length -Sum).Sum)"
  if ($uniq -ne $members.Count) { "FIELD-FAIL payload members not distinct"; Release-RigLock $lock; exit 9 }
  foreach ($nm in $members) { "GOLD $nm $($gold[$nm])" }
  $memarg = ($members -join ' ')

  $cargv = @{
    'parfast'     = "c -q -t12 -T16 -s$slice -r$pct f.par2 $memarg"
    'par2turbo'   = "c -q -t12 -T16 -s$slice -r$pct f.par2 $memarg"
    'par2classic' = "c -q -s$slice -r$pct f.par2 $memarg"
    'phpar2'      = "c -q -s$slice -r$pct f.par2 $memarg"
    'par2j64'     = "c /ss$slice /rr$pct f.par2 $memarg"
    'parpar'      = "-q -s ${slice}b -r $pct% -o f.par2 $memarg"
    'rarpar'      = "par create --quiet -s $slice -r $pct f.par2 $memarg"
  }
  $vargv = @{
    'parfast'     = 'v -q -t12 -T16 f.par2'
    'par2turbo'   = 'v -q -t12 -T16 f.par2'
    'par2classic' = 'v -q f.par2'
    'phpar2'      = 'v -q f.par2'
    'par2j64'     = 'v f.par2'
    'rarpar'      = 'par verify --quiet f.par2'
  }
  $rargv = @{
    'parfast'     = 'r -q -t12 -T16 f.par2'
    'par2turbo'   = 'r -q -t12 -T16 f.par2'
    'par2classic' = 'r -q f.par2'
    'phpar2'      = 'r -q f.par2'
    'par2j64'     = 'r f.par2'
    'rarpar'      = 'par repair --quiet f.par2'
  }

  foreach ($rep in $reps) {
    # ---------------- CREATE, every tool writes into its own clean dir ----
    foreach ($tool in $creators) {
      # A CREATE BUDGET, which the predecessor had only for repairs. A 100%
      # create costs about 6.7x a 15% one, and projected from their own
      # measured shallow legs that is minutes for most tools and THREE AND A
      # HALF HOURS for phpar2 and par2cmdline. The skip carries its projection,
      # so a missing bar reads as "too slow to measure here" rather than as an
      # unexplained gap - which is the honest answer to why this chart does not
      # reach the ceiling.
      if ($createBudget -gt 0 -and $createRef -and $createRef.ContainsKey($tool)) {
        $proj = [double]$createRef[$tool] * ($pct / 15.0)
        if ($proj -gt $createBudget) {
          "SKIP round=$round rep=$rep phase=create tool=$tool projected_s=$([math]::Round($proj)) budget_s=$createBudget from_pct=15 from_wall=$($createRef[$tool]) reason=projected-over-budget"
          continue
        }
      }
      Remove-Item "$rig\work" -Recurse -Force -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path "$rig\work" | Out-Null
      foreach ($nm in $members) { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" }
      Read-Warm "$rig\work"
      $r = Invoke-Leg "$bin\$tool.exe" $cargv[$tool] "$rig\work" "$rig\logs\create-$tool-r$rep"
      $pf = @(Get-ChildItem "$rig\work" -Filter *.par2 -ErrorAction SilentlyContinue)
      $g = Test-RestoredFast "$rig\work" $members $gold
      "CREATE round=$round rep=$rep tool=$tool argv='$($cargv[$tool])' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) par2files=$($pf.Count) par2bytes=$((($pf|Measure-Object Length -Sum).Sum)) sources_intact=$($g.good)/$($members.Count) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
      if ($tool -eq 'parfast' -and $rep -eq 1 -and $r.rc -eq 0 -and $pf.Count -gt 0) {
        Remove-Item "$rig\set\*" -Force -ErrorAction SilentlyContinue
        foreach ($f in $pf) { Copy-Item $f.FullName "$rig\set\$($f.Name)" }
      }
    }

    $parfiles = @(Get-ChildItem "$rig\set" | ForEach-Object { $_.Name })
    if ($parfiles.Count -eq 0) { "FIELD-FAIL no parfast set to read"; Release-RigLock $lock; exit 9 }
    if ($rep -eq 1) { "SET files=$($parfiles.Count) bytes=$(((Get-ChildItem "$rig\set")|Measure-Object Length -Sum).Sum) written_by=parfast" }
    foreach ($nm in $parfiles) { Copy-Item "$rig\set\$nm" "$rig\pristine\$nm" -Force }

    # ------ VERIFY + REPAIR, every reader on the SAME parfast-written set --
    foreach ($tool in $readers) {
      Remove-Item "$rig\work" -Recurse -Force -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path "$rig\work" | Out-Null
      foreach ($nm in $members)  { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" }
      foreach ($nm in $parfiles) { Copy-Item "$rig\set\$nm" "$rig\work\$nm" }
      Read-Warm "$rig\work"

      $r = Invoke-Leg "$bin\$tool.exe" $vargv[$tool] "$rig\work" "$rig\logs\verify-$tool-r$rep"
      $g = Test-RestoredFast "$rig\work" $members $gold
      "VERIFY round=$round rep=$rep tool=$tool argv='$($vargv[$tool])' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) intact=$($g.good)/$($members.Count) foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
      $null = Remove-Strays "$rig\work" $members $parfiles

    }

    # ------ REPAIR, every reader, at every rung it can afford ---------------
    foreach ($rung in $rungList) {
      $dseed = 20260911 + $rung * 7 + $rep
      foreach ($tool in $readers) {
        # A tool past its own ceiling is not attempted, and the line says the
        # ceiling rather than a projection - the reason is policy, not cost.
        if ($toolMaxRung -and $toolMaxRung.ContainsKey($tool) -and $rung -gt $toolMaxRung[$tool]) {
          "SKIP round=$round rep=$rep m=$rung tool=$tool ceiling=$($toolMaxRung[$tool]) reason=past-this-tool-s-depth-ceiling"
          continue
        }
        if ($toolReps -and $toolReps.ContainsKey($tool) -and $rep -gt $toolReps[$tool]) {
          "SKIP round=$round rep=$rep m=$rung tool=$tool reps_allowed=$($toolReps[$tool]) reason=past-this-tool-s-repetition-count"
          continue
        }
        # Project this tool's cost at this rung from ITS OWN previous rung. A
        # tool that has not run yet is always attempted; one that has is
        # attempted only if the projection fits the budget. The skip carries
        # the projection, so the log says WHY a bar is missing rather than
        # leaving a reader to wonder whether the tool failed.
        $prev = $script:lastleg[$tool]
        if ($prev -and $prev.m -gt 0) {
          $proj = [double]$prev.wall * ($rung / [double]$prev.m)
          if ($proj -gt $budget) {
            "SKIP round=$round rep=$rep m=$rung tool=$tool projected_s=$([math]::Round($proj)) budget_s=$budget from_m=$($prev.m) from_wall=$($prev.wall) reason=projected-over-budget"
            continue
          }
        }
        Remove-Item "$rig\work" -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path "$rig\work" | Out-Null
        foreach ($nm in $members)  { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" }
        foreach ($nm in $parfiles) { Copy-Item "$rig\set\$nm" "$rig\work\$nm" }
        $picks = Get-DamagePicks "$rig\work" $members $slice $rung $dseed
        $wrote = Invoke-DamagePicks "$rig\work" $members $slice $picks $dseed
        Read-Warm "$rig\work"
        $r = Invoke-Leg "$bin\$tool.exe" $rargv[$tool] "$rig\work" "$rig\logs\repair-$tool-m$rung-r$rep"
        $good = 0; $missing = 0
        foreach ($nm in $members) {
          $pth = "$rig\work\$nm"
          if (-not (Test-Path $pth)) { $missing++; continue }
          if ((Get-Sha256Fast $pth) -eq $gold[$nm]) { $good++ }
        }
        $strays = Remove-Strays "$rig\work" $members $parfiles
        "REPAIR round=$round rep=$rep m=$rung tool=$tool argv='$($rargv[$tool])' blocks_written=$wrote touched_members=$($picks.bymember.Keys.Count) wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) restored=$good/$($members.Count) still_absent=$missing strays=$strays seed=$dseed foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
        if ($good -eq $members.Count) { $script:lastleg[$tool] = @{ m = $rung; wall = [double]$r.wall } }
      }
    }
    "FIELD-REP-END rep=$rep $((Get-Date).ToUniversalTime().ToString('o'))"
  }
  Remove-Item "$rig\work" -Recurse -Force -ErrorAction SilentlyContinue
  "FIELD-END $((Get-Date).ToUniversalTime().ToString('o'))"
}
finally { Release-RigLock $lock }
