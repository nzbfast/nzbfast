# lad2.ps1 - the i5 15% ladder AGAIN, on a quiet box, three repetitions.
#
# The first run (lad.ps1, 10 Sep) carried two things a reader would seize on:
# a first repetition that ran cold on every tool (16 and 64 blocks at +-77% and
# +-119%), and a six-leg par2j thread-count probe at 1,024 blocks with other
# command lines, tagged rep=9, which the page's extract now refuses. This copy
# drops the probe, takes the box's shared rig lock rather than a private one,
# runs three repetitions with the same argv as before so it is comparable leg
# for leg, and is started by wquiet.ps1 only after the box has been idle and
# quiet for a stated stretch. Nothing else differs.
# lad.ps1 - ROUND 1, the i5 CLI repair ladder on DISTINCT data.
#
# The conservative box and the lead architecture. Rungs span both sides of the
# recalibrated Forney gate (BACKSUB_MIN_MISSING_NIBBLE = 1,280 on this AVX2
# nibble kernel, landed f0df421ece), from a single lost block to the parity
# ceiling.
#
# Payload: <rig>\pay-distinct, 10 x 1 GiB, every member generated from its
# own seeded stream. Verified here and independently before this round: 1,399
# unique slice hashes WITHIN each member and 10 unique hashes across members at
# every probe. The round it replaces ran on ten near-copies where 1,398 of each
# member's 1,399 slices were byte-identical across members, so both tools
# ADOPTED blocks instead of reconstructing them.
#
# Every timing is a CLI timing. parfast and par2turbo are given IDENTICAL argv.
# par2j64 gets its own dialect's equivalent, at its own defaults, and a /lc
# control arm at the end says what its default threading left on the table.
. <rig>\plib.ps1

$bin   = '<rig>\bin'
$pay   = '<rig>\pay-distinct'
$rig   = '<rig>\lad2'
$lock  = Join-Path $env:USERPROFILE '.parfast-rig.lock'   # the box's ONE lock, shared with every other round
$slice = 768000        # 750 KiB
$rblk  = 2098          # 14.996% of 13,990 source blocks
$tools = @('parfast','par2turbo','par2j64')
$rungs = @(1,16,64,256,512,768,1024,1152,1280,1408,1600,1792,2048,2098)
$reps  = @(1,2,3)
$argv  = @{
  'parfast'   = 'r -q -t12 -T16 f.par2'
  'par2turbo' = 'r -q -t12 -T16 f.par2'
  'par2j64'   = 'r f.par2'
}
$vargv = @{
  'parfast'   = 'v -q -t12 -T16 f.par2'
  'par2turbo' = 'v -q -t12 -T16 f.par2'
  'par2j64'   = 'v f.par2'
}

New-Item -ItemType Directory -Force -Path '<rig>' | Out-Null
Take-RigLock 'lad2'   # the ROUND's name, not $lock: see plib.ps1's Take-RigLock
try {
  "LAD2-START $((Get-Date).ToUniversalTime().ToString('o'))"
  Write-BoxFacts
  Write-BinFacts $bin $tools
  # The HARNESS's own provenance, and the round-start twin of the per-leg
  # `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath is THIS driver;
  # plib.ps1 adds itself. Without it a banked log cannot be traced to the
  # harness revision that wrote it (census
  # an internal note).
  Write-HarnessFacts @($PSCommandPath)
  "PROTOCOL slice=$slice recovery_blocks=$rblk source_blocks=13990 redundancy_pct=14.996 damage=scattered-seeded-slice-overwrite reps=3 gate=sha256-all-members prewarm=full-read-of-work-dir"
  "ARGV parfast='$($argv['parfast'])' par2turbo='$($argv['par2turbo'])' par2j64='$($argv['par2j64'])'"

  # ---- fixture ---------------------------------------------------------
  Remove-Item $rig -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path "$rig\pristine","$rig\work","$rig\logs" | Out-Null
  $members = @(Get-ChildItem $pay -Filter *.bin | Sort-Object Name | ForEach-Object { $_.Name })
  if ($members.Count -ne 10) { "LAD-FAIL payload has $($members.Count) members"; Release-RigLock $lock; exit 9 }
  foreach ($nm in $members) { Copy-Item "$pay\$nm" "$rig\pristine\$nm" }
  $gold = @{}
  foreach ($nm in $members) { $gold[$nm] = Get-Sha256Fast "$rig\pristine\$nm" }
  $uniq = ($gold.Values | Sort-Object -Unique).Count
  "FIXTURE members=$($members.Count) distinct_member_sha=$uniq/$($members.Count) bytes=$(((Get-ChildItem "$rig\pristine" -Filter *.bin)|Measure-Object Length -Sum).Sum)"
  if ($uniq -ne $members.Count) { "LAD-FAIL payload members not distinct"; Release-RigLock $lock; exit 9 }
  foreach ($nm in $members) { "GOLD $nm $($gold[$nm])" }

  # the set both rivals read is written by parfast, which doubles as proof the
  # rivals accept our output
  $memarg = ($members -join ' ')
  $cr = Invoke-Leg "$bin\parfast.exe" "c -q -t12 -T16 -s$slice -c$rblk f.par2 $memarg" "$rig\pristine" "$rig\logs\create-parfast"
  $pf = @(Get-ChildItem "$rig\pristine" -Filter *.par2)
  "CREATE tool=parfast rc=$($cr.rc) wall=$($cr.wall) cpu=$($cr.cpu) peak_mb=$($cr.peakmb) par2files=$($pf.Count) par2mb=$([math]::Round((($pf|Measure-Object Length -Sum).Sum)/1MB,1)) errlen=$($cr.errlen)"
  if ($cr.rc -ne 0 -or $pf.Count -eq 0) { "LAD-FAIL create rc=$($cr.rc)"; Release-RigLock $lock; exit 9 }
  $parfiles = @($pf | ForEach-Object { $_.Name })
  foreach ($nm in $members)  { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" }
  foreach ($nm in $parfiles) { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" }

  # ---- one leg, fully gated -------------------------------------------
  function Run-Rung {
    param([string]$tool, [int]$rung, [int]$rep, [int]$dseed, [string]$tag, [string]$targv)
    Read-Warm "$rig\work" $parfiles
    $picks = Get-DamagePicks "$rig\work" $members $slice $rung $dseed
    $wrote = Invoke-DamagePicks "$rig\work" $members $slice $picks $dseed
    $touched = $picks.bymember.Keys.Count
    $pre = Test-RestoredFast "$rig\work" $members $gold
    $r = Invoke-Leg "$bin\$tool.exe" $targv "$rig\work" "$rig\logs\$tag"
    $post = Test-RestoredFast "$rig\work" $members $gold
    $strays = Remove-Strays "$rig\work" $members $parfiles
    "LEG round=i5lad2 rep=$rep m=$rung tool=$tool argv='$targv' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) restored=$($post.good)/$($members.Count) damaged_members=$($members.Count - $pre.good) touched_members=$touched blocks_written=$wrote strays=$strays seed=$dseed foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    # undo: write the damaged slices back, then re-gate and fall back to a full
    # member copy for anything the pick list did not account for
    Restore-Slices "$rig\work" "$rig\pristine" $members $slice $picks
    $chk = Test-RestoredFast "$rig\work" $members $gold
    if ($chk.good -ne $members.Count) {
      foreach ($nm in $chk.bad) { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" -Force }
      $chk2 = Test-RestoredFast "$rig\work" $members $gold
      "RESET rep=$rep m=$rung tool=$tool slice_restore_left=$($members.Count - $chk.good) after_full_copy=$($chk2.good)/$($members.Count)"
      if ($chk2.good -ne $members.Count) { "LAD-FAIL work dir unrecoverable"; Release-RigLock $lock; exit 9 }
    }
    foreach ($nm in $parfiles) { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" -Force }
  }

  foreach ($rep in $reps) {
    foreach ($tool in $tools) {
      # FULL warm here, unlike a repair leg. A repair leg is preceded by the
      # pre-damage gate, which reads every member and so warms them; a verify
      # leg has no gate before it, so warming only the recovery set would run
      # the FIRST tool of each rep cold and the other two warm.
      Read-Warm "$rig\work"
      $r = Invoke-Leg "$bin\$tool.exe" $vargv[$tool] "$rig\work" "$rig\logs\verify-$tool-r$rep"
      $g = Test-RestoredFast "$rig\work" $members $gold
      "VERIFY round=i5lad2 rep=$rep tool=$tool argv='$($vargv[$tool])' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) intact=$($g.good)/$($members.Count) foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
      $null = Remove-Strays "$rig\work" $members $parfiles
    }
    foreach ($rung in $rungs) {
      $dseed = 20260910 + $rung * 7 + $rep     # identical damage for all three tools
      foreach ($tool in $tools) {
        Run-Rung $tool $rung $rep $dseed "r$rep-m$rung-$tool" $argv[$tool]
      }
    }
    "LAD2-REP-END rep=$rep $((Get-Date).ToUniversalTime().ToString('o'))"
  }

  # ---- par2j threading control, so "you crippled par2j" has an answer ---

  "LAD2-END $((Get-Date).ToUniversalTime().ToString('o'))"
}
finally { Release-RigLock $lock }
