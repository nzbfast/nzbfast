# full.ps1 - the FULL-RANGE i5 repair ladder: verify, then one lost block, all
# the way to a TOTAL loss.
#
# The 15% ladder measures a realistic release redundancy, but 15% parity caps
# the deepest possible repair at 2,098 of 13,990 blocks - a narrow window. This
# round is 100% parity over 32,177 source blocks, so m runs 1 to 32,177: the
# whole dynamic range PAR2 can express, four and a half orders of magnitude,
# ending with every single source block reconstructed. It still spans the
# recalibrated Forney gate (BACKSUB_MIN_MISSING_NIBBLE = 1,280 on this AVX2
# nibble kernel, landed f0df421ece), which now sits in the MIDDLE of the ladder
# rather than near its top.
#
# 32,177 is not an arbitrary top: 23 x 1 GiB at 750 KiB slices is the largest
# set that stays under PAR2's 32,768-slice cap, so this is the deepest single
# repair the format allows at this slice size.
#
# Payload: <rig>\pay-distinct, 10 x 1 GiB, every member generated from its
# own seeded stream. Verified here and independently before this round: 1,399
# unique slice hashes WITHIN each member and 10 unique hashes across members at
# every probe. The round it replaces ran on ten near-copies where 1,398 of each
# member's 1,399 slices were byte-identical across members, so both tools
# ADOPTED blocks instead of reconstructing them.
#
# TWO CHANGES from the 15% ladders, both forced by their own data.
#
# A WARM-UP PASS, DISCARDED. Across the banked ladders, repetition 1 is
# systematically slower than repetition 2 - and only on the boxes where the set
# does not sit comfortably in page cache: parfast summed 1.66x slower over the
# first four rungs on this i5, 1.30x on the VPS, 1.14x on the 31 GB coreultra9,
# against 0.96-1.00x on the 128 and 256 GB Apple boxes, which are flat. Two
# repetitions then average a cold reading with a warm one, and a median of two
# IS that average, so it cannot discard the outlier. The round now runs an
# untimed pass first, and timing starts on a settled box.
#
# REPETITIONS ESCALATE ON NOISE, rather than by a fixed schedule. The spread is
# concentrated exactly where legs are cheap - the small-m rungs, which are
# bound by reading the set rather than by arithmetic - and the expensive rungs
# are the quiet ones (the M3 full-range round has NO rung above 8% spread). So
# a rung whose repetitions disagree by 10% or more is repeated again, up to
# five times, while its legs stay under two minutes. That spends repetitions
# where the noise actually is instead of doubling the cost of a 19-minute leg
# to confirm a number that was never in doubt.
#
# Every timing is a CLI timing. parfast and par2turbo are given IDENTICAL argv.
# par2j64 gets its own dialect's equivalent, at its own defaults, and a /lc
# control arm at the end says what its default threading left on the table.
. <rig>\pub\plib.ps1

$bin   = '<rig>\bin'
$pay   = '<rig>\pay23'
$rig   = '<rig>\full'
$lock  = '<rig>\full.lock'
$slice = 768000        # 750 KiB
$rblk  = 32177         # 100% parity over 32,177 source blocks
$tools = @('parfast','par2turbo','par2j64')
$rungs = @(1,4,16,64,256,1024,2048,4096,8192,16384,24576,32177)
$reps  = @(1,2)
$maxreps = 5          # ceiling for the noise escalation below
$noisepct = 10.0      # escalate a rung whose reps disagree by this much
$noisecap = 120.0     # ...but only while a leg is cheap enough to repeat
$argv  = @{
  'parfast'   = 'r -q -t12 -T12 f.par2'
  'par2turbo' = 'r -q -t12 -T12 f.par2'
  'par2j64'   = 'r f.par2'
}
$vargv = @{
  'parfast'   = 'v -q -t12 -T12 f.par2'
  'par2turbo' = 'v -q -t12 -T12 f.par2'
  'par2j64'   = 'v f.par2'
}

New-Item -ItemType Directory -Force -Path '<rig>' | Out-Null
Take-RigLock $lock
try {
  "FULL-START $((Get-Date).ToUniversalTime().ToString('o'))"
  Write-BoxFacts
  Write-BinFacts $bin $tools
  "PROTOCOL slice=$slice recovery_blocks=$rblk source_blocks=32177 redundancy_pct=100.0 damage=scattered-seeded-slice-overwrite reps=2 gate=sha256-all-members prewarm=full-read-of-work-dir"
  "ARGV parfast='$($argv['parfast'])' par2turbo='$($argv['par2turbo'])' par2j64='$($argv['par2j64'])'"

  # ---- payload ---------------------------------------------------------
  # Same generator and the same seed formula as the 10-member payload, so
  # p00..p09 here are byte-identical to the 15% round's members and the two
  # ladders share a fixture lineage. Built in its OWN directory so the 10 GiB
  # rounds, which enumerate *.bin, keep seeing exactly ten members.
  New-Item -ItemType Directory -Force -Path $pay | Out-Null
  for ($i = 0; $i -lt 23; $i++) {
    $f = '{0}\p{1:d2}.bin' -f $pay, $i
    if ((Test-Path $f) -and ((Get-Item $f).Length -eq 1073741824)) { continue }
    $buf = New-Object byte[] (64MB)
    $rng = New-Object Random(20260910 + $i * 7919)
    $fs = [IO.File]::Create($f)
    for ($k = 0; $k -lt 16; $k++) { $rng.NextBytes($buf); $fs.Write($buf, 0, $buf.Length) }
    $fs.Close()
  }
  "PAYLOAD-READY members=$(@(Get-ChildItem $pay -Filter *.bin).Count) bytes=$(((Get-ChildItem $pay -Filter *.bin)|Measure-Object Length -Sum).Sum)"

  # ---- fixture ---------------------------------------------------------
  Remove-Item $rig -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path "$rig\pristine","$rig\work","$rig\logs" | Out-Null
  $members = @(Get-ChildItem $pay -Filter *.bin | Sort-Object Name | ForEach-Object { $_.Name })
  if ($members.Count -ne 23) { "FULL-FAIL payload has $($members.Count) members"; Release-RigLock $lock; exit 9 }
  foreach ($nm in $members) { Copy-Item "$pay\$nm" "$rig\pristine\$nm" }
  $gold = @{}
  foreach ($nm in $members) { $gold[$nm] = Get-Sha256Fast "$rig\pristine\$nm" }
  $uniq = ($gold.Values | Sort-Object -Unique).Count
  "FIXTURE members=$($members.Count) distinct_member_sha=$uniq/$($members.Count) bytes=$(((Get-ChildItem "$rig\pristine" -Filter *.bin)|Measure-Object Length -Sum).Sum)"
  if ($uniq -ne $members.Count) { "FULL-FAIL payload members not distinct"; Release-RigLock $lock; exit 9 }
  $probe = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($nm in $members) {
    $fs = [IO.File]::OpenRead("$rig\pristine\$nm"); $null = $fs.Seek([int64]5 * $slice, 'Begin')
    $b = New-Object byte[] $slice; $null = $fs.Read($b, 0, $slice); $fs.Close()
    $null = $probe.Add([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)))
  }
  "SLICE-PROBE index=5 unique=$($probe.Count)/$($members.Count)"
  if ($probe.Count -ne $members.Count) { "FULL-FAIL payload is near-copies"; Release-RigLock $lock; exit 9 }
  foreach ($nm in $members) { "GOLD $nm $($gold[$nm])" }

  # the set both rivals read is written by parfast, which doubles as proof the
  # rivals accept our output
  $memarg = ($members -join ' ')
  $cr = Invoke-Leg "$bin\parfast.exe" "c -q -t12 -T12 -s$slice -c$rblk f.par2 $memarg" "$rig\pristine" "$rig\logs\create-parfast"
  $pf = @(Get-ChildItem "$rig\pristine" -Filter *.par2)
  "CREATE tool=parfast rc=$($cr.rc) wall=$($cr.wall) cpu=$($cr.cpu) peak_mb=$($cr.peakmb) par2files=$($pf.Count) par2mb=$([math]::Round((($pf|Measure-Object Length -Sum).Sum)/1MB,1)) errlen=$($cr.errlen)"
  if ($cr.rc -ne 0 -or $pf.Count -eq 0) { "FULL-FAIL create rc=$($cr.rc)"; Release-RigLock $lock; exit 9 }
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
    "LEG round=i5full rep=$rep m=$rung tool=$tool argv='$targv' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) restored=$($post.good)/$($members.Count) damaged_members=$($members.Count - $pre.good) touched_members=$touched blocks_written=$wrote strays=$strays seed=$dseed foreign_cpu=$($r.foreign) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    # undo: write the damaged slices back, then re-gate and fall back to a full
    # member copy for anything the pick list did not account for
    Restore-Slices "$rig\work" "$rig\pristine" $members $slice $picks
    $chk = Test-RestoredFast "$rig\work" $members $gold
    if ($chk.good -ne $members.Count) {
      foreach ($nm in $chk.bad) { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" -Force }
      $chk2 = Test-RestoredFast "$rig\work" $members $gold
      "RESET rep=$rep m=$rung tool=$tool slice_restore_left=$($members.Count - $chk.good) after_full_copy=$($chk2.good)/$($members.Count)"
      if ($chk2.good -ne $members.Count) { "FULL-FAIL work dir unrecoverable"; Release-RigLock $lock; exit 9 }
    }
    foreach ($nm in $parfiles) { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" -Force }
    # NOT `return $r.wall`. Every log line in this function is written to the
    # OUTPUT stream, which the caller redirects into the round log, so a return
    # value would be captured together with the LEG lines - emptying the log and
    # handing the caller an array instead of a number. A script-scope slot keeps
    # the log stream pure.
    $script:lastwall = [double]$r.wall
  }

  # ---- untimed warm-up -------------------------------------------------
  # Two cheap rungs per tool, discarded. This is what settles the page cache
  # and drains the write-back left by CREATE, which is what made repetition 1
  # slow on every memory-constrained box.
  "WARMUP-START $((Get-Date).ToUniversalTime().ToString('o'))"
  foreach ($wrung in @(1,64)) {
    foreach ($tool in $tools) {
      Run-Rung $tool $wrung 0 (20260910 + $wrung * 7) "warm-m$wrung-$tool" $argv[$tool]
    }
  }
  "WARMUP-END $((Get-Date).ToUniversalTime().ToString('o'))"

  $walls = @{}
  foreach ($rep in $reps) {
    foreach ($tool in $tools) {
      # FULL warm here, unlike a repair leg. A repair leg is preceded by the
      # pre-damage gate, which reads every member and so warms them; a verify
      # leg has no gate before it, so warming only the recovery set would run
      # the FIRST tool of each rep cold and the other two warm.
      Read-Warm "$rig\work"
      $r = Invoke-Leg "$bin\$tool.exe" $vargv[$tool] "$rig\work" "$rig\logs\verify-$tool-r$rep"
      $g = Test-RestoredFast "$rig\work" $members $gold
      "VERIFY round=i5full rep=$rep tool=$tool argv='$($vargv[$tool])' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) intact=$($g.good)/$($members.Count) foreign_cpu=$($r.foreign) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
      $null = Remove-Strays "$rig\work" $members $parfiles
    }
    foreach ($rung in $rungs) {
      $dseed = 20260910 + $rung * 7 + $rep     # identical damage for all three tools
      foreach ($tool in $tools) {
        Run-Rung $tool $rung $rep $dseed "r$rep-m$rung-$tool" $argv[$tool]
        $w = $script:lastwall
        $k = "$rung|$tool"
        if (-not $walls.ContainsKey($k)) { $walls[$k] = @() }
        $walls[$k] += $w
      }
    }
    "FULL-REP-END rep=$rep $((Get-Date).ToUniversalTime().ToString('o'))"
  }

  # ---- escalate the noisy rungs ----------------------------------------
  # A rung is repeated again when its repetitions disagree by $noisepct or more
  # AND its legs are still cheap. All tools are repeated together at a rung, so
  # the comparison at that rung keeps the same number of samples per tool.
  $rep = [int]($reps[-1])
  while ($rep -lt $maxreps) {
    $noisy = @()
    foreach ($rung in $rungs) {
      foreach ($tool in $tools) {
        $w = $walls["$rung|$tool"]
        if (-not $w -or $w.Count -lt 2) { continue }
        $lo = ($w | Measure-Object -Minimum).Minimum
        $hi = ($w | Measure-Object -Maximum).Maximum
        if ($lo -le 0) { continue }
        $spread = ($hi - $lo) / $lo * 100.0
        if ($spread -ge $noisepct -and $hi -le $noisecap -and $noisy -notcontains $rung) { $noisy += $rung }
      }
    }
    if ($noisy.Count -eq 0) { "NOISE-SETTLED after rep=$rep"; break }
    $rep++
    "NOISE-ESCALATE rep=$rep rungs=$($noisy -join ',') $((Get-Date).ToUniversalTime().ToString('o'))"
    foreach ($rung in $noisy) {
      $dseed = 20260910 + $rung * 7 + $rep
      foreach ($tool in $tools) {
        Run-Rung $tool $rung $rep $dseed "r$rep-m$rung-$tool" $argv[$tool]
        $walls["$rung|$tool"] += $script:lastwall
      }
    }
  }

  "FULL-END $((Get-Date).ToUniversalTime().ToString('o'))"
}
finally { Release-RigLock $lock }
