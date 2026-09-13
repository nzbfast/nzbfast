# wfast.ps1 - the FAST MODE A/B at DEPTH, on x86.
#
# `--fast` arms the joint Forney solver, default OFF. The other lane measures it
# as a wash below about m = 8,000 and worth 25-40% of the whole wall by
# m = 16,000-20,000, so a ladder that stops at 2,098 sees nothing. This one runs
# 100% parity over 32,177 source blocks and reaches m = 32,177: every source
# block reconstructed.
#
# TWO ARMS OF THE SAME BINARY, interleaved per rung and per rep, so nothing can
# differ but the switch and no drift in the box can masquerade as an effect.
#
# THE FIXTURE IS -s768000 ON PURPOSE. The joint arm's stage 1 needs a block size
# that is a multiple of 32 BYTES; PAR2 requires only 4, and parfast's own default
# create picks a block COUNT and searches in steps of four, so it lands on a
# 32-multiple about one time in eight. 768,000 is aligned, and 23 x 1 GiB at that
# slice is 32,177 blocks - just inside PAR2's 32,768 cap, which makes it the
# largest standard set that keeps the arm ARMED.
#
# AND EVERY LEG IS CREDITED FROM ITS OWN STAGE-1 LABEL, not assumed. When the
# geometry is refused the arm silently runs the shipped arithmetic and says so
# only there:
#     forney stage 1 (joint whole/demand, stripe 256w, FALLBACK arithmetic): ...
# A parser that trims at the first comma reads that as a joint leg; that is how
# the other lane's first 24-leg A/B measured the wrong thing. NZBFAST_REPAIR_TIMING
# is set on BOTH arms so the label exists and the arms stay symmetric.: verify, then one lost block, all
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
# Every timing is a CLI timing. parfast and par2turbo are given IDENTICAL argv.
# par2j64 gets its own dialect's equivalent, at its own defaults, and a /lc
# control arm at the end says what its default threading left on the table.
. <rig>\plib.ps1

$bin   = '<rig>\bin'
$pay   = '<rig>\pay23'
$rig   = '<rig>\fastrig'
$lock  = '<rig>\wfast.lock'
$slice = 768000        # 750 KiB
$rblk  = 32177         # 100% parity over 32,177 source blocks
$tools = @('off','on')
$exe   = '<rig>\bin\parfast-joint.exe'
$envboth = @{ NZBFAST_REPAIR_TIMING = '1' }
# The 'off' arm is the CONTROL and must be off by construction, not by trusting
# the binary's default. Since 9856e25f19 the joint solve is the DEFAULT on
# KernelClass::Avx512Gfni, so on such a part a bare parfast IS the on arm and
# this A/B would quietly become an A/A reporting a dead heat. This box is
# Gfni256 and these binaries predate the flip, so it changes nothing here today;
# it is the arm's definition, not a workaround.
$envArm = @{ 'off' = @{ NZBFAST_FORNEY_JOINT = '0' } }
function Env-For([string]$tool) {
  $h = @{}; foreach ($k in $envboth.Keys) { $h[$k] = $envboth[$k] }
  if ($envArm.ContainsKey($tool)) { foreach ($k in $envArm[$tool].Keys) { $h[$k] = $envArm[$tool][$k] } }
  return $h
}
$rungs = @(4096,8192,16384,24576,32177)   # 4096 is the control BELOW the paying band
$reps  = @(1,2)
$argv  = @{ 'off' = "r -q -t16 -T16 f.par2"; 'on' = "r -q -t16 -T16 --fast f.par2" }
$vargv = @{ 'off' = "v -q -t16 -T16 f.par2"; 'on' = "v -q -t16 -T16 f.par2" }

New-Item -ItemType Directory -Force -Path '<rig>' | Out-Null
Take-RigLock $lock
try {
  "WFAST-START $((Get-Date).ToUniversalTime().ToString('o'))"
  Write-BoxFacts
  Write-BinFacts (Split-Path $exe -Parent) @([IO.Path]::GetFileNameWithoutExtension($exe))
  # The HARNESS's own provenance, not just the binary's, and the round-start
  # twin of the per-leg `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath
  # is THIS driver; plib.ps1 adds itself. A parfast round has no other evidence
  # of a harness that changed under it mid-round.
  Write-HarnessFacts @($PSCommandPath)
  "PROTOCOL slice=$slice recovery_blocks=$rblk source_blocks=32177 redundancy_pct=100.0 damage=scattered-seeded-slice-overwrite reps=$($reps.Count) gate=sha256-all-members arms=off/on interleaved=per-rung-per-rep"
  "ARGV off='$($argv['off'])' on='$($argv['on'])' env=NZBFAST_REPAIR_TIMING=1 (both arms) env_off=NZBFAST_FORNEY_JOINT=0 (control pinned off, not defaulted)"

  # ---- payload ---------------------------------------------------------
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
  if ($members.Count -ne 23) { "WFAST-FAIL payload has $($members.Count) members"; Release-RigLock $lock; exit 9 }
  foreach ($nm in $members) { Copy-Item "$pay\$nm" "$rig\pristine\$nm" }
  $gold = @{}
  foreach ($nm in $members) { $gold[$nm] = Get-Sha256Fast "$rig\pristine\$nm" }
  $uniq = ($gold.Values | Sort-Object -Unique).Count
  "FIXTURE members=$($members.Count) distinct_member_sha=$uniq/$($members.Count) bytes=$(((Get-ChildItem "$rig\pristine" -Filter *.bin)|Measure-Object Length -Sum).Sum)"
  if ($uniq -ne $members.Count) { "WFAST-FAIL payload members not distinct"; Release-RigLock $lock; exit 9 }
  $probe = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($nm in $members) {
    $fs = [IO.File]::OpenRead("$rig\pristine\$nm"); $null = $fs.Seek([int64]5 * $slice, 'Begin')
    $b = New-Object byte[] $slice; $null = $fs.Read($b, 0, $slice); $fs.Close()
    $null = $probe.Add([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)))
  }
  "SLICE-PROBE index=5 unique=$($probe.Count)/$($members.Count)"
  if ($probe.Count -ne $members.Count) { "WFAST-FAIL payload is near-copies"; Release-RigLock $lock; exit 9 }
  foreach ($nm in $members) { "GOLD $nm $($gold[$nm])" }

  # the set both rivals read is written by parfast, which doubles as proof the
  # rivals accept our output
  $memarg = ($members -join ' ')
  $cr = Invoke-Leg $exe "c -q -t16 -T16 -s$slice -c$rblk f.par2 $memarg" "$rig\pristine" "$rig\logs\create-parfast"
  $pf = @(Get-ChildItem "$rig\pristine" -Filter *.par2)
  "CREATE tool=parfast rc=$($cr.rc) wall=$($cr.wall) cpu=$($cr.cpu) peak_mb=$($cr.peakmb) par2files=$($pf.Count) par2mb=$([math]::Round((($pf|Measure-Object Length -Sum).Sum)/1MB,1)) errlen=$($cr.errlen)"
  if ($cr.rc -ne 0 -or $pf.Count -eq 0) { "WFAST-FAIL create rc=$($cr.rc)"; Release-RigLock $lock; exit 9 }
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
    $r = Invoke-Leg $exe $targv "$rig\work" "$rig\logs\$tag" (Env-For $tool)
    $post = Test-RestoredFast "$rig\work" $members $gold
    $strays = Remove-Strays "$rig\work" $members $parfiles
    $lbl = @(Select-String -Path "$rig\logs\$tag.out","$rig\logs\$tag.err" -Pattern 'forney stage 1 \(joint' -EA SilentlyContinue | ForEach-Object { $_.Line })
    $armed = if ($lbl -match 'FALLBACK') { 'FALLBACK' } elseif ($lbl) { 'joint' } else { 'no-label' }
    "LEG round=wfast rep=$rep m=$rung tool=$tool argv='$targv' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) restored=$($post.good)/$($members.Count) damaged_members=$($members.Count - $pre.good) touched_members=$touched blocks_written=$wrote strays=$strays stage1=$armed seed=$dseed errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o')) rig=$((Get-RigStamp) -join '')"
    # undo: write the damaged slices back, then re-gate and fall back to a full
    # member copy for anything the pick list did not account for
    Restore-Slices "$rig\work" "$rig\pristine" $members $slice $picks
    $chk = Test-RestoredFast "$rig\work" $members $gold
    if ($chk.good -ne $members.Count) {
      foreach ($nm in $chk.bad) { Copy-Item "$rig\pristine\$nm" "$rig\work\$nm" -Force }
      $chk2 = Test-RestoredFast "$rig\work" $members $gold
      "RESET rep=$rep m=$rung tool=$tool slice_restore_left=$($members.Count - $chk.good) after_full_copy=$($chk2.good)/$($members.Count)"
      if ($chk2.good -ne $members.Count) { "WFAST-FAIL work dir unrecoverable"; Release-RigLock $lock; exit 9 }
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
      $r = Invoke-Leg $exe $vargv[$tool] "$rig\work" "$rig\logs\verify-$tool-r$rep" (Env-For $tool)
      $g = Test-RestoredFast "$rig\work" $members $gold
      "VERIFY round=wfast rep=$rep tool=$tool argv='$($vargv[$tool])' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) intact=$($g.good)/$($members.Count) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o')) rig=$((Get-RigStamp) -join '')"
      $null = Remove-Strays "$rig\work" $members $parfiles
    }
    foreach ($rung in $rungs) {
      $dseed = 20260910 + $rung * 7 + $rep     # identical damage for all three tools
      foreach ($tool in $tools) {
        Run-Rung $tool $rung $rep $dseed "r$rep-m$rung-$tool" $argv[$tool]
      }
    }
    "WFAST-REP-END rep=$rep $((Get-Date).ToUniversalTime().ToString('o'))"
  }

  "WFAST-END $((Get-Date).ToUniversalTime().ToString('o'))"
}
finally { Release-RigLock $lock }
