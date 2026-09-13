# full.ps1 - the FULL-RANGE i5 repair ladder: verify, then one lost block, all
# the way to a TOTAL loss.
#
# The 15% ladder measures a realistic release redundancy, but 15% parity caps
# the deepest possible repair at 2,098 of 13,990 blocks - a narrow window. This
# round is 100% parity over 32,177 source blocks, so m runs 1 to 32,177: the
# whole dynamic range PAR2 can express, four and a half orders of magnitude,
# ending with every single source block reconstructed. It still spans the
# recalibrated Forney gate (BACKSUB_MIN_MISSING_NIBBLE = 1,280 on this kernel, landed f0df421ece), which now sits in the MIDDLE of the ladder
# rather than near its top.
#
# 32,177 is not an arbitrary top: 23 x 1 GiB at 750 KiB slices is the largest
# set that stays under PAR2's 32,768-slice cap, so this is the deepest single
# repair the format allows at this slice size.
#
# Payload: <rig>\pay23, 10 x 1 GiB, every member generated from its
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
# first four rungs on this i5, 1.30x on the VPS, 1.14x on the 31 GB zenbook,
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
. <rig>\plib.ps1

$bin   = '<rig>\bin'
$pay   = '<rig>\pay23'
$rig   = '<rig>\gfni'
$lock  = '<rig>\gfni.lock'
$slice = 768000        # 750 KiB
$rblk  = 32177         # 100% parity over 32,177 source blocks
# FOUR arms, and the arm table was WRONG until 11 Sep 2026. What changed is
# not the question but which PAIRS can answer it, and the reason is one
# predicate in gf16.rs that this round's author had not read carefully enough.
#
# `NZBFAST_GF16_ROWOP_GFNI` GATES TWO THINGS ON X86, NOT ONE. Its stated job is
# the fused butterfly. But `inplace_scale_preferred()` also reads it:
#
#     #[cfg(target_arch = "x86_64")]
#     if gfni256_available() && !gfni_rowop_armed() { return false; }
#
# so arming the variable ALSO switches par2ntt's additive leaf from folding
# through a zeroed temporary to scaling in place. On a GFNI part the variable
# therefore moves the butterfly AND the leaf together.
#
# That is fatal to the round's original `fastgate` arm. It was `--fast` plus
# the variable, paired against `base`, and its header line claimed to measure
# "the row-op flip". It moved THREE things at once: the joint solve, the
# butterfly and the leaf. Pairing it against `fast` instead would have removed
# the joint solve and still left two. There was no pair in the old four-arm
# table that isolated the butterfly, and the round would have reported a number
# for a question it could not ask.
#
# The clean isolation exists, and it is on the LEAF binary rather than main's.
# `pf-leaf` is built from 3667a696d50b, which DELETES that x86 arm, so on that
# binary `inplace_scale_preferred()` is true whatever the variable says - and
# the variable is then left gating the butterfly alone. Hence:
#
#   base      pf-base  (e0b44df99c31, origin/main)   no switch, JOINT=0
#   basegate  pf-base                                no switch, JOINT=0, ROWOP=1
#   leaf      pf-leaf  (3667a696d50b, branch)        no switch, JOINT=0
#   leafgate  pf-leaf                                no switch, JOINT=0, ROWOP=1
#
#   base vs leaf          - par2ntt's additive leaf, in place against folded
#                           through a temporary. BOTH RUN WITH NO SWITCH, and
#                           that is the whole point: the leaf is on every
#                           create and every repair and is reached by no flag
#                           at all.
#   leaf vs leafgate      - the fused butterfly, ALONE. Same binary, same
#                           switch, one variable apart, and on THIS binary that
#                           variable has only one consumer left.
#   basegate vs leafgate  - AN A/A, AND IT IS THE ONE ARM THAT CHECKS THE
#                           REASONING ABOVE. With the variable armed,
#                           inplace_scale_preferred() is true on pf-base too,
#                           so the predicate pf-leaf deletes is UNREACHABLE and
#                           the two binaries must behave identically. If these
#                           two walls agree within the spread, the model of
#                           what the variable gates is confirmed END TO END; if
#                           they do not, the model is wrong and every other
#                           pair in this round is void.
#
# NOTHING IN THE ENGINE PRINTS WHICH LEAF ARM A LEG TOOK. There is no
# diagnostic for inplace_scale_preferred() the way NZBFAST_REPAIR_TIMING names
# the Forney stages, so every other pair here ASSERTS its arm from the binary
# stamp and the environment rather than observing it. That is precisely the
# defect that cost the crossover lane the baseline column of a 405-leg round,
# and the A/A above is the nearest thing to an observation available without
# changing the engine: it is an A/A only if the assertion is true. Treat a
# basegate-vs-leafgate disagreement as a finding about the ROUND, not about
# the kernels.
#
# The old `fast` arm is gone too, and that one is a clean supersession rather
# than a defect: jcross.ps1 runs base-against---fast on this same box at
# fourteen rungs with an A/A at every one, where this round had two rungs and
# no floor. Nothing is lost by deleting it here and the round gets a quarter
# cheaper.
#
# WHAT HAPPENS TO THE RESULT:
#   If leaf WINS or ties, the change that lands is the deletion of
#   inplace_scale_preferred()'s x86 arm, made on MAIN and citing this round at
#   the site - the docstring there ends "When a quotable GFNI box has measured
#   the leaf, delete the x86 arm below", so this pair is the single thing that
#   discharges that debt. NOT a merge of the measurement branch, whose commit
#   says DO NOT MERGE and would drag that into main's history.
#   If leaf LOSES, that is a FINDING and it gets written up as one. "We tried
#   the in-place leaf on a GFNI part and it lost" is worth more than silence:
#   without it the next lane re-derives the same experiment from the same
#   docstring.
#
# THIS ROUND IS NOT TRYING TO REPRODUCE THE EPYC RESULT.
#
# The lane that built these binaries measured its arms on a shared VM that this
# campaign withdrew from quotation, and said so unprompted. If this box orders
# the arms differently, that is a FINDING and lands as one - one architecture
# cannot answer a two-architecture question, and a branch that does not merge
# because a second box disagreed is a good outcome. The bad outcome is a merge
# decided on one machine. So: report what this box says, in the order this box
# says it, and do not reach for an explanation of a disagreement.
#
# ALL FOUR ARMS COME FROM ONE MATCHED PAIR, and turbo is deliberately absent.
# The pair was cross-built on one Mac, same toolchain, same flags, same hour,
# ONE PREDICATE APART - so the toolchain cancels and what is left is the change.
# Racing either against the MSVC par2turbo already on this box would measure the
# toolchain as well, which is not the question this round asks. The parfast vs
# turbo comparison lives in the full-range round, on that box's own binaries.
#
# No absolute from this round may reach a published table: within-round A/B only.
$tools = @('base','basegate','leaf','leafgate')
$exeFor = @{ 'base'='pf-base'; 'basegate'='pf-base'; 'leaf'='pf-leaf'; 'leafgate'='pf-leaf' }
# NAME THE BASELINE, on Windows too. Since 9856e25f19 the joint solve is the
# DEFAULT on KernelClass::Avx512Gfni, so on a Zen 4 or an EPYC a bare parfast is
# already the ON arm and every arm here would silently acquire it. This box is
# Gfni256 rather than Avx512Gfni and these binaries predate the flip, so it is
# inert HERE and today; it stops being inert the moment either changes, and that
# is exactly the kind of thing nobody re-checks. All three arms pin it, because
# none of the three pairs is asking about the joint solve at all - jcross is.
$envFor = @{
  'base'     = @{ 'NZBFAST_FORNEY_JOINT' = '0' }
  'basegate' = @{ 'NZBFAST_FORNEY_JOINT' = '0'; 'NZBFAST_GF16_ROWOP_GFNI' = '1' }
  'leaf'     = @{ 'NZBFAST_FORNEY_JOINT' = '0' }
  'leafgate' = @{ 'NZBFAST_FORNEY_JOINT' = '0'; 'NZBFAST_GF16_ROWOP_GFNI' = '1' }
}
$rungs = @(16384,30000)   # the depths where the solve is a real share of the wall
$reps  = @(1,2)
$maxreps = 5          # ceiling for the noise escalation below
$noisepct = 10.0      # escalate a rung whose reps disagree by this much
$noisecap = 120.0     # ...but only while a leg is cheap enough to repeat
$argv  = @{
  'base'     = 'r -q -t16 -T16 f.par2'
  'basegate' = 'r -q -t16 -T16 f.par2'
  'leaf'     = 'r -q -t16 -T16 f.par2'          # NO SWITCH - see the header
  'leafgate' = 'r -q -t16 -T16 f.par2'          # NO SWITCH either: the arm is the variable
}
$vargv = @{
  'base'     = 'v -q -t16 -T16 f.par2'
  'basegate' = 'v -q -t16 -T16 f.par2'
  'leaf'     = 'v -q -t16 -T16 f.par2'
  'leafgate' = 'v -q -t16 -T16 f.par2'
}

New-Item -ItemType Directory -Force -Path '<rig>' | Out-Null
Take-RigLock $lock
try {
  "FULL-START $((Get-Date).ToUniversalTime().ToString('o'))"
  Write-BoxFacts
  Write-BinFacts $bin @('pf-base','pf-leaf')
  # The HARNESS's own provenance, not just the binary's, and the round-start
  # twin of the per-leg `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath
  # is THIS driver; plib.ps1 adds itself. A parfast round has no other evidence
  # of a harness that changed under it mid-round.
  Write-HarnessFacts @($PSCommandPath)
  "PROTOCOL slice=$slice recovery_blocks=$rblk source_blocks=32177 redundancy_pct=100.0 damage=scattered-seeded-slice-overwrite reps=2 gate=sha256-all-members prewarm=full-read-of-work-dir arms=$($tools -join '/') pairs=base-vs-leaf(additive-leaf-in-place),leaf-vs-leafgate(fused-butterfly-alone) create_env=per-arm"
  # A line that named par2turbo and par2j64 stood here until 11 Sep 2026 and
  # this round has never run either - it was inherited from full.ps1 and every
  # lookup in it resolved to an empty string, so the log recorded three empty
  # argv fields and nobody noticed. Print what the arms ACTUALLY are, from the
  # same tables the legs read, so the line cannot drift from them again.
  foreach ($t in $tools) {
    $e = $envFor[$t]
    $es = if ($e -and $e.Count) { (($e.Keys | Sort-Object | ForEach-Object { "$_=$($e[$_])" }) -join ',') } else { '-' }
    "ARGV $t exe=$($exeFor[$t]) repair='$($argv[$t])' verify='$($vargv[$t])' env=$es"
  }

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
  # CREATE IS AN A/B TOO, because the additive leaf is on the create path and
  # not only on repair. Both arms build the same set; the outputs must be
  # BYTE-IDENTICAL, and checking that is a correctness result in its own right -
  # a change to an arithmetic path that alters the bytes it emits is a defect
  # whatever it does to the clock.
  $createHash = @{}
  $createWall = @{}
  foreach ($carm in $tools) {
    Get-ChildItem "$rig\pristine\*.par2" -EA 0 | Remove-Item -Force -EA SilentlyContinue
    # THE ARM'S ENVIRONMENT GOES TO THE CREATE LEG TOO, and it did not until
    # 11 Sep 2026. This call passed no env at all, so `leafgate` would have
    # created with NZBFAST_GF16_ROWOP_GFNI unset - the arm's only difference -
    # and the create A/B would have compared leaf against a second copy of
    # leaf while reporting three distinct arms. The repair legs below always
    # passed it; only create did not, which is the kind of asymmetry that
    # survives review because the loop reads correctly on its own.
    $c = Invoke-Leg "$bin\$($exeFor[$carm]).exe" "c -q -t16 -T16 -s$slice -c$rblk f.par2 $memarg" "$rig\pristine" "$rig\logs\create-$carm" $envFor[$carm]
    $pfs = @(Get-ChildItem "$rig\pristine" -Filter *.par2 | Sort-Object Name)
    $sb = New-Object Text.StringBuilder
    foreach ($f in $pfs) { $null = $sb.Append((Get-FileHash $f.FullName -Algorithm SHA256).Hash) }
    $createHash[$carm] = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes($sb.ToString()))) -Algorithm SHA256).Hash
    $createWall[$carm] = $c.wall
    "CREATE round=zgfni arm=$carm rc=$($c.rc) wall=$($c.wall) cpu=$($c.cpu) peak_mb=$($c.peakmb) par2files=$($pfs.Count) setsha=$($createHash[$carm].Substring(0,16)) foreign_cpu=$($c.foreign) foreign_after=$($c.foreignAfter) errlen=$($c.errlen)"
    if ($c.rc -ne 0 -or $pfs.Count -eq 0) { "ZGFNI-FAIL create arm=$carm rc=$($c.rc)"; Release-RigLock $lock; exit 9 }
    $cr = $c
  }
  # EVERY arm, not just two: the fused butterfly and the in-place leaf are
  # both on the create path as well as the repair path, so all four have to
  # emit the same bytes. Derived from $tools so an arm added later is checked
  # without anyone remembering to widen this line.
  $identical = @($tools | Where-Object { $createHash[$_] -ne $createHash['base'] }).Count -eq 0
  "CREATE-IDENTICAL all_arms=$identical " + (($tools | ForEach-Object { "$($_)_sha=$($createHash[$_].Substring(0,16)) $($_)_wall=$($createWall[$_])" }) -join ' ')
  if (-not $identical) {
    "ZGFNI-WARN the arms emitted DIFFERENT parity bytes - a correctness finding that outranks every timing in this round"
    # AND THE FIRST HYPOTHESIS IS NOT THE LEAF ARITHMETIC. That is proved equal
    # to a naive reference on this silicon three separate ways:
    #   * par2ntt::tests::leaf_methods_agree_bit_for_bit compares whichever arm
    #     inplace_scale_preferred() selects against leaf_reference, over 14
    #     values of n, both x0 arms and widths 16 / 173 / 512 / 1024 - so
    #     running it in both configurations proves both arms equal the
    #     reference and therefore each other;
    #   * the in-place arm on the GFNI kernel was proved on 11 Sep 2026 on BOTH
    #     GFNI classes, each against an unarmed control (see the docstring on
    #     gfni_rowop_armed);
    #   * that same test was run green against commit 3667a696d50b itself - the
    #     exact tree pf-leaf.exe is built from - on a real GFNI part.
    # So a mismatch here points DOWNSTREAM of the maths: packet ordering, the
    # volume split, or a nondeterminism in the create path that two different
    # walls happened to expose. Look there first. That would be a genuinely new
    # finding rather than a broken kernel.
    "ZGFNI-HINT leaf arithmetic is reference-tested on this silicon incl. against 3667a696d50b; suspect packet order, volume split, or create-path nondeterminism before the kernel"
  }
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
    $envx = if ($envFor.ContainsKey($tool)) { $envFor[$tool] } else { $null }
    $envx = if ($envx) { $e2 = @{}; foreach ($k in $envx.Keys) { $e2[$k] = $envx[$k] }; $e2['NZBFAST_REPAIR_TIMING'] = '1'; $e2 } else { @{ 'NZBFAST_REPAIR_TIMING' = '1' } }
    $r = Invoke-Leg "$bin\$($exeFor[$tool]).exe" $targv "$rig\work" "$rig\logs\$tag" $envx
    $s1 = 'no-label'
    $errtxt = Get-Content "$rig\logs\$tag.err" -Raw -EA 0
    if ($errtxt -and $errtxt -match 'forney stage 1 \(joint([^)]*)\)') { $s1 = if ($Matches[1] -match 'FALLBACK') { 'FALLBACK' } else { ($Matches[1].Trim(" ,") ) } }
    $post = Test-RestoredFast "$rig\work" $members $gold
    $strays = Remove-Strays "$rig\work" $members $parfiles
    "LEG round=zgfni rep=$rep m=$rung tool=$tool argv='$targv' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) restored=$($post.good)/$($members.Count) damaged_members=$($members.Count - $pre.good) touched_members=$touched blocks_written=$wrote strays=$strays stage1='$s1' seed=$dseed foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o')) rig=$((Get-RigStamp) -join '')"
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
      $r = Invoke-Leg "$bin\$($exeFor[$tool]).exe" $vargv[$tool] "$rig\work" "$rig\logs\verify-$tool-r$rep"
      $g = Test-RestoredFast "$rig\work" $members $gold
      "VERIFY round=zgfni rep=$rep tool=$tool argv='$($vargv[$tool])' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) intact=$($g.good)/$($members.Count) foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) errlen=$($r.errlen) ts=$((Get-Date).ToUniversalTime().ToString('o')) rig=$((Get-RigStamp) -join '')"
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
