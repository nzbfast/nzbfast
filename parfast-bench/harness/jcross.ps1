param(
  # `-File` CANNOT bind a [string[]] parameter, in either the `-Rungs a,b` or
  # the `-Rungs a b` spelling - that cost this campaign a round on 10 Sep and
  # the fix was a rounds FILE. Every list here is therefore ONE string, split
  # inside, exactly as jcross.py takes them.
  [string]$Rungs = '256,704,1024,1536,2048,3072,4096,5120,6144,7168,8192,10240,12288,16384',
  [int]$Reps     = 3,
  [string]$Arms  = 'off,fast,aa',
  [string]$Tag   = 'jcross',
  [int]$Slice    = 262144,
  # THE NIBBLE-CLASS PROXY. `NZBFAST_GF16_FORCE=avx2` makes a GFNI part run
  # the AVX2 nibble kernels end to end - both dispatch chains and
  # `multi_fold_width` read it, so `KernelClass::current()` reports Nibble
  # and the scheduler, the thresholds and the kernel all agree on the arm.
  # The fleet has ONE box that reaches those kernels natively, the
  # i5-10600KF, and it is the field round's for a day at a time; this lets a
  # fast-mode fix be A/B'd on the Core Ultra 9 the same afternoon it is
  # written. It is a RATIO between two settings of one kernel on the wrong
  # silicon, never a leg to publish and never the i5's number - the
  # confirming ladder still runs on the i5, once, when the fix is ready.
  # Stamped on the PROTOCOL line and on every LEG as force=, so a forced log
  # cannot be mistaken for a native one.
  [string]$ForceKernel = '',
  # The two Windows bench boxes do not keep their binaries in the same place -
  # the zenbook has <rig>\bin, intel-i5-10600kf has <rig>\bin - and neither is
  # derivable from the rig root. Order: this parameter, then a one-line
  # `binpath.txt` beside the script, then `<root>\bin`. Whichever wins is
  # printed on the PROTOCOL line, and Write-BinFacts refuses the round outright
  # if the binary is not there, so a wrong guess cannot become a result.
  [string]$BinDir = '',
  # The binary the plain arms run, WITHOUT `.exe`, beside the others in $bin.
  # `parfast-jx` is the deployed one and stays the default; a round that
  # wants a candidate build deploys it under its own name and names it here,
  # so the binary already in flight for another round is never overwritten.
  # An arm can override this with its own `exe` key in $ArmTable (`fastdir`),
  # which is how two builds ride ONE round with a shared `off` and `aa`.
  [string]$Exe = 'parfast-jx'
)
# jcross.ps1 - the Windows arm of "where does `parfast --fast` stop paying,
# per kernel class?". A port of harness/jcross.py, which is macOS-only
# by construction (pdrv.py is fcntl.flock, os.wait4, resource, ps, lsof), onto
# plib.ps1. The crossover lane owns the QUESTION and the protocol; this file
# owns the Windows execution, and was smoke-run on a real Windows box before
# any round used it - which is the only reason it exists rather than being
# written blind from the spec.
#
# WHY WINDOWS AT ALL. The lane's Macs can only reach KernelClass::Neon. The two
# x86 classes a user is most likely to own are reachable only here:
#
#   intel-i5-10600kf     i5-10600KF     no GFNI            -> Avx2Nibble
#   intel-core-ultra-9-386h  Core Ultra 9   GFNI, no AVX-512   -> Gfni256
#
# Neither is Avx512Gfni, which is the class 9856e25f19 flipped the default on,
# so NOTHING in this round is measured on a box whose default already moved.
# That is a limit of this round and it travels with its numbers.
#
# THE PROTOCOL IS jcross.py'S, ITEM FOR ITEM. Anything that differs is a
# Windows mechanism, never a change of question:
#
#   * `off` and `aa` pin NZBFAST_FORNEY_JOINT=0 rather than trusting the
#     binary's default. The default is exactly what this round may move, and an
#     arm on a default stops measuring the moment it does.
#   * `aa` is `off` twice, at EVERY rung. A difference smaller than its own
#     rung's A/A is not a signal.
#   * 256 is below both Forney gates (704 NEON, 1,280 x86), so the two arms run
#     identical code there: a free end-to-end A/A that travels with the round.
#     704 and 1,024 bracket the x86 gate from below.
#   * 8,192 is JOINT_FACTOR_MIN_M itself; 12,288 and 16,384 are the POSITIVE
#     CONTROL - if they do not reproduce the known deep win, every other row is
#     void.
#   * both stage labels on the leg line. Since 11 Sep the two stages take their
#     arms INDEPENDENTLY, so a round that reads stage 1's label and credits
#     both stages to it is reading an arm it did not run.
#   * every leg gated on SHA-256 of all members, NEVER on rc.
#   * arm order alternates by rep, so no arm permanently pays the cache and
#     thermal cost of the damage write that precedes the first leg of a rung.
#   * `ctrl_s` on every leg line: the NEGATIVE control, a phase no arm of this
#     round can reach. NEITHER STAGE MARK IS ONE - both are attributed shares
#     of a single fused wall - and a round on a disturbed box completes every
#     leg and passes every SHA gate while reading pure noise. See the parser
#     below and jcross.py's CTRL_RE.
#
# ONE DELIBERATE DEPARTURE, and it is a fix rather than a difference.
# jcross.py's stage labels keep the engine's own wording, which contains
# SPACES and COMMAS ("short tail, stripe 4w") and, on the shipped stage-2 arm,
# the whole timing tail. Printed unquoted into a `key=value` leg line that
# makes the line unparseable at exactly the rungs where `--fast` did not
# engage - which is half of every A/B. Here each label is reduced to ONE token
# and the engine's raw wording is carried beside it, quoted:
#
#   stage1 = joint-short-tail | joint-peeled | joint-whole-demand | hankel
#            | ...-FALLBACK | no-label | no-err
#   stage2 = joint-factor | evaluate | joint-FALLBACK | no-label | no-err
#
# A FALLBACK is `-match 'FALLBACK'` on the token, in both stages, whatever
# kernel it sat on. Several distinct labels in one leg join with `+` rather
# than the last one silently winning.
#
# FIXTURE: 32 members x 512 slices, keyed on the block size, so two block sizes
# never share a fixture. At the default 262,144 B that is 128 MiB a member,
# 4 GiB of payload, 16,384 source blocks, and RBLK=16,384 (100% parity) so m
# can reach the deepest rung. ~16 GiB on disk with the working copy. The deep
# end of a ladder does not need a big SET, it needs a big m, and m is capped by
# the BLOCK count - the 11 Sep mcross round asked for 23 GiB and died on a full
# disk 3m45s in.
# THE RIG ROOT IS THE SCRIPT'S OWN DIRECTORY, not a hard-coded <rig>. The two
# Windows bench boxes do not agree on it - the zenbook runs out of <rig> and
# intel-i5-10600kf out of <rig> - and a hard-coded path is how a round ends up
# reading one box's binaries while writing another's logs. $PSScriptRoot is
# what the queue runner already uses to find this file.
$root = if ($PSScriptRoot) { $PSScriptRoot } else { '<rig>' }
. (Join-Path $root 'plib.ps1')

$bin = if ($BinDir) { $BinDir }
       elseif (Test-Path (Join-Path $root 'binpath.txt')) { (Get-Content (Join-Path $root 'binpath.txt') -Raw).Trim() }
       else { Join-Path $root 'bin' }
$pfx  = $Exe              # deployed BESIDE the other binaries, never over one:
                          # a round in flight must not change binary underneath
                          # itself.
$rig  = Join-Path $root "jcross-$Slice"
$lock = Join-Path $root 'jcross.lock'
$NMEM = 32
$MEMSLICES = 512
$SRCBLK = $NMEM * $MEMSLICES
$RBLK = 16384
$membytes = [int64]$Slice * $MEMSLICES

# NAMED $ArmTable AND NOT $ARMS, AND THAT IS NOT A STYLE CHOICE.
# PowerShell variable names are CASE-INSENSITIVE, so `$ARMS` and the `-Arms`
# parameter above are ONE variable: the table was overwritten by the string
# 'off,fast,aa' before a single leg ran, and the round died at
# `$ARMS.ContainsKey($nm)` with "[System.String] does not contain a method
# named 'ContainsKey'". Python, which this is a port of, is case-sensitive and
# has `ARMS` and `arms` side by side quite happily. Three more collided the
# same way and are renamed for the same reason: `$rungs`/`-Rungs`,
# `$arms`/`-Arms`, and `$tag` inside Run-Rung, which shadowed the round's
# `-Tag` so every leg line would have printed its OWN tag as the round name.
# A parse check cannot see any of this; only running it can, which is what the
# smoke is for.
$ArmTable = @{
  'off'   = @{ argv = @();         env = @{ 'NZBFAST_FORNEY_JOINT' = '0' } }
  'fast'  = @{ argv = @('--fast'); env = @{} }
  'aa'    = @{ argv = @();         env = @{ 'NZBFAST_FORNEY_JOINT' = '0' } }
  # The stage-2 pair holds stage 1 on the additive product in BOTH arms and
  # moves only the constant JOINT_FACTOR_MIN_M gates. Forced in both
  # directions: an arm left on the default stops measuring when the default
  # moves.
  's2off' = @{ argv = @(); env = @{ 'NZBFAST_FORNEY_JOINT' = '1'; 'NZBFAST_FORNEY_FACTOR' = 'off' } }
  's2on'  = @{ argv = @(); env = @{ 'NZBFAST_FORNEY_JOINT' = '1'; 'NZBFAST_FORNEY_FACTOR' = 'on'  } }
  # ...and its A/A must be a second copy of `s2off`, NOT `aa`. `aa` is the
  # SHIPPED solve, so pairing s2off against it would measure stage 1 - an A/B
  # wearing the name of a floor.
  's2aa'  = @{ argv = @(); env = @{ 'NZBFAST_FORNEY_JOINT' = '1'; 'NZBFAST_FORNEY_FACTOR' = 'off' } }
  # The stage-1 trio, 12 Sep 2026: both arms run the joint scheduler with
  # stage 2 on its own gate, and differ only in whether stage 1 takes the
  # additive kernel (`kernel`, the normal admission) or is HELD on the shipped
  # arithmetic (`owned`, NZBFAST_FORNEY_STAGE1 in joint.rs). This prices the
  # kernel ALONE, which the nibble decomposition found a 2-3% loss below
  # ~6,000 blocks; the A/A is a second copy of `s1off` for the reason `s2aa`
  # gives above.
  's1off' = @{ argv = @(); env = @{ 'NZBFAST_FORNEY_JOINT' = '1'; 'NZBFAST_FORNEY_STAGE1' = 'owned' } }
  's1on'  = @{ argv = @(); env = @{ 'NZBFAST_FORNEY_JOINT' = '1'; 'NZBFAST_FORNEY_STAGE1' = 'kernel' } }
  's1aa'  = @{ argv = @(); env = @{ 'NZBFAST_FORNEY_JOINT' = '1'; 'NZBFAST_FORNEY_STAGE1' = 'owned' } }
  # A SECOND BUILD in the same round: `--fast` on the binary named by `exe`
  # (deployed beside the others), against this round's own `off`/`fast`/`aa`
  # on the default one. The first user is the const-direction AVX2 butterfly
  # (Codex's direction-candidate.patch, 12 Sep 2026), built as parfast-jd.
  'fastdir' = @{ argv = @('--fast'); env = @{}; exe = 'parfast-jd' }
  # The same shape for the 24-source x86 fold batch (Codex's
  # stage2/x86-fold-batch.patch: `fold_rows` hands the GFNI kernels 24 views
  # instead of 8, so a six- or twelve-wide group is no longer restarted at
  # every eighth source), built as parfast-jb. A GFNI-class candidate; on
  # Nibble it changes nothing and is a free A/A.
  'fastb'   = @{ argv = @('--fast'); env = @{}; exe = 'parfast-jb' }
}

if ($ForceKernel -ne '' -and $ForceKernel -notin @('avx2','ssse3')) { "JCROSS-FAIL -ForceKernel must be avx2 or ssse3, not '$ForceKernel'"; exit 2 }
if ($ForceKernel -ne '') { foreach ($k in @($ArmTable.Keys)) { $ArmTable[$k].env['NZBFAST_GF16_FORCE'] = $ForceKernel } }
$forceTag = if ($ForceKernel -ne '') { $ForceKernel } else { 'native' }

$cores = (Get-CimInstance Win32_Processor | Measure-Object NumberOfLogicalProcessors -Sum).Sum
$THREADS = [math]::Min(32, $cores)
# parfast's own default hashing rule, min(cores, files). A flat -T16 caps a box
# with more cores than that.
$TFLAG = [math]::Min($cores, $NMEM)

function Get-RepairArgv([string]$armname) {
  $extra = $ArmTable[$armname].argv
  $parts = @('r', '-q', "-t$THREADS", "-T$TFLAG") + $extra + @('f.par2')
  return ($parts -join ' ')
}

# ---- stage labels ------------------------------------------------------
# The ONLY place the engine says which arm each stage actually took is a
# `repair-timing` trace line, so every leg sets NZBFAST_REPAIR_TIMING and reads
# it back off stderr.
function Get-StageLabels([string]$errpath) {
  # NOT `return` - see the note on $script:lastwall below. These land in
  # $script:stage1 / stage1raw / stage2 / stage2raw / ctrl.
  $script:stage1 = 'no-err'; $script:stage2 = 'no-err'
  $script:stage1raw = ''; $script:stage2raw = ''
  $script:ctrl = 'n/a'
  if (-not (Test-Path $errpath)) { return }
  $script:stage1 = 'no-label'; $script:stage2 = 'no-label'
  $t1 = New-Object 'System.Collections.Generic.List[string]'
  $t2 = New-Object 'System.Collections.Generic.List[string]'
  $r1 = New-Object 'System.Collections.Generic.List[string]'
  $r2 = New-Object 'System.Collections.Generic.List[string]'
  foreach ($line in [IO.File]::ReadAllLines($errpath)) {
    if ($line -match 'forney stage 1 \((.+?)\): \d') {
      $inner = $Matches[1]
      $tok = if ($inner -match '^joint\s+short tail') { 'joint-short-tail' }
             elseif ($inner -match '^joint\s+peeled') { 'joint-peeled' }
             elseif ($inner -match '^joint\s+whole/demand') { 'joint-whole-demand' }
             elseif ($inner -match '^joint') { 'joint-other' }
             elseif ($inner -match '^hankel') { 'hankel' }
             else { 'unknown' }
      if ($inner -match 'FALLBACK') { $tok = "$tok-FALLBACK" }
      if (-not $t1.Contains($tok)) { $t1.Add($tok); $r1.Add($inner) }
    }
    elseif ($line -match 'forney stage 2 \((.+?)\): \d') {
      $inner = $Matches[1]
      $tok = if ($inner -match 'FALLBACK') { 'joint-FALLBACK' }
             elseif ($inner -match 'joint factor') { 'joint-factor' }
             elseif ($inner -match '^evaluate') { 'evaluate' }
             else { 'unknown' }
      if (-not $t2.Contains($tok)) { $t2.Add($tok); $r2.Add($inner) }
    }
    elseif ($line -match 'verify targets \+ volume scan: \+([0-9.]+)(ns|.s|ms|s) \(total') {
      # THE NEGATIVE CONTROL. Neither stage mark can be one, and that is the
      # reason this exists: both stage marks are attributed SHARES of a single
      # fused wall (`split(s1)` / `split(s2)` in joint.rs), so a stage mark
      # holding still across the arms says the ATTRIBUTION held still, not that
      # the box did. `par2repair.rs`'s `mark("verify targets + volume scan")`
      # times the pass that reads and hashes every target BEFORE the Forney
      # gate is consulted: no arm of this round can reach it, and it is emitted
      # on every leg at every rung - including the rungs below the gate, where
      # the solver is never entered and there is no stage line at all.
      #
      # Without it a round on a disturbed box completes every leg, passes every
      # SHA-256 gate and reads pure noise, which is what
      # the banked discarded-leg logs was kept to show.
      #
      # `.s` is the microsecond arm and is deliberately a DOT rather than the
      # character: the micro sign is the one glyph in this trace that a console
      # code page can mangle, and matching it exactly is how a control turns
      # silently into `n/a` on the box while working on the dev machine. `ns`
      # must stay ahead of it in the alternation or `.s` eats it.
      $v = [double]$Matches[1]
      $u = $Matches[2]
      $script:ctrl = '{0:0.000000}' -f $(
        if     ($u -eq 'ns') { $v / 1e9 }
        elseif ($u -eq 'ms') { $v / 1e3 }
        elseif ($u -eq 's')  { $v }
        else                 { $v / 1e6 }   # the microsecond arm
      )
    }
  }
  if ($t1.Count) { $script:stage1 = ($t1 -join '+'); $script:stage1raw = ($r1 -join ' | ') }
  if ($t2.Count) { $script:stage2 = ($t2 -join '+'); $script:stage2raw = ($r2 -join ' | ') }
}

# ---- main ---------------------------------------------------------------
# Cheap, and it names the cause rather than the symptom. If a later edit
# reintroduces a case-insensitive collision with a parameter, this fires with
# the reason instead of a MethodNotFound thirty lines down.
if ($ArmTable -isnot [hashtable]) {
  "JCROSS-FAIL `$ArmTable is a $($ArmTable.GetType().Name), not a hashtable."
  "JCROSS-HINT PowerShell variable names are CASE-INSENSITIVE - a parameter whose name matches a table's, in any case, IS that table. Rename one."
  exit 2
}
$rungList = @($Rungs.Split(',') | Where-Object { $_ } | ForEach-Object { [int]$_ })
$armList  = @($Arms.Split(',')  | Where-Object { $_ })
foreach ($nm in $armList) { if (-not $ArmTable.ContainsKey($nm)) { "JCROSS-FAIL unknown arm $nm"; exit 2 } }
if (($rungList | Measure-Object -Maximum).Maximum -gt $SRCBLK) {
  "JCROSS-FAIL deepest rung exceeds $SRCBLK source blocks"; exit 2
}
# ~16 GiB of fixture at the default block size, and a full disk killed the
# 11 Sep mcross round 3m45s in having already spent 70 s on create. Refuse
# BEFORE the create, not during it.
$need = [math]::Round(($membytes * $NMEM * 2.0 * 2.0) / 1GB, 1) + 5
$rigdrive = (Split-Path -Qualifier $root).TrimEnd(':')
$drv = Get-PSDrive -Name $rigdrive
if (($drv.Free / 1GB) -lt $need) {
  "JCROSS-FAIL need $need GiB free on ${rigdrive}:, have $([math]::Round($drv.Free/1GB,1))"; exit 9
}

# REFUSE TO RUN OVER A FAILED SMOKE. jsmoke.ps1 writes jsmoke-verdict.txt and
# the failure it is most worth refusing on is an arm that never engaged: if
# stage 1 declines on this kernel class, `off` and `fast` are the same code at
# every rung and this round produces paired zeroes that read as a decisive
# "no gain" from a round that never ran the arm under test. The instruction from
# the lane that spotted it was to read the smoke log first and shout; a queue
# stepping between rounds at 3 a.m. has nobody to shout to.
#
# Gated on $Tag so the smoke itself is never blocked by its own verdict.
if ($Tag -ne 'jsmoke') {
  $vf = Join-Path $root 'jsmoke-verdict.txt'
  if ((Test-Path $vf) -and ((Get-Content $vf -Raw) -match '^FAIL')) {
    "JCROSS-REFUSED the smoke on this box FAILED and the round it gates would be meaningless:"
    Get-Content $vf | Select-Object -Skip 1 | ForEach-Object { "  $_" }
    "JCROSS-HINT fix the cause, re-run jsmoke, and delete $vf only when it passes"
    exit 13
  }
}
New-Item -ItemType Directory -Force -Path '<rig>' | Out-Null
Take-RigLock $lock
try {
  "JCROSS-START $((Get-Date).ToUniversalTime().ToString('o')) tag=$Tag"
  Write-BoxFacts
  # Every binary an arm in THIS round names, the default first, each once:
  # a second build that rides the round has to be pinned on its own BIN line
  # or the log cannot say what its arm measured.
  $exeList = @($pfx)
  foreach ($nm in $armList) {
    $ax = $ArmTable[$nm].exe
    if ($ax -and ($exeList -notcontains $ax)) { $exeList += $ax }
  }
  Write-BinFacts $bin $exeList
  # The HARNESS's own provenance, not just the binary's, and the round-start
  # twin of the per-leg `rig=` token - see plib.ps1's Get-RigStamp. $PSCommandPath
  # is THIS driver; plib.ps1 adds itself. A parfast round has no other evidence
  # of a harness that changed under it mid-round.
  Write-HarnessFacts @($PSCommandPath)
  # `arm_order=rotating-by-rep` IS THE ONLY THING IN A BANKED LOG THAT
  # SAYS WHICH ORDERING RULE PRODUCED IT, and until 12 Sep 2026 it read
  # `alternating-by-rep` under the reversal this file used to carry - a
  # label that fits both rules and so distinguishes neither. Every Windows
  # round banked before that date is stamped the old way; which ones they
  # are, and what each one's own position effect measures, is
  # an internal note. Change this string
  # whenever the rule changes, or the next audit has to reverse-engineer
  # the order out of the LEG lines again, which is what that one did.
  "PROTOCOL bin=$bin slice=$Slice recovery_blocks=$RBLK source_blocks=$SRCBLK redundancy_pct=100.0 damage=scattered-seeded-slice-overwrite reps=$Reps arms=$($armList -join '/') gate=sha256-all-members prewarm=full-read-of-work-dir arm_order=rotating-by-rep threads=$THREADS tflag=$TFLAG force=$forceTag port_of=harness/jcross.py"
  foreach ($nm in $armList) {
    $e = $ArmTable[$nm].env
    $es = if ($e.Count) { (($e.Keys | Sort-Object | ForEach-Object { "$_=$($e[$_])" }) -join ',') } else { '-' }
    "ARGV $nm repair='$(Get-RepairArgv $nm)' env=$es"
  }

  $pristine = "$rig\pristine"; $work = "$rig\work"; $logs = "$rig\logs"
  New-Item -ItemType Directory -Force -Path $pristine,$work,$logs | Out-Null
  $members = @(0..($NMEM-1) | ForEach-Object { 'p{0:d2}.bin' -f $_ })

  # ---- payload ---------------------------------------------------------
  # Seeded rather than /dev/urandom: the fixture is then reproducible on any
  # box, which is the whole point of publishing a harness. The distinctness
  # probe below is what actually guards the near-copy defect, and it runs
  # either way.
  foreach ($i in 0..($NMEM-1)) {
    $f = "$pristine\$($members[$i])"
    if ((Test-Path $f) -and ((Get-Item $f).Length -eq $membytes)) { continue }
    $chunk = 4MB
    $buf = New-Object byte[] $chunk
    $rng = New-Object Random(20260911 + $i * 7919)
    $fs = [IO.File]::Create($f)
    $written = [int64]0
    while ($written -lt $membytes) {
      $n = [int][math]::Min([int64]$chunk, $membytes - $written)
      $rng.NextBytes($buf)
      $fs.Write($buf, 0, $n)
      $written += $n
    }
    $fs.Close()
  }
  $gold = @{}
  foreach ($nm in $members) { $gold[$nm] = Get-Sha256Fast "$pristine\$nm" }
  $uniq = ($gold.Values | Sort-Object -Unique).Count
  "FIXTURE members=$($members.Count) distinct_member_sha=$uniq/$($members.Count) bytes=$($membytes * $NMEM) source_blocks=$SRCBLK member_bytes=$membytes"
  if ($uniq -ne $members.Count) { "JCROSS-FAIL payload members not distinct"; exit 9 }
  # The near-copy defect that voided the September publication rounds is caught
  # by hashing the SAME slice index in every member, not by hashing members.
  $probe = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($nm in $members) {
    $fs = [IO.File]::OpenRead("$pristine\$nm"); $null = $fs.Seek([int64]5 * $Slice, 'Begin')
    $b = New-Object byte[] $Slice; $null = $fs.Read($b, 0, $Slice); $fs.Close()
    $null = $probe.Add([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)))
  }
  "SLICE-PROBE index=5 unique=$($probe.Count)/$($members.Count)"
  if ($probe.Count -ne $members.Count) { "JCROSS-FAIL payload is near-copies"; exit 9 }
  foreach ($nm in $members) { "GOLD $nm $($gold[$nm])" }

  # ---- create (reused across runs at the same block size) --------------
  $parfiles = @(Get-ChildItem $pristine -Filter *.par2 -EA 0 | Sort-Object Name | ForEach-Object { $_.Name })
  if (-not $parfiles.Count) {
    $memarg = ($members -join ' ')
    $c = Invoke-Leg "$bin\$pfx.exe" "c -q -t$THREADS -T$TFLAG -s$Slice -c$RBLK f.par2 $memarg" $pristine "$logs\create"
    $pf = @(Get-ChildItem $pristine -Filter *.par2 | Sort-Object Name)
    $parfiles = @($pf | ForEach-Object { $_.Name })
    "CREATE tool=parfast rc=$($c.rc) wall=$($c.wall) cpu=$($c.cpu) peak_mb=$($c.peakmb) par2files=$($pf.Count) par2bytes=$((($pf|Measure-Object Length -Sum).Sum)) foreign_cpu=$($c.foreign) foreign_after=$($c.foreignAfter) errlen=$($c.errlen)"
    if ($c.rc -ne 0 -or -not $parfiles.Count) { "JCROSS-FAIL create rc=$($c.rc)"; exit 9 }
  } else {
    "CREATE reused par2files=$($parfiles.Count)"
  }

  foreach ($nm in ($members + $parfiles)) {
    $s = "$pristine\$nm"; $d = "$work\$nm"
    if (-not (Test-Path $d) -or (Get-Item $d).Length -ne (Get-Item $s).Length) { Copy-Item $s $d -Force }
  }
  $null = Remove-Strays $work $members $parfiles
  $g0 = Test-RestoredFast $work $members $gold
  if ($g0.good -ne $members.Count) { foreach ($nm in $g0.bad) { Copy-Item "$pristine\$nm" "$work\$nm" -Force } }

  # ---- one leg, fully gated -------------------------------------------
  function Run-Rung {
    param([string]$armname, [int]$rung, [int]$rep, [int]$dseed, [string]$legtag)
    $targv = Get-RepairArgv $armname
    Read-Warm $work
    $picks = Get-DamagePicks $work $members $Slice $rung $dseed
    $wrote = Invoke-DamagePicks $work $members $Slice $picks $dseed
    $pre = Test-RestoredFast $work $members $gold
    $legenv = @{ 'NZBFAST_REPAIR_TIMING' = '1' }
    foreach ($k in $ArmTable[$armname].env.Keys) { $legenv[$k] = $ArmTable[$armname].env[$k] }
    $legexe = if ($ArmTable[$armname].exe) { $ArmTable[$armname].exe } else { $pfx }
    $r = Invoke-Leg "$bin\$legexe.exe" $targv $work "$logs\$legtag" $legenv
    $post = Test-RestoredFast $work $members $gold
    $strays = Remove-Strays $work $members $parfiles
    Get-StageLabels "$logs\$legtag.err"
    "LEG round=$Tag rep=$rep m=$rung arm=$armname exe=$legexe argv='$targv' wall=$($r.wall) cpu=$($r.cpu) cpu_over_wall=$([math]::Round($r.cpu/[math]::Max($r.wall,0.001),2)) peak_mb=$($r.peakmb) rc=$($r.rc) restored=$($post.good)/$($members.Count) damaged_members=$($members.Count - $pre.good) blocks_written=$wrote strays=$strays seed=$dseed stage1=$($script:stage1) stage2=$($script:stage2) stage1_raw='$($script:stage1raw)' stage2_raw='$($script:stage2raw)' ctrl_s=$($script:ctrl) foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) errlen=$($r.errlen) force=$forceTag ts=$((Get-Date).ToUniversalTime().ToString('o')) rig=$((Get-RigStamp) -join '')"
    Restore-Slices $work $pristine $members $Slice $picks
    $chk = Test-RestoredFast $work $members $gold
    if ($chk.good -ne $members.Count) {
      foreach ($nm in $chk.bad) { Copy-Item "$pristine\$nm" "$work\$nm" -Force }
      $chk2 = Test-RestoredFast $work $members $gold
      "RESET rep=$rep m=$rung arm=$armname after_full_copy=$($chk2.good)/$($members.Count)"
      if ($chk2.good -ne $members.Count) { "JCROSS-FAIL work dir unrecoverable"; exit 9 }
    }
    foreach ($nm in $parfiles) { Copy-Item "$pristine\$nm" "$work\$nm" -Force }
    # NOT `return`. Every log line in this function goes to the OUTPUT stream,
    # which the caller redirects into the round log, so a return value would be
    # captured together with the LEG lines - emptying the log and handing the
    # caller an array instead of a number.
    $script:lastwall = [double]$r.wall
  }

  # ---- arm order, computed and CHECKED before a single leg runs ---------
  # Rotation, per the block in the rep loop below. It is built and validated
  # HERE, ahead of the warm-up, for two reasons.
  #
  # ONE: this file cannot be parse-checked into correctness on a mac - there is
  # no pwsh on the dev box - so the port that introduced the rotation landed
  # UNRUN, and the class of defect that then ships is an order that is quietly
  # not a permutation. `[array]::Reverse` on @($armList) was exactly that kind
  # of bug waiting to happen; an off-by-one in the modulus is the same kind.
  # So the round asserts the property it needs (every arm exactly once, in
  # every rep) and dies at leg zero rather than publishing a scrambled ladder.
  #
  # TWO: it prints each rep's order into the log. Until 12 Sep 2026 the ONLY
  # record of which slot an arm ran in was the sequence of LEG lines, and
  # recovering it meant reconstructing the rule from the data - which is what
  # an internal note had to do across ten banked
  # rounds. These lines make that free for anyone reading a future log.
  $repOrders = @()
  foreach ($rep in 1..$Reps) {
    $k = ($rep - 1) % $armList.Count
    # A NEW array every rep. NOT [array]::Reverse or a rotate-in-place on
    # @($armList) - @() around an object[] hands back the SAME object, so a
    # mutation there would scramble every later rep.
    $ord = @(0..($armList.Count - 1) | ForEach-Object { $armList[($k + $_) % $armList.Count] })
    if ($ord.Count -ne $armList.Count -or
        @(Compare-Object $ord $armList -SyncWindow ($armList.Count)).Count -ne 0) {
      "JCROSS-FAIL rep=$rep arm order '$($ord -join ',')' is not a permutation of '$($armList -join ',')'"
      exit 2
    }
    $repOrders += ,$ord
    "ARM-ORDER rep=$rep $($ord -join ',')"
  }

  # ---- untimed warm-up, discarded --------------------------------------
  "WARMUP-START $((Get-Date).ToUniversalTime().ToString('o'))"
  foreach ($armname in $armList) { Run-Rung $armname 64 0 20260911 "warm-$armname" }
  "WARMUP-END $((Get-Date).ToUniversalTime().ToString('o'))"

  foreach ($rep in 1..$Reps) {
    # Arm ORDER ROTATES by rep. Within a rung the first arm pays any residual
    # cache and thermal cost of the damage write that precedes it, and the first
    # arm of the FIRST rung additionally pays for whatever the previous rep left
    # dirty - so holding one arm in one position folds that into the signal in
    # the same direction at every depth.
    #
    # **THIS WAS A REVERSAL UNTIL 12 SEP 2026, AND REVERSING THREE ARMS IS NOT
    # ALTERNATING THEM.** `[off, fast, aa]` reversed is `[aa, fast, off]`: the
    # middle element does not move, so across every rep of every round this
    # driver has run, `fast` - the arm under test - was NEVER first and never
    # last, while `off` and `aa` split those slots between them. Any
    # position-dependent cost was therefore paid by the baseline and the floor
    # and never by the arm the table reports.
    #
    # jcross.py carries the evidence: the rung where the cost is comparable to
    # the leg, the +42.75% row it manufactured for an arm that could not engage,
    # and the note that a rep count which is a MULTIPLE of the arm count is
    # preferred (at 3 arms and 5 reps the first slot goes 2/2/1). The two
    # drivers are twins and jsum.py / s2sum.py reduce both, so this must stay
    # the same rule, not a PowerShell-idiomatic variant of it. Which banked
    # Windows rounds ran under the old order, and what each one's own position
    # effect measures: an internal note.
    #
    # The orders themselves are built and CHECKED above the warm-up, before any
    # leg runs, and each one is printed as an ARM-ORDER line - so a round that
    # computed a non-permutation dies at leg zero, and a reader of the log never
    # has to infer the order from the sequence of LEG lines.
    $order = $repOrders[$rep - 1]
    foreach ($rung in $rungList) {
      $dseed = 20260911 + $rung * 7 + $rep    # identical damage for every arm
      foreach ($armname in $order) { Run-Rung $armname $rung $rep $dseed "r$rep-m$rung-$armname" }
    }
    "JCROSS-REP-END rep=$rep $((Get-Date).ToUniversalTime().ToString('o'))"
  }
  "JCROSS-END $((Get-Date).ToUniversalTime().ToString('o'))"
}
finally { Release-RigLock $lock }
