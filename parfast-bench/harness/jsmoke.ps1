# jsmoke.ps1 - the end-to-end smoke for jcross.ps1, and a GATE on the round
# behind it.
#
# NO NUMBER OUT OF THIS ROUND IS A RESULT. It exists to prove the Windows
# harness runs at all before a real round spends a night on it: a small block
# size so the fixture is 1 GiB rather than 4, one rep, and four rungs.
#
# THE FIRST THREE RUNGS ARE THE POINT, and they are cheap on purpose. 256, 704
# and 1,024 are all below the x86 Forney gate (BACKSUB_MIN_MISSING_NIBBLE =
# 1,280), so the two arms run IDENTICAL CODE there: a free end-to-end A/A that
# costs about a minute. 2,048 is the one rung above the gate, and it is there
# to prove the arms can DIVERGE at all.
#
# SO THE SMOKE PASSES ONLY IF:
#   * every leg restores all members by SHA-256, at every rung, on every arm;
#   * at 256 / 704 / 1,024 all three arms agree on their stage labels;
#   * at 2,048 the `fast` arm reports a JOINT stage-1 label and `off` does not.
#
# `no-label` BELOW THE GATE IS THE CORRECT READING AND THIS COMMENT SAID
# `hankel` UNTIL THE FIRST RUN CORRECTED IT. Below BACKSUB_MIN_MISSING the
# repair does not enter the Forney solver at all, so there is no stage line to
# print and no arm to name. Measured on Zen 5, 11 Sep 2026: no-label at
# 256/704/1,024 on all three arms, and at 2,048 off=hankel/evaluate,
# fast=joint-whole-demand/joint-FALLBACK, aa=hankel/evaluate.
#
# WHY THIS NOW WRITES A VERDICT FILE RATHER THAN LEAVING IT TO A READER.
#
# The `joint-default-nibble-x86-11sep` lane put the danger in one sentence: if
# stage 1 declines on a kernel class, then `off` and `fast` are THE SAME CODE at
# every rung, and jcross produces 126 legs of paired zeroes that read exactly
# like a decisive "no gain" - a publishable-looking negative result from a round
# that never engaged the thing it was testing. Its instruction was to read this
# log before anything else and shout if it looks wrong.
#
# That is the right instruction and the wrong mechanism: it depends on somebody
# being awake at the moment a queue steps from one round to the next, at night,
# on a box in another room. So the check is made here, mechanically, and written
# to `jsmoke-verdict.txt`, which jcross refuses to start over when it says FAIL.
# A reader still gets the shout; the queue no longer needs one.
param([string]$ForceKernel = '')   # see jcross.ps1: the Nibble-class proxy on a GFNI part
$root = $PSScriptRoot
$legfile = Join-Path $root 'jsmoke-legs.txt'
$verdict = Join-Path $root 'jsmoke-verdict.txt'
Remove-Item $legfile, $verdict -Force -EA SilentlyContinue

# Tee rather than re-read: the queue runner holds this round's log open through
# an Out-File, and reading a file another process is writing is a race nobody
# needs. Everything still reaches the queue's log unchanged.
& (Join-Path $root 'jcross.ps1') -ForceKernel $ForceKernel -Slice 65536 -Rungs '256,704,1024,2048' -Reps 1 -Arms 'off,fast,aa' -Tag 'jsmoke' |
  Tee-Object -FilePath $legfile

# The assessment is a FUNCTION so it can be run against a banked log without
# spending a round. Tested against the passing Zen 5 smoke and against
# synthesised failures for each arm of the verdict.
function Test-SmokeLegs([string]$path) {
  $fail = @()
  $legs = @(Get-Content $path -EA 0 | Where-Object { $_ -like 'LEG *' -and $_ -notmatch ' rep=0 ' })
  $script:smokeLegs = $legs
  if ($legs.Count -lt 12) { $fail += "only $($legs.Count) timed legs, expected 12" }
  foreach ($l in $legs) {
    $r = [regex]::Match($l, 'restored=(\d+)/(\d+)')
    if (-not $r.Success -or $r.Groups[1].Value -ne $r.Groups[2].Value) {
      $fail += "a leg did not restore every member: " + ([regex]::Match($l, 'm=\d+ arm=\w+').Value)
    }
  }
  function Stage1For([string]$m, [string]$arm) {
    $hit = $script:smokeLegs | Where-Object { $_ -match " m=$m " -and $_ -match " arm=$arm " } | Select-Object -First 1
    if (-not $hit) { return '(missing)' }
    return [regex]::Match($hit, ' stage1=(\S+)').Groups[1].Value
  }
  # script scope: the PASS line and the verdict file below are outside this
  # function and read these. Local copies would have printed empty strings into
  # the one artefact a later reader trusts.
  $script:fastAbove = Stage1For '2048' 'fast'
  $script:offAbove  = Stage1For '2048' 'off'
  $fastAbove = $script:fastAbove
  $offAbove  = $script:offAbove
  $script:smokeLegCount = $legs.Count
  if ($fastAbove -notmatch '^joint') {
    $fail += "ABOVE THE GATE THE FAST ARM DID NOT ENGAGE: m=2048 fast stage1='$fastAbove'. " +
             "If stage 1 declines on this kernel class then off and fast are the same code at " +
             "every rung, and a full jcross would produce paired zeroes that read as a decisive " +
             "'no gain' from a round that never ran the arm under test."
  }
  if ($offAbove -match '^joint') {
    $fail += "the BASELINE engaged the joint solve at m=2048 (stage1='$offAbove') - " +
             "NZBFAST_FORNEY_JOINT=0 is not reaching the child, so both arms are the on-arm."
  }
  foreach ($m in '256','704','1024') {
    $s = @('off','fast','aa' | ForEach-Object { Stage1For $m $_ })
    if (@($s | Sort-Object -Unique).Count -ne 1) {
      $fail += "below the gate the arms disagree at m=$m (" + ($s -join '/') + ") - they should be identical code there"
    }
  }
  # NOT `return ,$fail`. The comma operator is the documented way to stop
  # PowerShell enumerating a collection on return, and it is right for a
  # NON-empty one - but over an EMPTY array it wraps it, so `@()` comes back as
  # one element containing an empty array and `.Count` reads 1. A clean smoke
  # then reports exactly one nameless problem, which is what the first run of
  # this test did on all five fixtures at once. A script-scope slot has no
  # return semantics to get wrong, and it is the same fix as $script:lastwall.
  $script:smokeFail = $fail
}

Test-SmokeLegs $legfile
$fail = @($script:smokeFail)
if ($fail.Count) {
  "JSMOKE-FAIL $($fail.Count) problem(s):"
  $fail | ForEach-Object { "  - $_" }
  "FAIL`n" + ($fail -join "`n") | Set-Content $verdict
  "JSMOKE-VERDICT written to $verdict - jcross will REFUSE to start on this box until it is resolved"
  exit 12
}
"JSMOKE-PASS $($script:smokeLegCount) timed legs, every member restored, arms identical below the gate and divergent above it (m=2048 off=$($script:offAbove) fast=$($script:fastAbove))"
"PASS m2048_off=$($script:offAbove) m2048_fast=$($script:fastAbove) legs=$($script:smokeLegCount) ts=$((Get-Date).ToUniversalTime().ToString('o'))" | Set-Content $verdict
