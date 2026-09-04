# PAR2 component round, Windows: the repair and verify legs. The twin of
# par2-round.sh, same protocol - fresh copy, pre-warm every byte, lift
# the process to High priority, time it, gate on SHA256 identity.
#
# High priority is not a nicety here: without it Windows execution-speed
# throttling demotes sustained work onto efficiency cores a few seconds
# in, which took one heavy repair leg from 17 s to 58 s and measured the
# scheduler rather than the tool.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File par2-round.ps1 `
#       -Rounds 3 [-Legs verify,3,101,heavy] [-Tools ours,turbo16]
#       [-Timing 1] [-Layout mirror] [-SettleMs 1000] [-Reps 2]
#
# SHIP IT AS A FILE and run it that way. The default shell over ssh to
# these boxes is cmd and inlining PowerShell through it mangles `&&`
# and `;` - the shell then silently runs half the script.
#
# Legs and arms as par2-round.sh, including m<N> crossover legs built by
# par2-mkdamage.ps1, the dense/forney back-substitution pair (whose
# rig caveat is spelled out in par2-round.sh's header: the published
# 10% heavy set caps N at 1,638, under the shipped gate) and the
# sched16/sched32 fold-geometry pair with its own A/A twin sched16b.
# Method and results: research/PAR2-PERF-AUDIT-2026-09-02.md sections 1,
# 2a, 7, 20 and 22h.
#
# -Layout mirror / -SettleMs / -Reps are the protocol this box needs and
# all three default OFF; the one change a bare run does carry is that the
# arm order now ROTATES by round in the script rather than by hand, which
# is what the audit's own protocol asked for. THE REASON FOR THE REST IS
# MEASURED, on this same Windows box: two big writes back
# to back with no idle between them latch for a whole run with a RANDOM
# SIGN, so a pair of BYTE-IDENTICAL arms reads as a clean 0/6 or 6/6
# sweep - the statistic a lane trusts most (audit round 40,
# research/RAR-PERF-AUDIT-2026-09-02.md, and the long comment at
# bench/component/shootout.rs's order/settle site). One second of idle
# between legs removes it. `mirror` runs the round's arm order and then
# its reverse (A B B A), so both arms hold both positions inside one
# round; `-Reps` repeats that within a round so a round yields a median
# rather than a single sample. Use `-Layout mirror -SettleMs 1000` for
# any two-arm A/B here, and PROVE THE PROTOCOL FIRST with the A/A -
# `-Tools sched16,sched16b`, which is one binary against itself and must
# come out flat before either real arm is believed.
param(
  [string]$Root   = "$env:USERPROFILE\paraudit",
  [string]$Ours   = "$env:USERPROFILE\paraudit\bin\par2_repair_dir.exe",
  [string]$Turbo  = "$env:USERPROFILE\paraudit\bin\turbo150\par2.exe",
  # The PRODUCT arm, added 4 Sep 2026 to match the shell rig: `ours` is
  # the par2_repair_dir harness and measures the ENGINE, `parfast` is the
  # binary a user actually runs. A release table has to come from the
  # second one, argument parsing and output layer included.
  [string]$Parfast = "$env:USERPROFILE\paraudit\bin\parfast.exe",
  [int]$Rounds    = 3,
  [string]$Legs   = "verify,3,101,heavy",
  [string]$Tools  = "ours,turbo16,turbo",
  [string]$Timing = "",
  # Protocol knobs - see the header. All three default to the old shape.
  [ValidateSet("rotate","mirror")]
  [string]$Layout = "rotate",
  [int]$SettleMs  = 0,
  [int]$Reps      = 1
)
$ErrorActionPreference = "Continue"
$rig = "$Root\rig"; $work = "$Root\work"
$pristineSha = @{}
Get-ChildItem "$rig\pristine\*" -File | ? { $_.Name -notlike "*.par2" } | % {
  $pristineSha[$_.Name] = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash
}
$total = $pristineSha.Count
"BIN ours $((Get-FileHash -Algorithm SHA256 $Ours).Hash) $((Get-Item $Ours).Length)"
"BIN turbo $(& $Turbo --version 2>&1 | select -First 1)"
"CPU $((Get-CimInstance Win32_Processor).Name)  load: $((Get-CimInstance Win32_Processor).LoadPercentage)%"
"PROTOCOL rounds=$Rounds layout=$Layout settle_ms=$SettleMs reps=$Reps legs=$Legs tools=$Tools"
function Invoke-Arm([string]$exe, [string[]]$argv, [hashtable]$envs) {
  foreach ($k in $envs.Keys) { Set-Item "Env:$k" $envs[$k] }
  $p = Start-Process -FilePath $exe -ArgumentList $argv -NoNewWindow -PassThru `
        -RedirectStandardOutput "$Root\last.out" -RedirectStandardError "$Root\last.err"
  try { $p.PriorityClass = "High" } catch {}
  $p.WaitForExit()
  foreach ($k in $envs.Keys) { if ($k -ne "NZBFAST_REPAIR_TIMING") { Remove-Item "Env:$k" -EA SilentlyContinue } }
}
foreach ($r in 1..$Rounds) {
  foreach ($leg in $Legs.Split(",")) {
    switch ($leg) {
      "verify" { $src = "pristine" }
      "3"      { $src = "damaged-3" }
      "101"    { $src = "damaged-101" }
      "heavy"  { $src = "damaged-heavy" }
      default  { $src = "damaged-$leg" }
    }
    # The round's arm order: rotated by round so each arm holds each
    # position across rounds, mirrored within the round when asked so it
    # holds both inside ONE round, and repeated -Reps times.
    $arms = $Tools.Split(",")
    $base = @(); foreach ($i in 0..($arms.Count - 1)) { $base += $arms[($i + $r - 1) % $arms.Count] }
    $order = @()
    foreach ($q in 1..$Reps) {
      $order += $base
      if ($Layout -eq "mirror") { $order += ($base[($base.Count - 1)..0]) }
    }
    $pos = 0
    foreach ($tool in $order) {
      $pos++
      # Idle OUTSIDE every timed region. This is the line that breaks the
      # back-to-back-write latch; do not move it inside the stopwatch.
      if ($SettleMs -gt 0) { Start-Sleep -Milliseconds $SettleMs }
      if (Test-Path $work) { Remove-Item -Recurse -Force $work }
      Copy-Item -Recurse "$rig\$src" $work
      Get-ChildItem $work -File | % { $null = [System.IO.File]::ReadAllBytes($_.FullName) }  # pre-warm
      # The set's own index name differs between rigs; believe the corpus.
      $par = (Get-ChildItem "$work\*.par2" | ? { $_.Name -notmatch "vol" } | select -First 1).Name
      Push-Location $work
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      switch ($tool) {
        "ours"    { Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing } }
        "fold"    { Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing; NZBFAST_NTT = "0" } }
        "ntt"     { Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing; NZBFAST_NTT = "force" } }
        "dense"   { Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing; NZBFAST_BACKSUB = "dense" } }
        "forney"  { Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing; NZBFAST_BACKSUB = "forney" } }
        # The fold-schedule geometry pair (audit 22h). One binary, two
        # env settings, so no arm can secretly be the other; sched16b is
        # sched16's byte-identical twin and exists to be the A/A control.
        "sched16" { Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing; NZBFAST_GF16_GRANULE = "16" } }
        "sched16b"{ Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing; NZBFAST_GF16_GRANULE = "16" } }
        "sched32" { Invoke-Arm $Ours  @(".")                 @{ NZBFAST_REPAIR_TIMING = $Timing; NZBFAST_GF16_GRANULE = "32" } }
        "parfast" { Invoke-Arm $Parfast @("r","-q",$par)      @{} }
        "turbo16" { Invoke-Arm $Turbo @("r","-q","-T16",$par) @{} }
        "turbo"   { Invoke-Arm $Turbo @("r","-q",$par)        @{} }
      }
      $sw.Stop()
      $ok = 0
      Get-ChildItem "$work\*" -File | ? { $_.Name -notlike "*.par2" } | % {
        if ((Get-FileHash -Algorithm SHA256 $_.FullName).Hash -eq $pristineSha[$_.Name]) { $ok++ }
      }
      Pop-Location
      "LEG r=$r pos=$pos leg=$leg tool=$tool wall=$([math]::Round($sw.Elapsed.TotalSeconds,3)) sha_ok=$ok/$total"
      if ($Timing) { Get-Content "$Root\last.err" -EA SilentlyContinue | Select-String "repair-timing" |
                     % { "    " + ($_ -replace '.*repair-timing: ','') } }
    }
  }
}
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
