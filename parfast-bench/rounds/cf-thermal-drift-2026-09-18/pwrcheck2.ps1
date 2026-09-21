param(
  [int]$Reps = 5,                 # idle comparisons
  [int]$Window = 1,               # seconds per delta window; must match across routes
  [string]$LoadGen = '',          # optional: path to harness/... loadgen.ps1
  [int]$LoadSeconds = 20
)
# pwrcheck2.ps1 - decide, ON A BOX, whether `% Processor Performance` can be
# read the way `Get-PowerState` reads it, and whether the proposed raw-delta
# replacement agrees with the route this repo has already proved.
#
# STEP 1 OF THREE. The other two are in
# rounds/cf-thermal-drift-2026-09-18/README.md. Nothing may be wired
# into plib.ps1 until this script has run green on a Windows box, because a
# harness edit that parses on a Mac and reads empty on Windows is the exact
# failure the FIRST pwrcheck.ps1 was written to exclude - and the defect this
# one exists to settle slipped past that script anyway.
#
# WHY IT EXISTS. `e7f7cd14d` gave every LEG line `perf_pct` and a `freq_mhz`
# derived from it, so that candidate 3 of the within-sitting drift census
# (thermal and frequency drift) could be tested at all. Reduced from the six
# validation legs that lane banked, the end-of-leg frequency spans 912-2585
# MHz - 2.83x - across legs that all held ~10 of 12 threads busy on a box
# whose thermometer read 27.9 C on every single sample. A quantity that moves
# 2.83x while everything that could move it is fixed is not measuring
# frequency. The full argument is in the README beside this file.
#
# THE THREE ROUTES, and the point is that they are read AT THE SAME MOMENT on
# ONE box. The existing evidence compares a reading from 18 Sep against one
# from 4 Sep, which is enough to convict but not enough to sign off a fix:
#
#   A  cooked CIM, single un-refreshed query  - what Get-PowerState does today
#   B  Get-Counter -SampleInterval -MaxSamples - the route
#      an internal note section 2a PROVED, and the
#      reference every other route is judged against here
#   C  raw-delta bracket, computed in the harness - the proposed replacement
#
# C IS THE CANDIDATE AND NOT MERELY A FIX. B is correct and unusable in the
# place the harness needs it: a delta counter needs an interval, the AFTER
# sample is taken within ~300 ms of the child exiting, and a one-second
# interval starting there integrates the idle decay rather than the leg. C
# brackets the leg with two cheap raw reads and divides the deltas itself, so
# it returns the average over EXACTLY the leg's own window - which also
# retires the stated limit wcomb.ps1's header carries ("the samples BRACKET
# the leg, they do not average it").
#
# IT REFUSES RATHER THAN FALLING BACK. If the raw class is absent, or does not
# carry the two properties C needs, this script says so by name and exits
# non-zero. A validator that quietly substitutes a route it can reach would
# report agreement between two copies of the same wrong number, which is the
# rubber-stamp failure this repo names in its gate rules. Failing to find is
# failing.
#
# IDLE IS ENOUGH, and that is deliberate. The disagreement to be settled is
# already a factor of four AT IDLE: route A read 24-30% of nominal on an idle
# intel-i5-10600kf in the banked legs, and route B read 109.74-110.45% on the same
# idle box, flat to a third of a percent across five calls. So the default
# arm needs no load generator, no exclusive box and about half a minute, and
# a lane can run it while somebody else owns the machine for real work. The
# -LoadGen arm is a bonus and is OFF by default; when used it reuses
# loadgen.ps1, which carries two independent internal deadlines, and never a
# spinner written here - memory topic
# `nzbfast-orphaned-load-generators-skew-a-whole-day`.
$ErrorActionPreference = 'Stop'
function Say([string]$m) { "$((Get-Date).ToUniversalTime().ToString('o')) $m" }

Say "PWRCHECK2 start host=$env:COMPUTERNAME reps=$Reps window=${Window}s"
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$nominal = [int]$cpu.MaxClockSpeed
Say "BOX cpu=$($cpu.Name) nominal_mhz=$nominal cores=$($cpu.NumberOfCores) threads=$($cpu.NumberOfLogicalProcessors)"
Say "NOTE nominal is Win32_Processor.MaxClockSpeed and is a NOMINAL, not a ceiling - on Core Ultra 9 386H it is the P-core nominal 2100 and understates the part 2.3x. Every route below is reported in PERCENT OF NOMINAL first for that reason; the MHz column is the percent times this number and is only as meaningful as it is."

# --- route C's preconditions, checked by name before anything is compared ---
$rawClass = 'Win32_PerfRawData_Counters_ProcessorInformation'
try {
  $raw = Get-CimInstance $rawClass -Filter "Name='_Total'" -ErrorAction Stop | Select-Object -First 1
} catch {
  Say "REFUSE raw class $rawClass is not queryable on this box: $($_.Exception.Message)"
  exit 3
}
if (-not $raw) { Say "REFUSE $rawClass has no Name='_Total' instance"; exit 3 }
$props = ($raw | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)
$need  = @('PercentProcessorPerformance', 'PercentProcessorPerformance_Base')
$miss  = @($need | Where-Object { $props -notcontains $_ })
if ($miss.Count -gt 0) {
  Say "REFUSE $rawClass is missing $($miss -join ', ')"
  Say "REFUSE the properties it DOES carry, so the fix can be repointed rather than guessed: $(($props | Where-Object { $_ -like '*Processor*' }) -join ', ')"
  exit 3
}
Say "RAW-CLASS ok $rawClass carries $($need -join ' and ')"

function Read-RouteA {
  # Exactly what Get-PowerState does today: ONE un-refreshed cooked query.
  $p = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation `
         -Filter "Name='_Total'" -ErrorAction Stop | Select-Object -First 1
  return [double]$p.PercentProcessorPerformance
}
function Read-RouteB([int]$secs) {
  # The proven route. MaxSamples 2 and DISCARD the first: sample 1 of a
  # -SampleInterval series is itself a single raw sample and carries the very
  # artefact this is the reference for.
  $s = Get-Counter '\Processor Information(_Total)\% Processor Performance' `
         -SampleInterval $secs -MaxSamples 2 -ErrorAction Stop
  return [double]($s[1].CounterSamples.CookedValue)
}
function Read-RouteC([int]$secs) {
  # The candidate: bracket the window, divide the deltas here. This is what
  # Get-PowerState would do around a leg, with $secs replaced by the leg.
  $a = Get-CimInstance $rawClass -Filter "Name='_Total'" -ErrorAction Stop | Select-Object -First 1
  Start-Sleep -Seconds $secs
  $b = Get-CimInstance $rawClass -Filter "Name='_Total'" -ErrorAction Stop | Select-Object -First 1
  $dn = [double]$b.PercentProcessorPerformance - [double]$a.PercentProcessorPerformance
  $dd = [double]$b.PercentProcessorPerformance_Base - [double]$a.PercentProcessorPerformance_Base
  if ($dd -eq 0) { return [double]::NaN }
  return 100.0 * $dn / $dd
}

function Run-Arm([string]$arm) {
  $A = @(); $B = @(); $C = @()
  Say "ARM $arm"
  Say "  rep |   A cooked-1shot |   B Get-Counter |   C raw-delta   (percent of nominal / MHz)"
  for ($i = 1; $i -le $Reps; $i++) {
    $a = Read-RouteA
    $b = Read-RouteB $Window
    $c = Read-RouteC $Window
    $A += $a; $B += $b; $C += $c
    Say ("  {0,3} | {1,7:N2} / {2,5:N0} | {3,7:N2} / {4,5:N0} | {5,7:N2} / {6,5:N0}" -f `
         $i, $a, ($nominal*$a/100), $b, ($nominal*$b/100), $c, ($nominal*$c/100))
  }
  foreach ($pair in @(@('A cooked-1shot',$A), @('B Get-Counter',$B), @('C raw-delta',$C))) {
    $n = $pair[0]; $v = $pair[1]
    $mn = ($v | Measure-Object -Minimum).Minimum
    $mx = ($v | Measure-Object -Maximum).Maximum
    $av = ($v | Measure-Object -Average).Average
    $sp = if ($mn -ne 0) { $mx / $mn } else { [double]::NaN }
    Say ("  SPREAD $arm {0,-14} mean {1,7:N2}  range {2,7:N2}-{3,7:N2}  ratio {4,5:N2}x" -f $n, $av, $mn, $mx, $sp)
  }
  # The verdict this script exists to give, stated as a comparison and not a
  # threshold: B is the reference, so what matters is which of A and C tracks
  # it. Printed as the ratio of means; a reader checks it against the per-rep
  # table above rather than trusting one number.
  $mb = ($B | Measure-Object -Average).Average
  if ($mb -ne 0) {
    Say ("  VERDICT $arm  A/B = {0,5:N2}   C/B = {1,5:N2}   (1.00 is agreement with the proven route)" -f `
         ((($A | Measure-Object -Average).Average) / $mb), ((($C | Measure-Object -Average).Average) / $mb))
  }
}

Run-Arm 'idle'

if ($LoadGen) {
  if (-not (Test-Path $LoadGen)) { Say "REFUSE -LoadGen path not found: $LoadGen"; exit 4 }
  # Reused, never re-written, and given a deadline it enforces ITSELF.
  $deadline = (Get-Date).ToUniversalTime().AddSeconds($LoadSeconds + 30).ToString('o')
  Say "LOADGEN starting $LoadGen deadline=$deadline (it stops itself; this script does not depend on killing it)"
  $p = Start-Process -FilePath 'powershell' -PassThru -WindowStyle Hidden `
         -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$LoadGen,
                         '-TargetPct','400','-DeadlineUtc',$deadline,'-MaxSeconds',[string]($LoadSeconds+30))
  Start-Sleep -Seconds 3
  try { Run-Arm 'loaded' } finally {
    Say "LOADGEN leaving pid=$($p.Id) to its own deadline; confirm it is gone before you leave the box"
  }
}

Say "PWRCHECK2 DONE - read the VERDICT lines. C/B near 1.00 with A/B far from it confirms both the defect and the fix; C/B far from 1.00 means the raw-delta formula is wrong and MUST NOT be wired into plib.ps1."
