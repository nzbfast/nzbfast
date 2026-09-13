param(
  [Parameter(Mandatory=$true)][string]$Script,
  [Parameter(Mandatory=$true)][string]$Tag,
  [string]$Root = '<rig>',
  [double]$QuietPct = 3.0,        # foreign CPU as a share of the WHOLE box
  [int]$IdleLockMin = 30,         # the rig lock must have been absent this long
  [int]$QuietSamples = 10,        # consecutive one-minute samples under QuietPct
  [int]$MaxWaitH = 72
)
# wquiet.ps1 - the Windows twin of waitquiet.py: start a round only once the box
# has been FREE and QUIET for a stated stretch. Two conditions, both stated on
# every line it prints, so a reader can see what it was waiting for:
#   1. no rig lock for IdleLockMin minutes running - a box that other rounds
#      keep taking is in use, whatever the CPU says between them;
#   2. foreign CPU under QuietPct of the whole box for QuietSamples samples in
#      a row - a tighter bar than the leg guard's 10%, because this exists to
#      buy clean numbers, not merely valid ones.
# It never takes the lock itself; wlaunch.ps1 does that through the round.
. (Join-Path $Root 'plib.ps1')
$lock = Join-Path $env:USERPROFILE '.parfast-rig.lock'
$cores = (Get-CimInstance Win32_Processor | Measure-Object NumberOfLogicalProcessors -Sum).Sum
$ceiling = $cores * $QuietPct
$deadline = (Get-Date).AddHours($MaxWaitH)
$lockFreeSince = $null; $quiet = 0
"WQUIET-START tag=$Tag quiet_pct=$QuietPct ceiling=$ceiling% idle_lock_min=$IdleLockMin samples=$QuietSamples ts=$((Get-Date).ToUniversalTime().ToString('o'))"
while ((Get-Date) -lt $deadline) {
  if (Test-Path $lock) { $lockFreeSince = $null; $quiet = 0; "WAIT lock-present ts=$((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))Z"; Start-Sleep 60; continue }
  if (-not $lockFreeSince) { $lockFreeSince = Get-Date }
  $idle = ((Get-Date) - $lockFreeSince).TotalMinutes
  $f = Get-ForeignCpu
  if ($f -ge 0 -and $f -lt $ceiling) { $quiet++ } else { $quiet = 0 }
  "WAIT foreign_cpu=$f% ceiling=$ceiling% quiet_samples=$quiet/$QuietSamples lock_free_min=$([math]::Round($idle)) ts=$((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))Z"
  if ($idle -ge $IdleLockMin -and $quiet -ge $QuietSamples) {
    "BOX-QUIET starting $Script ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    & (Join-Path $Root 'wlaunch.ps1') -Script $Script -Tag $Tag -Root $Root -Force
    exit $LASTEXITCODE
  }
  Start-Sleep 60
}
"WQUIET-TIMEOUT never quiet in ${MaxWaitH}h"; exit 19
