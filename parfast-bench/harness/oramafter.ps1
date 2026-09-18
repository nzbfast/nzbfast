param(
  [Parameter(Mandatory=$true)][string]$AfterTag,   # the round on this box to wait out
  [Parameter(Mandatory=$true)][string]$Tag,
  [Parameter(Mandatory=$true)][string]$Plan,
  [Parameter(Mandatory=$true)][string]$Bin,
  [int]$MaxReps = 3,
  [int]$WaitHours = 6,
  [string]$AfterCmd = ''                           # optional: ALSO wait until no powershell command line matches this regex
)
# oramafter.ps1 - start an oramx round once THIS box's previous oramx round
# has ended (its log reads ALL DONE or a FAIL, or its runner is gone), and
# the rig lock is unheld. Launch it detached like oramxl.ps1. KEEP PURE ASCII.
# -AfterCmd waits out a FOREIGN round as well (another lane's harness, which
# writes no oramx log): pass -AfterTag none and a regex naming its scripts
# (added 15 Sep 2026 for TODO 345 C, queued behind rgbs-15sep's wcomb round).
#
# IT OBSERVES THE LOCK AND NEVER TAKES IT - the round oramxl launches does that,
# through oramx.ps1's Take-RigLock. So it asks plib's read-only Test-RigLockHeld
# rather than Test-Path: until 16 Sep 2026 this loop read the lock file's mere
# EXISTENCE as a hold, so an ORPHANED lock naming a dead pid would have held it
# at `Start-Sleep 30` until -WaitHours expired and it exited 19, for a box that
# was free the whole time. That is the apple-m3-ultra failure in miniature
# (an internal note); liveness comes from
# the HOLDER, never from the clock, and plib.ps1's Get-RigLockHolder is the one
# place that rule lives.
$R0 = Join-Path $env:USERPROFILE 'oram-15sep'
. (Join-Path $R0 'harness\plib.ps1')
function Ts { (Get-Date).ToUniversalTime().ToString('o') }
"ORAMAFTER-START after=$AfterTag aftercmd=[$AfterCmd] tag=$Tag $(Ts)"
$until = (Get-Date).AddHours($WaitHours)
while ($true) {
  $t = Get-Content "$R0\$AfterTag.log" -ErrorAction SilentlyContinue
  $ended = [bool]($t -match '^ALL DONE|ORAMX-FAIL|ABORT-LOAD|LOCK-BUSY')
  $alive = [bool](Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match "run-$AfterTag\.ps1|oramx\.ps1" })
  $foreign = $AfterCmd -and [bool](Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match $AfterCmd })
  if (($ended -or -not $alive) -and -not $foreign -and -not (Test-RigLockHeld)) { break }
  if ((Get-Date) -gt $until) { "ORAMAFTER-FAIL predecessor never ended $(Ts)"; exit 19 }
  Start-Sleep 30
}
"ORAMAFTER-GO $(Ts)"
& powershell -NoProfile -ExecutionPolicy Bypass -File "$R0\harness\oramxl.ps1" -Tag $Tag -Plan $Plan -MaxReps $MaxReps -Bin $Bin
