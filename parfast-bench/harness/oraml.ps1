param([string]$Tag = 'oram1', [string]$Par2 = '')
# oraml.ps1 - launch oram.ps1 DETACHED (Win32_Process::Create), so it
# survives the ssh session that started it (wlaunch.ps1's header). Not
# wlaunch itself: that refuses while a live rig lock exists, and this round
# is meant to be queued behind one (pass oram.ps1 its -After* arguments by
# editing the command line below for the round you are queueing behind).
$R0 = Join-Path $env:USERPROFILE 'oram-15sep'
$log = "$R0\$Tag.log"
if (Test-Path $log) { "ORAML-REFUSED $log exists"; exit 1 }
$p2 = if ($Par2) { " -Par2 $Par2" } else { '' }
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $R0\harness\oram.ps1 -Root $R0 -Tag $Tag$p2 > $log 2> $R0\$Tag.err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
"ORAML rc=$($r.ReturnValue) pid=$($r.ProcessId) cmd=$cmd"
