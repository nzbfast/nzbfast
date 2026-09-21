# cfkneelaunch.ps1 - launch cfknee.ps1 DETACHED from the ssh that starts it.
# Lane cf-load-term-knee-rung-18sep. t6launch.ps1's pattern,
# unchanged except for the paths, and the two reasons it is not something
# simpler are both structural:
#
#  - NOT Start-Process. Windows OpenSSH puts the ssh session in a JOB OBJECT
#    and kills everything in it on disconnect, so a Start-Process'd driver dies
#    in about a second. Win32_Process::Create is spawned by WmiPrvSE, outside
#    that job, and survives.
#  - NOT wlaunch.ps1. wlaunch is the right launcher for a round when the lock
#    is free, and it is free now; this stays on the same CIM pattern the rest
#    of the lane's scripts use so there is one detach mechanism to reason about.
#
# I do not touch, clear or test the lock here. cfknee.ps1 takes it, and it
# never clears one it did not prove abandoned.
$ErrorActionPreference = 'Stop'
$root = '<rig>\cfknee18sep'
$log  = Join-Path $root 'cfknee.out'
$err  = Join-Path $root 'cfknee.err'
foreach ($f in @($log, $err)) { if (Test-Path $f) { Remove-Item $f -Force } }
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $root\cfknee.ps1 > $log 2> $err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
if ($r.ReturnValue -ne 0) { "CFKNEELAUNCH-FAILED rc=$($r.ReturnValue)"; exit 2 }
"CFKNEELAUNCH-OK pid=$($r.ProcessId) log=$log err=$err"
