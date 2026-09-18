# cflaunch.ps1 - launch cfwait.ps1 DETACHED from the ssh that starts it.
# Lane parfast-load-term-and-third-binary-i5. This is t6launch.ps1's pattern,
# unchanged except for the paths, and the two reasons it is not something
# simpler are both structural:
#
#  - NOT Start-Process. Windows OpenSSH puts the ssh session in a JOB OBJECT
#    and kills everything in it on disconnect, so a Start-Process'd waiter dies
#    in about a second. Win32_Process::Create is spawned by WmiPrvSE, outside
#    that job, and survives.
#  - NOT wlaunch.ps1. wlaunch REFUSES (exit 17) while the rig lock is held by a
#    live pid, which is right for launching a ROUND and exactly wrong for
#    launching a WAITER: the lock being held is the whole reason the waiter
#    exists.
#
# I do not touch, clear or test the lock here; cfwait.ps1 tests it and never
# clears one.
$ErrorActionPreference = 'Stop'
$root = '<rig>\cfload16sep'
$log  = Join-Path $root 'cfwait.out'
$err  = Join-Path $root 'cfwait.err'
foreach ($f in @($log, $err)) { if (Test-Path $f) { Remove-Item $f -Force } }
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $root\cfwait.ps1 > $log 2> $err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
if ($r.ReturnValue -ne 0) { "CFLAUNCH-FAILED rc=$($r.ReturnValue)"; exit 2 }
"CFLAUNCH-OK pid=$($r.ProcessId) log=$log err=$err"
