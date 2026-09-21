# fpk-launch.ps1 - launch fpk-round.ps1 DETACHED from the ssh that starts it.
# Lane fold-parallelism-knee-18sep. This is cflaunch.ps1's pattern, unchanged
# except for the paths, and the two reasons it is not something simpler are
# both structural:
#
#  - NOT Start-Process. Windows OpenSSH puts the ssh session in a JOB OBJECT
#    and kills everything in it on disconnect, so a Start-Process'd round dies
#    in about a second.  Win32_Process::Create is spawned by WmiPrvSE, outside
#    that job, and survives.
#  - NOT wlaunch.ps1. The chip's box-discipline section names it as the older
#    pattern; cflaunch is the current one.
#
# I do not touch, clear or test the rig lock here. fpk-round.ps1's load gate
# tests it and never clears one.
$ErrorActionPreference = 'Stop'
$root = '<rig>\fpk18sep'
$log  = Join-Path $root 'fpk-driver.log'
$err  = Join-Path $root 'fpk-driver.err'
foreach ($f in @($log, $err)) { if (Test-Path $f) { Remove-Item $f -Force } }
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $root\harness\fpk-round.ps1 > $log 2> $err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
if ($r.ReturnValue -ne 0) { "FPKLAUNCH-FAILED rc=$($r.ReturnValue)"; exit 2 }
"FPKLAUNCH-OK pid=$($r.ProcessId) log=$log err=$err"
