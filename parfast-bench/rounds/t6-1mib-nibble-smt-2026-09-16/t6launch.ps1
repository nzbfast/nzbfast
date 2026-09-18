# t6launch.ps1 - launch t6wait.ps1 DETACHED from the ssh that starts it.
#
# NOT wlaunch.ps1, and the reason is structural rather than a preference:
# wlaunch REFUSES (exit 17) while the rig lock is held by a live pid, which is
# right for launching a ROUND and exactly wrong for launching a WAITER - the
# lock being held is the whole reason the waiter exists. The detach trick is
# wlaunch's and is copied verbatim: Win32_Process::Create is spawned by
# WmiPrvSE, so the new process is not in the ssh session's JOB OBJECT and
# survives the disconnect, where Start-Process would be killed within a second.
# I do NOT touch, clear or test the lock here; t6wait.ps1 does all three, and
# it never clears one.
$ErrorActionPreference = 'Stop'
$root = '<rig>\t6sep16'
$log  = Join-Path $root 't6wait.out'
$err  = Join-Path $root 't6wait.err'
foreach ($f in @($log, $err)) { if (Test-Path $f) { Remove-Item $f -Force } }
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $root\t6wait.ps1 > $log 2> $err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
if ($r.ReturnValue -ne 0) { "T6LAUNCH-FAILED rc=$($r.ReturnValue)"; exit 2 }
"T6LAUNCH-OK pid=$($r.ProcessId) log=$log err=$err"
