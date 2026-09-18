param([Parameter(Mandatory=$true)][string]$Tag, [Parameter(Mandatory=$true)][string]$Plan, [int]$MaxReps = 3, [string]$Bin = '')
# oramxl.ps1 - launch oramx.ps1 DETACHED (Win32_Process::Create), so it
# survives the ssh session that started it (wlaunch.ps1's header). The plan
# is written to a file first, because a ';'-separated plan does not survive
# cmd.exe's command line. -Bin names a binary other than bin\parfast.exe, so
# a candidate round never replaces the binary a running round is using.
$R0 = Join-Path $env:USERPROFILE 'oram-15sep'
$log = "$R0\$Tag.log"
if (Test-Path $log) { "ORAMXL-REFUSED $log exists"; exit 1 }
$planfile = "$R0\$Tag.plan"
[IO.File]::WriteAllText($planfile, $Plan)
$binarg = if ($Bin) { " -Bin '$Bin'" } else { '' }
$runner = "$R0\harness\run-$Tag.ps1"
[IO.File]::WriteAllText($runner, "& '$R0\harness\oramx.ps1' -Root '$R0' -Tag '$Tag' -Plan ([IO.File]::ReadAllText('$planfile')) -Par2 '$R0\bin\par2.exe' -MaxReps $MaxReps$binarg`r`n")
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $runner > $log 2> $R0\$Tag.err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
"ORAMXL rc=$($r.ReturnValue) pid=$($r.ProcessId) tag=$Tag"
