param([string]$Root = '<rig>\catwin-15sep', [string]$MainSha = '', [string]$NotBeforeUtc = '', [switch]$ParseOnly)
# Parse-check catwin.ps1, then start it DETACHED (Win32_Process::Create, the
# wlaunch.ps1 job-object trap). Not wlaunch itself: it refuses while another
# round holds the rig lock, and catwin.ps1 is built to WAIT for that lock.
$ProgressPreference = 'SilentlyContinue'
$script = Join-Path $Root 'catwin.ps1'
Unblock-File $script
$toks = $null; $errs = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$toks, [ref]$errs)
"PARSE errors=$($errs.Count)"
foreach ($e in $errs) { "  line $($e.Extent.StartLineNumber): $($e.Message)" }
if ($errs.Count -gt 0 -or $ParseOnly) { exit $errs.Count }
$log = Join-Path $Root 'catwin.log'
$err = Join-Path $Root 'catwin.err'
if (Test-Path $log) { "LAUNCH-REFUSED $log exists"; exit 1 }
$nb = if ($NotBeforeUtc) { " -NotBeforeUtc $NotBeforeUtc" } else { '' }
$cmd = "cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -File $script -Root $Root -MainSha $MainSha$nb > $log 2> $err"
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
"LAUNCH rc=$($r.ReturnValue) cmd_pid=$($r.ProcessId)"
Start-Sleep -Seconds 5
Get-Content $log -ErrorAction SilentlyContinue
Get-Content $err -ErrorAction SilentlyContinue
