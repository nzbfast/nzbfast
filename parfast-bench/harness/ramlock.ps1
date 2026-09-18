param(
  [Parameter(Mandatory=$true)][int]$TargetAvailMB,   # leave this much AvailableMBytes behind
  [Parameter(Mandatory=$true)][string]$ReadyFile,
  [Parameter(Mandatory=$true)][string]$StopFile,
  [Parameter(Mandatory=$true)][int]$ParentPid
)
# ramlock.ps1 - pin physical RAM so a big box behaves like a smaller one for
# the FILE CACHE (TODO 345). KEEP THIS FILE PURE ASCII.
#
# A per-process cap (a job's working-set limit) would NOT reproduce a file
# larger than RAM: the pages it trims go to the standby list and come back as
# soft faults. The standby list itself has to shrink, and only taking physical
# memory away does that. So this process raises its own minimum working set
# (SetProcessWorkingSetSizeEx - SeIncreaseBasePriorityPrivilege, held by an
# administrator's token) and VirtualLocks enough committed memory that
# AvailableMBytes falls to the target. No system setting is changed, nothing
# survives a reboot, and every locked page is returned the moment this process
# exits - including when it is killed. It exits by itself when the stop file
# appears or its parent round is gone.
$ErrorActionPreference = 'Stop'
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class RamHog {
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetProcessWorkingSetSizeEx(IntPtr h, UIntPtr min, UIntPtr max, uint flags);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr size, uint type, uint prot);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualLock(IntPtr a, UIntPtr size);
  public static string Lock(long bytes) {
    ulong min = (ulong)bytes + (768UL << 20);
    ulong max = min + (512UL << 20);
    if (!SetProcessWorkingSetSizeEx(GetCurrentProcess(), (UIntPtr)min, (UIntPtr)max, 0))
      return "wsfail err=" + Marshal.GetLastWin32Error();
    long chunk = 256L << 20;
    long done = 0;
    while (done < bytes) {
      long n = Math.Min(chunk, bytes - done);
      IntPtr p = VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)n, 0x3000, 0x04);
      if (p == IntPtr.Zero) return "allocfail at=" + done + " err=" + Marshal.GetLastWin32Error();
      if (!VirtualLock(p, (UIntPtr)(ulong)n)) return "lockfail at=" + done + " err=" + Marshal.GetLastWin32Error();
      done += n;
    }
    return "ok locked=" + done;
  }
}
"@
function Get-AvailMB { [int64](Get-CimInstance Win32_PerfRawData_PerfOS_Memory).AvailableMBytes }
Remove-Item $ReadyFile, $StopFile -Force -ErrorAction SilentlyContinue
$before = Get-AvailMB
$lockmb = $before - $TargetAvailMB
if ($lockmb -lt 0) { $lockmb = 0 }
# A locked page is COMMITTED memory, so the lock spends commit charge as well
# as RAM. These boxes are somebody's desktop with a small pagefile: never take
# the machine within 12 GB of its commit limit, or the round would make other
# programs' allocations fail. A capped lock is reported, and the leg lines'
# avail_mb fields show what the file cache actually had.
$pm = Get-CimInstance Win32_PerfRawData_PerfOS_Memory
$headmb = [int64](([int64]$pm.CommitLimit - [int64]$pm.CommittedBytes) / 1MB)
$capmb = $headmb - 12288
$capped = $false
if ($lockmb -gt $capmb) { $lockmb = [math]::Max([int64]0, $capmb); $capped = $true }
$res = if ($lockmb -gt 0) { [RamHog]::Lock([int64]$lockmb * 1MB) } else { 'ok locked=0' }
Start-Sleep 5
$after = Get-AvailMB
[IO.File]::WriteAllText($ReadyFile, "target_avail_mb=$TargetAvailMB avail_before_mb=$before commit_headroom_mb=$headmb lock_mb=$lockmb capped=$capped result=[$res] avail_after_mb=$after pid=$PID")
while (-not (Test-Path $StopFile)) {
  if (-not (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) { break }
  Start-Sleep 2
}
