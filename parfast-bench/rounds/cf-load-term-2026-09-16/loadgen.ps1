param(
  [Parameter(Mandatory=$true)][double]$TargetPct,    # percent of ONE core, e.g. 70 = 0.70 of a core
  [Parameter(Mandatory=$true)][string]$DeadlineUtc,  # ISO-8601 Z. HARD internal stop.
  [int]$MaxSeconds = 1500,                           # SECOND, independent internal bound
  [int]$BufKiB = 4096,                               # working set the co-runner displaces
  [string]$Log = ''
)
# loadgen.ps1 - a steady synthetic co-runner for lane
# parfast-load-term-and-third-binary-i5, on intel-i5-10600kf.
#
# WHY THIS SCRIPT HAS TWO INDEPENDENT INTERNAL DEADLINES AND NO RELIANCE ON
# ANYONE KILLING IT. On 10 Sep 2026 an under-load experiment in this repo left
# 352 busy loops on an M3 Ultra, ppid 1, running 6 h 39 m, holding the box at
# 0% idle and load average 478 - and nothing crashed. Legs completed, SHA gates
# passed, and every wall and CPU number taken on that box for most of a day was
# ~10x too large; two artefacts were written from inside that window and both
# drew a wrong conclusion. The mechanism was banal: the script ENDED with a
# cleanup loop that killed its children, the parent shell died before reaching
# it, and every child was reparented to init. Memory topic
# `nzbfast-orphaned-load-generators-skew-a-whole-day`.
#
# So a cleanup step in the launcher is the BELT and it is not enough. The
# BRACES are here, inside the thing that burns the CPU:
#
#   1. $DeadlineUtc, an absolute wall-clock instant this process checks itself
#      roughly every 2 ms. It stops on schedule whether or not its launcher,
#      its shell, the ssh session or the whole Claude session still exists.
#   2. $MaxSeconds from ITS OWN START, which bounds it even if the deadline
#      string names an instant far in the future (a mistyped year, a timezone
#      slip, a clock that moved). The effective stop is the EARLIER of the two.
#
# Both are checked in the same hot loop, so neither depends on the other, and a
# parse failure of $DeadlineUtc THROWS rather than defaulting - a generator that
# cannot compute its own stop time must not start. Fail-safe, never fail-open.
#
# WHAT THE LOAD IS, which matters for how the result may be read. A busy loop,
# a compiler and an Adobe updater do not stress the same resource, so this one
# is deliberately a mix of both things a real co-runner does: it burns ALU in a
# tight kernel AND walks a $BufKiB buffer at 64-byte stride, read-modify-write,
# so it displaces L3 as well as consuming scheduler time. The i5-10600KF has
# 12 MiB of L3; the default 4 MiB is a third of it, which is a realistic
# neighbour rather than a pathological thrasher. The write-up MUST say this,
# because the coefficient this round measures is a coefficient against THIS
# load and is not a general correction factor.
#
# LEVEL CONTROL is closed-loop rather than a fixed duty cycle: Windows' default
# timer granularity is ~15.6 ms, so a "spin 7 ms, sleep 3 ms" duty cycle would
# silently deliver ~32% where it claimed 70%. Instead the loop reads its OWN
# TotalProcessorTime against wall elapsed over a rolling 0.5 s window and
# spins or sleeps to steer the ratio to $TargetPct. The achieved level is not
# assumed either way: every leg's own `foreign_cpu` field is the independent
# variable the round actually reports.
$ErrorActionPreference = 'Stop'

# Parse FIRST and let a bad string kill the process before it burns anything.
$styles = [Globalization.DateTimeStyles]([int][Globalization.DateTimeStyles]::AdjustToUniversal -bor
                                        [int][Globalization.DateTimeStyles]::AssumeUniversal)
$deadline = [datetime]::Parse($DeadlineUtc, [Globalization.CultureInfo]::InvariantCulture, $styles)
$startUtc = (Get-Date).ToUniversalTime()
$hardStop = $startUtc.AddSeconds($MaxSeconds)
if ($deadline -lt $hardStop) { $hardStop = $deadline }
if ($hardStop -le $startUtc) { throw "loadgen: stop time $hardStop is not in the future (now $startUtc)" }

if (-not ('Burn' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
public static class Burn {
  // Spin for about `ms` milliseconds, touching `buf` at 64-byte stride so the
  // co-runner displaces cache as well as consuming a core. Returns the number
  // of bytes touched, only so the JIT cannot elide the loop.
  public static long Spin(byte[] buf, int ms, ref int cursor) {
    Stopwatch sw = Stopwatch.StartNew();
    long touched = 0;
    int c = cursor;
    int n = buf.Length;
    while (sw.Elapsed.TotalMilliseconds < ms) {
      for (int i = 0; i < 4096; i++) {
        c += 64;
        if (c >= n) c -= n;
        buf[c] = (byte)(buf[c] + 1);
        touched += 64;
      }
    }
    cursor = c;
    return touched;
  }
}
'@
}

$proc = [Diagnostics.Process]::GetCurrentProcess()
$buf  = New-Object byte[] ($BufKiB * 1024)
$cur  = 0
$touched = 0L

function Say([string]$m) {
  $line = "$((Get-Date).ToUniversalTime().ToString('o')) loadgen pid=$PID $m"
  Write-Output $line
  if ($Log) { try { Add-Content -Path $Log -Value $line -ErrorAction SilentlyContinue } catch { } }
}

Say "START target_pct=$TargetPct buf_kib=$BufKiB deadline=$($deadline.ToString('o')) max_s=$MaxSeconds hard_stop=$($hardStop.ToString('o'))"

$winSecs = 0.5
$sw      = [Diagnostics.Stopwatch]::StartNew()
$winT0   = $sw.Elapsed.TotalSeconds
$winC0   = $proc.TotalProcessorTime.TotalSeconds
$lastRep = $sw.Elapsed.TotalSeconds

try {
  while ((Get-Date).ToUniversalTime() -lt $hardStop) {
    $now  = $sw.Elapsed.TotalSeconds
    $wall = $now - $winT0
    $cpu  = $proc.TotalProcessorTime.TotalSeconds - $winC0
    if ($wall -ge $winSecs) { $winT0 = $now; $winC0 = $proc.TotalProcessorTime.TotalSeconds; continue }
    $ratio = if ($wall -gt 0.01) { 100.0 * $cpu / $wall } else { 0.0 }
    if ($ratio -gt $TargetPct) {
      [Threading.Thread]::Sleep(2)
    } else {
      $touched += [Burn]::Spin($buf, 2, [ref]$cur)
    }
    if (($now - $lastRep) -ge 60) {
      $lastRep = $now
      $achieved = [math]::Round(100.0 * $proc.TotalProcessorTime.TotalSeconds / $now, 1)
      Say "HEARTBEAT achieved_pct_since_start=$achieved elapsed_s=$([math]::Round($now,0)) remaining_s=$([math]::Round(($hardStop - (Get-Date).ToUniversalTime()).TotalSeconds,0))"
    }
  }
} finally {
  $el = $sw.Elapsed.TotalSeconds
  $achieved = if ($el -gt 0) { [math]::Round(100.0 * $proc.TotalProcessorTime.TotalSeconds / $el, 1) } else { 0 }
  Say "STOP reason=deadline elapsed_s=$([math]::Round($el,1)) achieved_pct=$achieved touched_mib=$([math]::Round($touched/1MB,0))"
}
