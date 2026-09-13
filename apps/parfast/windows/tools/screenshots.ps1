# Take the phase 0 screenshots: every mock scenario, light and dark.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\screenshots.ps1 -Out $env:USERPROFILE\parfast-shots
#
# These are judged on looks, so they are taken at ONE window
# size (the app's own default, 1280 x 860 LOGICAL pixels) so two rounds of them
# can be compared.
#
# HOW IT DRIVES THE APP. The app carries a --shot switch that opens a scenario,
# runs it to its settled state and reports ready; this script starts one process
# per picture and captures its window. Driving it by simulated clicks would be
# quicker to write and would produce a different set of pictures every run,
# because a click that lands a frame early catches a half-drawn screen.
#
# THE FIRST RUN OF THIS SCRIPT WAS 12 SEP 2026 AND IT DID NOT WORK. Two things
# were wrong, both invisible until a real Windows desktop was involved, and both
# are why the capture below looks nothing like the obvious version:
#
#   1. IT MUST DECLARE ITSELF DPI AWARE BEFORE IT MEASURES ANYTHING. PowerShell
#      is DPI-unaware, so Windows virtualises the coordinates it hands back: on
#      the 192 DPI (200%) panel this was first run on, GetWindowRect reported the
#      app's 1280x860 window as 640x430 and the capture took a quarter of it.
#      SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2) first, and the numbers
#      become the real ones. A capture script that is not DPI aware silently
#      produces a WRONG PICTURE rather than an error, on exactly the
#      high-resolution machines whose pictures anyone would want.
#
#   2. IT MUST NOT READ THE SCREEN. The original used SetForegroundWindow plus
#      Graphics.CopyFromScreen, which captures whatever pixels are on the display
#      at those coordinates - so it needs the app to be genuinely frontmost on an
#      unobstructed, unlocked desktop. This box runs an OEM OLED-care screensaver
#      that takes the desktop on its own, and with it up GetForegroundWindow
#      returns 0, SetForegroundWindow does nothing and every capture came back
#      BLANK WHITE, at the right size, with no error anywhere. That is the worst
#      failure this script could have: sixteen plausible-looking files, in both
#      themes, all empty.
#
#      PrintWindow with PW_RENDERFULLCONTENT (0x2) asks the window to render
#      ITSELF into a bitmap, which works for a WinUI 3 window regardless of what
#      is in front of it, whether it has focus, or whether a screensaver owns the
#      desktop. It also removes the whole class of "another window drifted over
#      the shot". Flag 0 (the plain PrintWindow) is NOT enough - it predates
#      DirectComposition and returns a near-empty frame for a WinUI window;
#      measured on the first run, flag 0 gave 3 distinct colours where flag 2
#      gave 28.
#
# EVERY SHOT IS CHECKED FOR BEING BLANK before it is written, because that is the
# failure this script actually had, and a blank PNG is indistinguishable from a
# good one in a directory listing.
#
# System.Drawing.Common is used for the capture. It is in the .NET SDK on Windows
# and needs no package.

[CmdletBinding()]
param(
    [string]$Out,
    [string]$Exe,
    [int]$SettleSeconds = 6
)

$ErrorActionPreference = "Stop"

# THE DEFAULTS ARE RESOLVED HERE, NOT IN THE param() BLOCK. They were
# `(Join-Path $PSScriptRoot ...)` defaults until 12 Sep 2026, and under
# `powershell -File` $PSScriptRoot is EMPTY while the param defaults are being
# evaluated, so the script died on its own second parameter before running a
# line:
#
#   Join-Path : Cannot bind argument to parameter 'Path' because it is an
#   empty string.  At screenshots.ps1:57
#
# It fails that way whether or not the caller passes the parameter, which is the
# detail worth keeping: passing -Out did not help, because the -Exe default is
# evaluated regardless. $PSCommandPath is populated by then.
$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
if (-not $Out) { $Out = Join-Path $root "out\shots" }
if (-not $Exe) { $Exe = Join-Path $root "out\publish\parfast-gui.exe" }
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
    [DllImport("user32.dll")] public static extern int SetProcessDpiAwarenessContext(IntPtr c);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
"@

# BEFORE ANY MEASUREMENT. -4 is DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2; see
# note 1 in the header for what a virtualised coordinate does to a screenshot.
$dpiRc = [Win]::SetProcessDpiAwarenessContext([IntPtr](-4))
if ($dpiRc -eq 0) { Write-Host "  (could not set DPI awareness; sizes may be virtualised)" -ForegroundColor Yellow }

if (-not (Test-Path $Exe)) { throw "$Exe is not there; run tools\build.ps1 -Publish first" }
New-Item -ItemType Directory -Path $Out -Force | Out-Null

# scenario key, screen to land on, and the file name stem.
$shots = @(
    @{ key = "damaged";      screen = "verify";    name = "01-verify-repairable" },
    @{ key = "clean";        screen = "verify";    name = "02-verify-complete" },
    @{ key = "unrepairable"; screen = "verify";    name = "03-verify-unrepairable" },
    @{ key = "misnamed";     screen = "verify";    name = "04-verify-misnamed" },
    @{ key = "unicode";      screen = "verify";    name = "05-verify-unicode" },
    @{ key = "10k";          screen = "verify";    name = "06-verify-10k-blocks" },
    @{ key = "damaged";      screen = "repaired";  name = "07-verify-repaired" },
    @{ key = "damaged";      screen = "verifying"; name = "08-verify-in-progress" },
    @{ key = "broken";       screen = "verify";    name = "09-verify-failed" },
    @{ key = "";             screen = "empty";     name = "10-verify-empty" },
    @{ key = "slowcreate";   screen = "create";    name = "11-create" },
    @{ key = "slowcreate";   screen = "create-preview"; name = "11b-create-preview" },
    @{ key = "slowcreate";   screen = "progress";  name = "12-create-progress" },
    @{ key = "";             screen = "checksums"; name = "13-checksums" },
    @{ key = "slowcreate";   screen = "queue";     name = "14-queue" },
    @{ key = "";             screen = "settings";  name = "15-settings" },
    @{ key = "damaged";      screen = "log";       name = "16-log-drawer" }
)

# A shot that is one flat colour is the failure this script had, so it is
# refused rather than written. Sampling a grid is enough and costs nothing: a
# real screen of this app has a chrome, a card and a control in it.
function Test-NotBlank([System.Drawing.Bitmap]$bmp) {
    $seen = @{}
    for ($x = 0; $x -lt $bmp.Width; $x += 37) {
        for ($y = 0; $y -lt $bmp.Height; $y += 41) {
            $seen[$bmp.GetPixel($x, $y).ToArgb()] = 1
            if ($seen.Count -gt 4) { return $true }
        }
    }
    return $false
}

$written = 0
$blank = 0
foreach ($theme in @("light", "dark")) {
    foreach ($shot in $shots) {
        $name = "$($shot.name)-$theme.png"
        $path = Join-Path $Out $name
        $shotArgs = @("--mock", "--shot", $shot.screen, "--theme", $theme)
        if ($shot.key) { $shotArgs += @("--scenario", $shot.key) }

        Write-Host "  $name" -NoNewline
        $proc = Start-Process $Exe -ArgumentList $shotArgs -PassThru
        try {
            # Wait for the window rather than sleeping blind, THEN settle: a
            # fixed sleep is either slower than it needs to be or shorter than
            # the app is, depending on the box.
            $handle = [IntPtr]::Zero
            for ($i = 0; $i -lt 20; $i++) {
                Start-Sleep -Seconds 1
                $proc.Refresh()
                if ($proc.HasExited) { break }
                if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { $handle = $proc.MainWindowHandle; break }
            }
            if ($proc.HasExited) {
                Write-Host ("  (exited, code " + $proc.ExitCode + ")") -ForegroundColor Red
                continue
            }
            if ($handle -eq [IntPtr]::Zero) { Write-Host "  (no window)" -ForegroundColor Yellow; continue }
            Start-Sleep -Seconds $SettleSeconds

            $rect = New-Object Win+RECT
            [void][Win]::GetWindowRect($handle, [ref]$rect)
            $w = $rect.R - $rect.L
            $h = $rect.B - $rect.T
            $bmp = New-Object System.Drawing.Bitmap $w, $h
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $dc = $g.GetHdc()
            # 0x2 = PW_RENDERFULLCONTENT. Header note 2: the window draws itself,
            # so this does not care what owns the desktop.
            $ok = [Win]::PrintWindow($handle, $dc, 2)
            $g.ReleaseHdc($dc)
            $g.Dispose()

            if (-not $ok) {
                Write-Host "  (PrintWindow refused)" -ForegroundColor Red
                $bmp.Dispose()
                continue
            }
            if (-not (Test-NotBlank $bmp)) {
                Write-Host "  BLANK - not written" -ForegroundColor Red
                $bmp.Dispose()
                $blank++
                continue
            }
            $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
            $bmp.Dispose()
            $written++
            Write-Host ("  ${w}x${h} @ " + [Win]::GetDpiForWindow($handle) + " dpi") -ForegroundColor Green
        }
        finally {
            # By PID, never by name: another lane's process must not be touched
            # (CLAUDE.md invariant 2a).
            $proc.Refresh()
            if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        }
    }
}

Write-Host ""
Write-Host "wrote $written screenshots to $Out" -ForegroundColor Green
if ($blank -gt 0) {
    # Not a warning. A blank shot means the capture path is broken again, and the
    # whole point of this run was the pictures.
    throw "$blank shot(s) came back blank and were not written; the capture path is broken"
}
if ($written -ne ($shots.Count * 2)) {
    throw "expected $($shots.Count * 2) shots, wrote $written"
}
