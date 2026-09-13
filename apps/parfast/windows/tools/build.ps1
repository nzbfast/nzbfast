# Build, test and publish the parfast GUI on a Windows box.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\build.ps1 [-Publish] [-Installer] [-Run]
#
# WHY A .ps1 AND NOT AN INLINE ssh COMMAND: the maintainer notes' "Windows-over-ssh
# rules" - never inline complex PowerShell through ssh, the quoting mangles. scp
# this file and run it with `powershell -File`.
#
# It assumes the .NET 8 SDK is on PATH. The Windows App SDK is a NuGet package the
# project restores; it is NOT an installer, so nothing else needs to be present.
#
# Long-running work DIES when the ssh session closes (same file). A publish is a
# couple of minutes and survives an attached session, but if you are driving this
# detached, redirect to a log and poll it rather than waiting on the pipe.

[CmdletBinding()]
param(
    [switch]$Publish,
    [switch]$Installer,
    [switch]$Run,
    [string]$Version = "1.5.0",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($name) {
    Write-Host ""
    Write-Host "=== $name ===" -ForegroundColor Cyan
}

Step "toolchain"
dotnet --version
if ($LASTEXITCODE -ne 0) { throw "the .NET SDK is not on PATH (winget install Microsoft.DotNet.SDK.8)" }

Step "generated sources are current"
# Never hand-patch a generated file; this proves nobody did.
dotnet run --project Parfast.Gen -- --check
if ($LASTEXITCODE -ne 0) { throw "generated sources are stale; run: dotnet run --project Parfast.Gen" }

Step "build"
dotnet build Parfast.sln -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "build failed" }

Step "test"
dotnet test Parfast.Tests\Parfast.Tests.csproj -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

if ($Publish -or $Installer -or $Run) {
    Step "publish"
    # Self-contained and unpackaged (plan 6.2): the Windows App SDK's own DLLs are
    # copied beside the exe, so the zip and the installer both produce something
    # that runs on a clean machine with nothing installed.
    $out = Join-Path $root "out\publish"
    dotnet publish Parfast.App\Parfast.App.csproj `
        -c $Configuration -r win-x64 --self-contained true `
        -p:WindowsAppSDKSelfContained=true -p:WindowsPackageType=None `
        -p:Version=$Version -o $out --nologo
    if ($LASTEXITCODE -ne 0) { throw "publish failed" }

    $exe = Join-Path $out "parfast-gui.exe"
    if (-not (Test-Path $exe)) { throw "published, but $exe is not there" }
    # A green verification proves nothing until you confirm WHICH artifact it
    # exercised (MACHINES.md). So the path and its hash are printed, always -
    # but $exe is the .NET APPHOST, a small launcher stub whose bytes do not
    # depend on the managed code at all. Two demonstrably different source
    # trees published the byte-identical apphost hash
    # C808A19C78F6576542CCE644A13BE15722A5B478048228B846584C313A1150EC on
    # 12 Sep 2026 (the maintainer notes, "Also
    # owed"). The app itself is `parfast-gui.dll` beside it, so THAT is what
    # a verification must hash - the exe hash is printed too, labelled, only
    # because it is what a user actually double-clicks.
    $dll = Join-Path $out "parfast-gui.dll"
    if (-not (Test-Path $dll)) { throw "published, but $dll is not there" }
    $exeHash = (Get-FileHash $exe -Algorithm SHA256).Hash
    $dllHash = (Get-FileHash $dll -Algorithm SHA256).Hash
    Write-Host "published        $out"
    Write-Host "sha256 exe       $exeHash  ($exe - the apphost stub; invariant across managed-code changes)"
    Write-Host "sha256 dll       $dllHash  ($dll - the managed app; THIS is the one that proves WHICH code shipped)"
    Write-Host "size             $((Get-Item $exe).Length) bytes (exe)"
    Write-Host "files            $((Get-ChildItem $out -Recurse -File).Count)"

    # MOTW-stamped executables hang headless (MACHINES.md): SmartScreen has no
    # desktop to ask on. Anything that came off the network carries the mark.
    Get-ChildItem $out -Recurse -File | Unblock-File
}

if ($Installer) {
    Step "installer"
    $iscc = Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"
    if (-not (Test-Path $iscc)) { throw "ISCC.exe not found at $iscc" }

    $stage = Join-Path $root "out\stage-gui"
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item (Join-Path $root "out\publish\*") $stage -Recurse -Force

    # REFUSE rather than skip. This was `if (Test-Path) { copy }`, so a tree
    # without a LICENSE at the repo root staged quietly and ISCC failed
    # eighty lines into the .iss with "Could not read ...\stage-gui\LICENSE" -
    # an error about the stage directory for a file that was never put in it.
    # The .iss REQUIRES the file (LicenseFile=), so there is no case where
    # carrying on is right. Found 12 Sep 2026: the bundle script's source sync
    # did not ship LICENSE, and this guard turned a one-line omission into a
    # puzzle.
    $license = Join-Path $root "..\..\..\LICENSE"
    if (-not (Test-Path $license)) {
        throw "the installer needs a LICENSE at the repo root and $license is not there"
    }
    Copy-Item $license (Join-Path $stage "LICENSE") -Force

    $iss = Join-Path $root "packaging\parfast-gui.iss"
    & $iscc "/DAppVersion=$Version" "/DStageDir=$stage" $iss
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
}

if ($Run) {
    Step "run"
    Start-Process (Join-Path $root "out\publish\parfast-gui.exe") -ArgumentList "--mock"
}

Write-Host ""
Write-Host "done" -ForegroundColor Green
