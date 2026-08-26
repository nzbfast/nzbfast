@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem nzbfast - one-double-click launcher for Windows.
rem
rem What this launcher does, in order:
rem   1. Checks the app is here.
rem   2. Runs the interactive setup wizard (first run asks a few questions).
rem   3. Makes the watch\ and downloads\ folders.
rem   4. Picks a free web port and starts the downloader + dashboard,
rem      opening it in your browser.
rem
rem It deliberately does NOT strip Windows' "downloaded from the internet"
rem mark. It used to, with a recursive PowerShell Unblock-File over this
rem whole folder, and Defender's ML classifier flagged the launcher as
rem Trojan:Script/Wacatac.H!ml for it - correctly, in behavioural terms:
rem silently clearing Mark-of-the-Web across a folder is exactly what a
rem dropper does to its payloads. Clearing a security marker on the user's
rem behalf was the wrong call anyway. Windows may now show a SmartScreen
rem prompt on first run; the text below says so and what to click. The real
rem fix is a signed binary.
rem
rem It narrates every step, confirms each with [ok], and ALWAYS stays open
rem at the end (waits for a key) so the window can never just vanish.

echo.
echo ============================================================
echo    nzbfast - setup ^& launch
echo ============================================================
echo.
echo This window sets up nzbfast and starts it. It shows each step
echo as it goes and stays open at the end so you can read what
echo happened. Settings and the download queue are kept safe in
echo %%LOCALAPPDATA%%\nzbfast, so tidying your Downloads folder can
echo never delete them.
echo.

rem ---- Where nzbfast keeps its own records --------------------------------
rem Settings, the queue record and spooled NZBs live in
rem %LOCALAPPDATA%\nzbfast, NOT next to the app: people unzip into their
rem Downloads folder, and data that lives beside the app gets deleted with
rem the next Downloads tidy-up (a tester lost his spool exactly that way).
rem An older setup that already has config.local.json next to this
rem launcher keeps using it - continuity beats tidiness.
set "DATA=%LOCALAPPDATA%\nzbfast"
if exist "%~dp0config.local.json" set "DATA=%~dp0."
if not exist "%DATA%" mkdir "%DATA%" >nul 2>&1
echo Because these files came from the internet and are not yet
echo code-signed, Windows may show "Windows protected your PC".
echo That is SmartScreen being cautious about an unknown publisher,
echo not a virus report. Click "More info" then "Run anyway".
echo.

rem ---- Step 1: prepare the app -------------------------------------------
echo [1 of 4]  Checking the app...
if not exist nzbfast.exe (
    echo       [X] couldn't find nzbfast.exe in this folder.
    echo.
    echo       Make sure ALL the files from the .zip stayed together in
    echo       one folder ^(the same folder as this launcher^), then
    echo       double-click "Start nzbfast.bat" again.
    echo.
    pause
    exit /b 1
)
echo       [ok] found the nzbfast program
echo.

rem ---- Step 2: server setup ----------------------------------------------
echo [2 of 4]  Your usenet server^(s^)...
echo       Answer the questions below - there's no file to edit.
echo.
rem nzbfast.exe setup exits 3, and ONLY 3, when the user picks Quit
rem (main.rs, Command::Setup). Anything else non-zero is a real failure -
rem most often Defender or SmartScreen stopping the unsigned exe. Do not
rem narrate that as "you chose to quit". Note that "if errorlevel N"
rem means "N or higher", so the code is captured and compared exactly.
rem (No redirection characters in these rem lines - cmd still processes
rem those on a rem line and would silently create a stray file.)
nzbfast.exe --config "%DATA%\config.local.json" setup
set RC=%errorlevel%
if "%RC%"=="3" (
    echo.
    echo [2 of 4]  You chose to quit - nzbfast was NOT started.
    echo       Double-click "Start nzbfast.bat" again anytime to finish
    echo       setup and start downloading.
    echo.
    pause
    exit /b 0
)
if not "%RC%"=="0" (
    echo.
    echo       [X] nzbfast.exe did not finish setup ^(exit code %RC%^).
    echo.
    echo       The usual cause on a fresh download is Windows blocking it.
    echo       These builds are not code-signed yet, so SmartScreen and
    echo       Defender treat them as an unknown publisher and can stop
    echo       or quarantine the program with no visible error.
    echo.
    echo       To allow it:
    echo         1. If a blue "Windows protected your PC" box appeared,
    echo            click "More info" then "Run anyway".
    echo         2. Otherwise open Windows Security ^> Virus ^& threat
    echo            protection ^> Protection history, find nzbfast and
    echo            choose Restore / Allow.
    echo         3. Double-click "Start nzbfast.bat" again.
    echo.
    echo       If an error message appeared above instead, that is the
    echo       real reason and Windows is not involved.
    echo.
    pause
    exit /b 1
)
echo       [ok] saved your server settings
echo.

rem ---- Step 3: folders ----------------------------------------------------
echo [3 of 4]  Folders...
rem Defaults live in your Downloads folder; a portable setup that already
rem has watch\ + downloads\ next to the exe keeps using those.
set "WATCH=%USERPROFILE%\Downloads"
set "OUT=%USERPROFILE%\Downloads\nzbfast downloads"
if exist watch set "WATCH=watch"
if exist downloads set "OUT=downloads"
if not exist "%OUT%" mkdir "%OUT%"
echo       [ok] watch folder:  %WATCH%
echo            ^(save any .nzb there - it's picked up automatically^)
echo       [ok] finished downloads:  %OUT%
echo       ^(PAR2 repair and RAR unpacking are built in - nothing else
echo        to install.^)
echo.

rem ---- Step 4: pick a port and start -------------------------------------
echo [4 of 4]  Starting the dashboard...
rem Default web port is 6789. If it's already in use (usually nzbfast
rem already running) step to the next free port so THIS copy still starts.
rem EMPTY sentinel, not 6789: seeded with 6789 this reported "web port
rem 6789 is free" when every candidate was in use, and then started a
rem daemon that failed to bind - the one message the user got was the
rem opposite of what happened.
set "PORT="
for %%p in (6789 6790 6791 6792 6793 6794) do (
    netstat -a -n -p TCP | findstr /R /C:":%%p .*LISTENING" >nul 2>&1
    if errorlevel 1 (
        set PORT=%%p
        goto :gotport
    )
)
:gotport
if not defined PORT (
    echo       [X] web ports 6789-6794 are all in use, so nzbfast has
    echo           nowhere to listen. Close whatever is using them
    echo           ^(another nzbfast window?^) and run this again.
    echo.
    pause
    exit /b 1
)
if "%PORT%"=="6789" (
    echo       [ok] web port 6789 is free
) else (
    echo       [ok] port 6789 was busy ^(nzbfast may already be running^) - using %PORT%
)
echo.

echo ============================================================
echo    nzbfast is starting.
echo.
echo    -^>  Open this address in your browser:
echo.
echo           http://localhost:%PORT%
echo.
echo        Your browser should open it automatically in a moment.
echo        When you see the nzbfast dashboard, it's working.
echo.
echo    -  Keep THIS window open while downloading.
echo    -  To STOP nzbfast: click this window and press Ctrl-C,
echo       or just close the window.
echo ============================================================
echo.

rem Control returns here when the daemon stops, so we can say what
rem happened and keep the window open. --open pops the browser.
rem --index-db is ABSOLUTE and under %DATA%. The flag defaults to the
rem relative `index.db`, which for a portable copy is beside the exe: on
rem read-only media the daemon cannot create it at all, and on a normal
rem unzip the index is lost the moment the extracted folder is replaced
rem by the next release. Everything else here is already under %DATA%.
if exist "%~dp0index.db" if not exist "%DATA%\index.db" move /Y "%~dp0index.db*" "%DATA%\" >nul 2>&1
nzbfast.exe --config "%DATA%\config.local.json" serve --watch "%WATCH%" --out "%OUT%" --index-db "%DATA%\index.db" --port %PORT% --open
set CODE=%errorlevel%

echo.
echo ------------------------------------------------------------
if "%CODE%"=="0" (
    echo    nzbfast has stopped.
) else (
    echo    [X] nzbfast stopped ^(exit code %CODE%^).
    echo    If there's an error message above, that's the reason.
)
echo.
echo    To start nzbfast again another day, just double-click
echo    "Start nzbfast.bat" again.
echo ------------------------------------------------------------
echo.
pause
