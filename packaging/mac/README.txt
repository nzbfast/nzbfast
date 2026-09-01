nzbfast - Mac build (universal: Apple Silicon + Intel)
======================================================

THE EASY WAY: THE APP
---------------------
Most people should use the Mac app instead of this zip:
download  nzbfast-<version>-macos.dmg,  open it, and drag NzbFast
into Applications.

  First launch: macOS warns that nzbfast isn't Apple-notarized yet.
  Right-click the app -> Open - or go to System Settings ->
  Privacy & Security, scroll down, and click "Open Anyway".
  One-time step.

The app manages everything: the dashboard opens in its own window,
first-run setup happens right there (Settings -> Usenet servers),
.nzb files can be double-clicked in Finder, downloads land in
~/Downloads/nzbfast, and "Start at Login" lives in the app menu.

THIS ZIP: THE PORTABLE / SCRIPTED WAY
-------------------------------------
  1. Keep all these files together in one folder.
  2. Double-click  "Start nzbfast.command".
     Not the "nzbfast" file next to it - that one is the program
     itself, and Finder answers a double-click on it with
     "The application "nzbfast" can't be opened." The launcher is
     what sets it up and starts it.
     The first time, macOS asks if you're sure you want to open it
     (it's from a developer it can't verify) - click Open.
       - If there's no Open button, go to System Settings ->
         Privacy & Security, scroll down, and click "Open Anyway",
         then double-click the launcher again.
  3. nzbfast walks you through setup right in the window:
       - If you already use SABnzbd, it offers to use those servers.
       - Otherwise it asks for your usenet provider's address,
         username and password (hidden as you type). You can add
         more servers - e.g. a backup/block account - right there.
  4. It starts downloading and opens the dashboard in your browser
     (http://localhost:6789/). Drop .nzb files into the "watch"
     folder to download them.

You never edit a file. To add or remove a server later, just
double-click the launcher again and choose "Add another server"
or "Remove a server".

To stop nzbfast: press Control-C in its window, or close the window.
To start it again later: double-click "Start nzbfast.command".

IF NOTHING OPENS AT ALL
-----------------------
"The application ... can't be opened." with no other explanation
almost always means the download lost its Unix permissions on the
way to you. That happens when the files are passed on through a
chat app, a cloud drive or a re-zip rather than downloaded from
the GitHub releases page - macOS keeps the permission
bit inside the .zip, and those channels do not.

Download the .dmg or the .zip directly from the releases page and it
will not happen. If you want to rescue the copy you already have,
open Terminal, type  chmod +x   with a trailing space, drag the
"Start nzbfast.command" and "nzbfast" files onto the window, and
press Return - then double-click the launcher again.

More detail and Sonarr/Radarr setup are in the User Manual
(MANUAL.html - also at http://localhost:6789/manual while running).

Everything is built in: RAR extraction and PAR2 verification/repair
are native - no unrar or par2 tool needed, nothing else to install.
