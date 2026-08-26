#!/bin/bash
# nzbfast - one-double-click launcher for macOS.
#
# What this launcher does, in order:
#   1. Checks the nzbfast program is here and executable. It deliberately
#      does NOT clear Apple's "downloaded from the internet" block - see
#      the note at step 1 below.
#   2. Runs the interactive setup wizard (first run asks a few questions;
#      later runs let you add/remove servers or just start).
#   3. Makes the watch/ and downloads/ folders.
#   4. Picks a free web port and starts the downloader + dashboard,
#      opening it in your browser.
#
# It narrates every step, confirms each one with a ✓, and ALWAYS stays
# open at the end (waits for you to press Return) so the window can never
# just vanish before you've seen what happened.

cd "$(dirname "$0")" || exit 1

# ---- Always leave the window open with a clear prompt, no matter what.
# (A bare error scrolling past and the window closing is exactly the
# confusing thing we're avoiding.)
finish() {
    echo
    echo "You can close this window now, or press Return to close it."
    read -r _
}
trap finish EXIT

say()  { printf '%s\n' "$*"; }
ok()   { printf '      \xE2\x9C\x93 %s\n' "$*"; }   # "✓ ..."
fail() { printf '      \xE2\x9C\x97 %s\n' "$*"; }   # "✗ ..."

echo
echo "============================================================"
echo "   nzbfast - setup & launch"
echo "============================================================"
echo
echo "This window sets up nzbfast and starts it. It shows each step"
echo "as it goes and stays open at the end so you can read what"
echo "happened. Settings and the download queue are kept safe in"
echo "~/Library/Application Support/nzbfast, so tidying the folder"
echo "you unzipped into can never delete them."
echo

# ---- Where nzbfast keeps its own records --------------------------------
# Settings, the queue record and spooled NZBs live in Application
# Support (the same place the Mac app wrapper uses), NOT next to the
# binary: people unzip into Downloads, and data that lives beside the
# app gets deleted with the next Downloads tidy-up (a tester lost his
# spool exactly that way on Windows). An older setup that already has
# config.local.json next to this launcher keeps using it - continuity
# beats tidiness.
DATA="$HOME/Library/Application Support/nzbfast"
[ -f "./config.local.json" ] && DATA="$(pwd)"
mkdir -p "$DATA"
echo "These files came from the internet and are not yet signed, so"
echo "macOS may refuse the first launch. If it does: System Settings >"
echo "Privacy & Security, then click \"Open Anyway\"."
echo

# ---- Step 1: prepare the app -------------------------------------------
# Deliberately does NOT clear com.apple.quarantine. The Windows twin of
# this line (a recursive PowerShell Unblock-File) got that launcher flagged
# as Trojan:Script/Wacatac.H!ml - behaviourally fair, since silently
# clearing the OS download marker across a folder is what a dropper does.
# Removed here too for consistency and because disarming a user protection
# on their behalf is not ours to do. Gatekeeper may warn on first run; the
# text above says so. The real fix is notarized, signed builds.
say "[1 of 4]  Checking the app…"
chmod +x nzbfast 2>/dev/null
if [ ! -x ./nzbfast ]; then
    fail "couldn't find the nzbfast program in this folder."
    echo
    echo "      Make sure ALL the files from the .zip stayed together"
    echo "      in one folder (the same folder as this launcher), then"
    echo "      double-click \"Start nzbfast.command\" again."
    exit 1
fi
ok "found the nzbfast program"
echo

# ---- Step 2: server setup ----------------------------------------------
say "[2 of 4]  Your usenet server(s)…"
say "      Answer the questions below - there's no file to edit."
echo
# `nzbfast setup` exits 3, and ONLY 3, when the user picks Quit
# (main.rs, Command::Setup). Anything else non-zero is a real failure -
# most often Gatekeeper killing the unsigned binary, which the shell
# reports as 137 (SIGKILL). Do not narrate that as "you chose to quit":
# telling someone they quit when the OS shot the process is how a
# blocked launch turns into "the app is broken".
./nzbfast --config "$DATA/config.local.json" setup
rc=$?
if [ "$rc" -eq 3 ]; then
    echo
    say "[2 of 4]  You chose to quit - nzbfast was NOT started."
    echo "      Double-click \"Start nzbfast.command\" again anytime to"
    echo "      finish setup and start downloading."
    exit 0
elif [ "$rc" -ne 0 ]; then
    echo
    fail "the nzbfast program did not finish setup (exit code $rc)."
    echo
    echo "      The usual cause on a fresh download is macOS blocking it."
    echo "      These builds are not code-signed yet, so Gatekeeper stops"
    echo "      the first launch and may kill it without a visible error."
    echo
    echo "      To allow it:"
    echo "        1. Open  System Settings > Privacy & Security."
    echo "        2. Scroll down to the Security section - there should be"
    echo "           a line saying \"nzbfast\" was blocked."
    echo "        3. Click \"Open Anyway\", then confirm."
    echo "        4. Double-click \"Start nzbfast.command\" again."
    echo
    echo "      If an error message appeared above instead, that is the"
    echo "      real reason and Gatekeeper is not involved."
    exit 1
fi
ok "saved your server settings"
echo

# ---- Step 3: folders ----------------------------------------------------
say "[3 of 4]  Folders…"
# Defaults live in your Downloads folder; a portable setup that already
# has watch/ + downloads/ next to the binary keeps using those.
WATCH="$HOME/Downloads"
OUT="$HOME/Downloads/nzbfast downloads"
[ -d watch ] && WATCH="watch"
[ -d downloads ] && OUT="downloads"
mkdir -p "$OUT"
ok "watch folder:  $WATCH"
say "      (save any .nzb there - it's picked up automatically)"
ok "finished downloads:  $OUT"
say "      (PAR2 repair and RAR unpacking are built in - nothing else"
say "       to install.)"
echo

# ---- Step 4: pick a port and start -------------------------------------
say "[4 of 4]  Starting the dashboard…"
# The default web port is 6789. If something is already listening there
# (usually nzbfast itself, already running) we step to the next free port
# so THIS copy still starts instead of dying on a "port in use" error.
# bash's /dev/tcp probe = "can I connect?" = the port is in use.
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3>&- 3<&-; }
# EMPTY sentinel, not 6789. Seeded with 6789 the loop reported "port
# 6789 is free" when every candidate was in use, and then started a
# daemon that failed to bind - so the one message the user got was the
# opposite of what had happened.
PORT=""
for p in 6789 6790 6791 6792 6793 6794; do
    if ! port_in_use "$p"; then PORT=$p; break; fi
done
if [ -z "$PORT" ]; then
    fail "web ports 6789-6794 are all in use, so nzbfast has nowhere to listen."
    echo "      Quit whatever is using them (another nzbfast window?) and"
    echo "      double-click \"Start nzbfast.command\" again."
    exit 1
fi
if [ "$PORT" = "6789" ]; then
    ok "web port 6789 is free"
else
    ok "port 6789 was busy (nzbfast may already be running) - using $PORT"
fi
echo

echo "============================================================"
echo "   nzbfast is starting."
echo
echo "   ->  Open this address in your browser:"
echo
echo "          http://localhost:$PORT"
echo
echo "       Your browser should open it automatically in a moment."
echo "       When you see the nzbfast dashboard, it's working."
echo
echo "   -  Keep THIS window open while downloading."
echo "   -  To STOP nzbfast: click this window and press Control-C,"
echo "      or just close the window."
echo "============================================================"
echo

# NOT 'exec' - control returns here when the daemon stops, so we can
# tell you what happened and keep the window open. --open pops the browser.
# --index-db is ABSOLUTE and under $DATA. The flag defaults to the
# relative `index.db`, which for a portable copy is beside the binary:
# on read-only media the daemon cannot create it at all, and on a normal
# unzip the index is lost the moment the extracted folder is replaced by
# the next release. Everything else this launcher passes is already
# under $DATA; the index was the one thing that was not.
[ -f ./index.db ] && [ ! -f "$DATA/index.db" ] && mv -f ./index.db* "$DATA/" 2>/dev/null
./nzbfast --config "$DATA/config.local.json" serve --watch "$WATCH" --out "$OUT" \
    --index-db "$DATA/index.db" --port "$PORT" --open
code=$?

echo
echo "------------------------------------------------------------"
if [ "$code" -eq 0 ] || [ "$code" -eq 130 ]; then
    echo "   nzbfast has stopped."
else
    fail "nzbfast stopped unexpectedly (exit code $code)."
    echo "   If there's an error message above, that's the reason."
fi
echo
echo "   To start nzbfast again another day, just double-click"
echo "   \"Start nzbfast.command\" again."
echo "------------------------------------------------------------"
