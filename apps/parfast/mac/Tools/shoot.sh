#!/bin/bash
# Take the phase-0 screenshot set: every screen and state in plan section 5,
# light AND dark, at a normal window size.
#
#   ./Tools/shoot.sh <output-dir>
#
# It drives the app over the demo URL route (Sources/ParfastApp/DemoRoute.swift)
# rather than by clicking, so the set is reproducible: rerun it after a design
# change and the shots land on the same states. The window id is resolved by
# CGWindowList and each frame is `screencapture -l`, which needs Screen
# Recording permission for the shell running this - nothing else.
#
# The app must already be built (`./make-app.sh`).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:?usage: shoot.sh <output-dir>}"
mkdir -p "$OUT"
APP=build/parfast.app
SIZE=1280x860

command -v swiftc >/dev/null || { echo "swiftc is needed for the window-id probe"; exit 1; }
PROBE=$(mktemp -d)/winid
cat > "$PROBE.swift" <<'SWIFT'
import CoreGraphics
import Foundation
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements],
                                      kCGNullWindowID) as? [[String: Any]] ?? []
let want = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "parfast"
// EVERY PID BELONGING TO THIS BUNDLE'S EXECUTABLE, from argv[2] on. The
// owner-name test alone matches every parfast on the box, the other worktrees'
// builds included; with none given the scope is off and the old behaviour
// stands. Same rule shoot-real.sh already uses - see its header for the
// 38-frame set that came back showing another lane's app, every frame entirely
// plausible. Every pid rather than just the one launched, because
// LaunchServices may answer in a SECOND copy of our own bundle and that copy's
// window is the right one to shoot.
let wantPids = CommandLine.arguments.dropFirst(2).compactMap { Int($0) }
// The LAST match is the frontmost sheet or panel when one is up, which is the
// window a sheet shot wants; without a sheet there is only one.
var ids: [Int] = []
for w in list where (w[kCGWindowOwnerName as String] as? String ?? "") == want {
    if let h = (w[kCGWindowBounds as String] as? [String: Any])?["Height"] as? Double, h < 60 { continue }
    if !wantPids.isEmpty,
       !wantPids.contains(w[kCGWindowOwnerPID as String] as? Int ?? -1) { continue }
    ids.append(w[kCGWindowNumber as String] as? Int ?? 0)
}
print(ids.map(String.init).joined(separator: " "))
SWIFT
swiftc -O "$PROBE.swift" -o "$PROBE" 2>/dev/null

# LAUNCH THE EXECUTABLE, NOT THE BUNDLE THROUGH `open`. `open` asks
# LaunchServices for "a parfast.app" and it picks whichever it likes, which on a
# box with several worktrees is a coin flip - this very script, run from another
# worktree on 12 Sep 2026, drove THIS one's app for about fifteen minutes,
# capturing its screens and flipping its appearance while every frame looked
# correct. shoot-real.sh has launched directly for a while; this one had not.
#
# Retire this bundle's own leftovers first, and trap so the next run starts
# clean. By the FULL PATH, never the name `parfast`: there is a parfast CLI on
# this box and other worktrees' apps must not be touched (CLAUDE.md 2a).
retire_instances() {
    for p in $(pgrep -f "^$PWD/$APP/Contents/MacOS/parfast$" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
}
retire_instances
sleep 1

PARFAST_SCREENSHOT=1 "$PWD/$APP/Contents/MacOS/parfast" >/dev/null 2>&1 &
trap retire_instances EXIT
sleep 3

# Every pid of this bundle, recomputed per shot: LaunchServices may have
# answered in a second copy of our own app since the last one.
our_pids() { pgrep -f "^$PWD/$APP/Contents/MacOS/parfast$" 2>/dev/null | tr '\n' ' '; }

shoot() {  # shoot <name> <query> [settle-seconds] [window-pick]
    local name="$1" query="$2" settle="${3:-2.8}" pick="${4:-first}"
    # `open -a <THIS BUNDLE>` and never a bare `open`. A bare one asks
    # LaunchServices for "an app that handles parfast://", and with
    # /Applications/parfast.app installed and RUNNING it hands the URL to that
    # copy every time: our app never hears the route and stays on whatever
    # screen it was already showing. Measured 12 Sep 2026 - a bare `open` sent
    # `screen=create` to the installed 1.5.0-beta.1 build while our 1.5.0-mock
    # window sat on the empty verify screen, and the frame came back looking
    # like a broken Create screen rather than like a misdelivered URL.
    #
    # This is the SECOND half of the same trap the launch note above fixes.
    # That one stopped us photographing another app's window; this one stops
    # another app eating the instruction and leaving us photographing our own
    # window in a stale state - which is worse, because the window IS ours and
    # every check below passes.
    open -a "$PWD/$APP" "parfast://demo?$query&size=$SIZE"
    sleep "$settle"
    local ids; ids=$("$PROBE" parfast $(our_pids))
    local id
    if [ "$pick" = "last" ]; then id=${ids##* }; else id=${ids%% *}; fi
    # Not "no window" - not OUR window. A URL that went to another lane's app
    # leaves ours unchanged, which shows up as repeated frames and trips the
    # appearance check: a detectable failure instead of a plausible lie about
    # which build was photographed.
    [ -n "$id" ] || { echo "!! no window of ours for $name (is another lane's parfast.app up?)"; return; }
    screencapture -o -x -l "$id" "$OUT/$name.png"
    echo "   $name.png"
}

for mode in dark light; do
    echo "== $mode"
    A="appearance=$mode"
    shoot "$mode-01-empty-verify"      "$A&screen=empty&mode=verify"
    shoot "$mode-02-empty-create"      "$A&screen=empty&mode=create"
    shoot "$mode-03-empty-checksums"   "$A&screen=empty&mode=checksums"
    shoot "$mode-04-verify-running"    "$A&screen=verify&scenario=bigset&speed=0.6" 3.2
    shoot "$mode-05-verify-clean"      "$A&screen=verify&scenario=clean&speed=30" 3.0
    shoot "$mode-06-verify-repairable" "$A&screen=verify&scenario=damaged&speed=30" 3.2
    shoot "$mode-07-verify-unrepairable" "$A&screen=verify&scenario=unrepairable&speed=30" 3.2
    shoot "$mode-08-verify-misnamed"   "$A&screen=verify&scenario=misnamed&speed=30" 3.2
    shoot "$mode-09-verify-unicode"    "$A&screen=verify&scenario=unicode&speed=30" 3.0
    shoot "$mode-10-verify-bigset"     "$A&screen=verify&scenario=bigset&speed=40" 3.6
    shoot "$mode-11-repair-done"       "$A&screen=verify&scenario=damaged&repair=1&speed=30" 3.4
    shoot "$mode-12-verify-log"        "$A&screen=verify&scenario=damaged&speed=30&log=1" 3.2
    shoot "$mode-13-create"            "$A&screen=create&speed=30" 3.2
    shoot "$mode-14-create-uniform"    "$A&screen=create&scheme=uniform&speed=30" 3.0
    shoot "$mode-15-progress-sheet"    "$A&screen=verify&scenario=bigset&speed=0.5&sheet=1" 3.0 last
    shoot "$mode-16-checksums-verify"  "$A&screen=checksums&speed=30" 3.0
    shoot "$mode-17-checksums-create"  "$A&screen=checksums&sub=create&speed=30" 3.0
    shoot "$mode-18-queue"             "$A&screen=queue&speed=2" 3.4
    shoot "$mode-19-queue-done"        "$A&screen=queue&speed=40" 4.0
done

echo "wrote $(ls "$OUT" | wc -l | tr -d ' ') frames to $OUT"
