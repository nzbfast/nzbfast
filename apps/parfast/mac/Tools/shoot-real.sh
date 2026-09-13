#!/bin/bash
# Phase 1: screenshot the app driving the REAL engine over the acceptance
# corpus (plan section 7).
#
#   PARFAST_CORPUS=/path/to/corpus ./Tools/shoot-real.sh <output-dir>
#
# The mock set (Tools/shoot.sh) covers every screen and state; this one covers
# the nine scenarios the corpus measures, so the two together are "every state"
# and "against the real engine". The demo route is GONE in a real build - the
# app is driven here by `parfast://open?path=`, the same router a Finder drop
# uses - and the appearance/size half is reachable only under
# PARFAST_SCREENSHOT=1 (see DemoRoute.screenshotModeAllowed).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:?usage: shoot-real.sh <output-dir>}"
CORPUS="${PARFAST_CORPUS:?set PARFAST_CORPUS to a make-corpus.py output directory}"
mkdir -p "$OUT"
APP=build/parfast.app
SIZE=1280x860

# SHOOT ONLY OUR OWN WINDOW. `open <url>` hands the URL to whatever app
# LaunchServices has registered for `parfast://`, and on this machine that is a
# coin flip: every worktree holds its own `build/parfast.app` and several lanes
# have one up at once. On 12 Sep 2026 a 38-frame set came back showing ANOTHER
# lane's app - its corpus path in the header, its older status pill - and every
# frame looked entirely plausible. `open -a "$PWD/$APP"` is NOT the fix: it
# launches a second copy rather than delivering to the instance this script
# started, and the appearance check below catches that within one run.
#
# So the probe takes the PIDs of THIS bundle's executable and returns only
# windows owned by one of them. A URL that goes to somebody else's app then
# leaves our own window unchanged, which reads as repeated frames and trips the
# appearance check - a detectable failure instead of a plausible lie about which
# build was photographed. Every pid rather than the one we launched, because the
# retire block below explains that LaunchServices may answer in a SECOND copy of
# our own app, and that copy's window is the right one to shoot.
PROBE=$(mktemp -d)/winid
cat > "$PROBE.swift" <<'SWIFT'
import CoreGraphics
import Foundation
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements],
                                      kCGNullWindowID) as? [[String: Any]] ?? []
// The arguments are every PID belonging to THIS bundle's executable. The
// owner-name test alone matches every parfast on the box, the other worktrees'
// builds included; with no arguments the scope is off and the old behaviour
// stands.
let wantPids = Set(CommandLine.arguments.dropFirst().compactMap(Int.init))
var ids: [Int] = []
for w in list where (w[kCGWindowOwnerName as String] as? String ?? "") == "parfast" {
    if let h = (w[kCGWindowBounds as String] as? [String: Any])?["Height"] as? Double, h < 60 { continue }
    if !wantPids.isEmpty,
       !wantPids.contains(w[kCGWindowOwnerPID as String] as? Int ?? -1) { continue }
    ids.append(w[kCGWindowNumber as String] as? Int ?? 0)
}
print(ids.map(String.init).joined(separator: " "))
SWIFT
swiftc -O "$PROBE.swift" -o "$PROBE" 2>/dev/null

# Launch the EXECUTABLE, not the bundle through `open`: LaunchServices does
# not reliably forward the caller's environment, so PARFAST_SCREENSHOT can
# fail to reach the app and DemoRoute then refuses the appearance switch
# SILENTLY - both passes come out in the system appearance and half the set
# is mislabeled. It worked once and not the next time, which is worse than
# never working. The check below is what catches it either way.
# AND FIRST, RETIRE ANY INSTANCE ALREADY RUNNING FROM THIS BUNDLE, or this
# run photographs the OLD BINARY. The launch above starts our build, but the
# `open` in shoot() hands the URL to LaunchServices, which activates whichever
# registered instance it likes - and a previous run's process is still sitting
# there, because nothing here ever stopped it. Three accumulated over three
# runs on 12 Sep 2026 and the create frame then came back BYTE-IDENTICAL across
# two different builds: a real code change, rebuilt and re-signed, photographed
# as if it had never happened. That is the worst shape a harness can have,
# because the frames look perfectly good and simply show the wrong app.
#
# By the FULL PATH of this bundle's executable, never by the name `parfast`:
# CLAUDE.md invariant 2a, and there is a parfast CLI on this box.
for stale in $(pgrep -f "^$PWD/$APP/Contents/MacOS/parfast$" || true); do
    echo "  retiring a previous instance, pid $stale"
    kill "$stale" 2>/dev/null || true
done
sleep 1

our_pids() {
    pgrep -f "^$PWD/$APP/Contents/MacOS/parfast$" 2>/dev/null || true
}

retire_instances() {
    for p in $(pgrep -f "^$PWD/$APP/Contents/MacOS/parfast$" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
}

# BEFORE THE LAUNCH, not only on the way out. The trap below covers a run that
# ENDS; this covers a run that DIED - interrupted, timed out, or killed - and so
# never ran its trap at all. That is the case the guard was written for: the
# leftovers of a dead run are exactly what the next run photographs, and the
# frames look perfectly good while showing an older build.
#
# The call was lost in a merge on 12 Sep 2026 that reported no conflict, leaving
# the function defined and trapped but never invoked at the start - half a guard,
# and the half that was doing the work.
retire_instances
sleep 1

PARFAST_SCREENSHOT=1 "$PWD/$APP/Contents/MacOS/parfast" >/dev/null 2>&1 &
# Clean up EVERY instance of this bundle on the way out, not just the one we
# started: `open` hands the URL to LaunchServices, which will happily launch a
# SECOND copy rather than activate ours, so killing $! alone still leaves the
# run's leftovers for the next run to photograph.
trap retire_instances EXIT
sleep 4

shoot() {
    local name="$1" url="$2" settle="${3:-2.5}"
    open "$url"
    sleep "$settle"
    # EVERY pid of this bundle, not just the one we launched: LaunchServices
    # may answer the URL in a second copy of OUR app, and that copy's window is
    # the right one to photograph. What must never be photographed is a window
    # belonging to a DIFFERENT worktree's build, which is what the scope buys.
    local id; id=$("$PROBE" $(our_pids) | cut -d' ' -f1)
    [ -n "$id" ] || { echo "!! no window for $name"; return; }
    screencapture -o -x -l "$id" "$OUT/$name.png"
    echo "   $name.png"
}

for mode in dark light; do
    echo "== $mode"
    # `open -a <THIS BUNDLE>`, never a bare `open` - see Tools/shoot.sh's note
    # at the same call: an installed parfast.app answers the URL scheme first
    # and our window is left on its previous screen, photographed and plausible.
    open -a "$PWD/$APP" "parfast://demo?appearance=$mode&size=$SIZE"; sleep 1
    n=0
    for scenario in clean damaged missing misnamed moved unrepairable unicode blocks10k volgaps; do
        n=$((n+1))
        dir=$(python3 -c "import json,sys;d=json.load(open('$CORPUS/$scenario/expected.json'));print(d['set']['dir'])")
        par2=$(python3 -c "import json,sys;d=json.load(open('$CORPUS/$scenario/expected.json'));print(d['set']['par2'])")
        shoot "$(printf '%s-%02d-%s' "$mode" "$n" "$scenario")" \
              "parfast://open?path=$CORPUS/$scenario/$dir/$par2"
    done
    # Create, reached the way a Finder drop reaches it: non-par2 paths.
    src=$(python3 -c "
import json,glob,os
d=json.load(open('$CORPUS/clean/expected.json'))
base=os.path.join('$CORPUS','clean',d['set']['dir'])
print('&'.join('path='+os.path.join(base,m) for m in d['set']['members']))")
    shoot "$mode-10-create" "parfast://open?$src"
done

echo "wrote $(ls "$OUT" | wc -l | tr -d ' ') frames to $OUT"

# A mislabeled frame is worse than a missing one, so PROVE the two passes
# differ rather than trusting that the appearance switch took. A dark frame
# averages ~30 and a light one ~240; anything closer than 100 apart means the
# switch was refused and the labels are lying.
python3 - "$OUT" <<'CHECK'
import subprocess, sys, tempfile, os, zlib, struct, glob
def brightness(p):
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "t.png")
        subprocess.run(["sips", "-Z", "24", "-s", "format", "png", p, "--out", out],
                       capture_output=True)
        data = open(out, "rb").read(); pos = 8; idat = b""; w = h = ct = 0
        while pos < len(data):
            ln = struct.unpack(">I", data[pos:pos + 4])[0]; typ = data[pos + 4:pos + 8]
            body = data[pos + 8:pos + 8 + ln]
            if typ == b"IHDR": w, h, _, ct = struct.unpack(">IIBB", body[:10])
            elif typ == b"IDAT": idat += body
            pos += 12 + ln
        raw = zlib.decompress(idat); ch = {0: 1, 2: 3, 4: 2, 6: 4}[ct]; stride = w * ch
        prev = bytearray(stride); total = n = i = 0
        for _ in range(h):
            f = raw[i]; i += 1; line = bytearray(raw[i:i + stride]); i += stride
            for x in range(stride):
                a = line[x - ch] if x >= ch else 0
                b = prev[x]; c = prev[x - ch] if x >= ch else 0
                if f == 1: line[x] = (line[x] + a) & 0xFF
                elif f == 2: line[x] = (line[x] + b) & 0xFF
                elif f == 3: line[x] = (line[x] + (a + b) // 2) & 0xFF
                elif f == 4:
                    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                    pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                    line[x] = (line[x] + pr) & 0xFF
            for x in range(0, stride, ch):
                total += line[x] + line[x + 1] + line[x + 2]; n += 3
            prev = line
        return total / max(1, n)

out = sys.argv[1]
bad = []
for dark in sorted(glob.glob(os.path.join(out, "dark-*.png"))):
    light = dark.replace("/dark-", "/light-")
    if not os.path.exists(light):
        bad.append(f"{os.path.basename(dark)}: no light twin"); continue
    d, l = brightness(dark), brightness(light)
    if abs(l - d) < 100:
        bad.append(f"{os.path.basename(dark)}: dark {d:.0f} vs light {l:.0f} - the appearance switch did NOT take")
if bad:
    print("APPEARANCE CHECK FAILED:"); [print("  " + b) for b in bad]
    sys.exit(1)
print("appearance check: every pair differs as it should")
CHECK
