#!/bin/bash
# Build NzbFast.app - the WKWebView wrapper that owns the bundled
# nzbfast engine (packaging/INSTALLER-SPEC.md, chip A).
#
#   ./make-app.sh                    universal wrapper + universal engine
#   ENGINE=/path/to/nzbfast ./make-app.sh   reuse a prebuilt engine binary
#
# Version source of truth is crates/nzbfast/Cargo.toml (shared rule 8).
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"

# DEPLOYMENT TARGET. Unset, rustc stamps the engine 11.0 (arm64) / 10.12
# (x86_64) while cc-rs compiles every C object in it - aws-lc, ring,
# sqlite, mimalloc, rapidyenc - for the BUILD HOST's SDK default, so the
# engine said "11.0" in its header and was 27.0 inside on the dev Mac
# (research/MAC-DEPLOYMENT-TARGET-2026-09-15.md). The ENGINE is pinned to
# 11.0, the floor of every mac CLI asset, and NOT to
# the app's 14.0: it shares target/ with the release-bundle zip recipe,
# whose binary is also the updater payload, so a second value would
# compile the whole engine twice per release and bundle a different
# binary from the one the updater ships. The app's own floor stays
# LSMinimumSystemVersion below and `.macOS(.v14)` in Package.swift, which
# is why this is scoped to the cargo line and never exported to swift.
# Kept out of .cargo/config.toml: it moves rustc fingerprints, which a
# checked-in setting would push onto every CI cache key. An ENGINE=
# passed in was built elsewhere and does not get this.
ENGINE_MACOS_FLOOR=11.0

VERSION=$(grep '^version' "$REPO/crates/nzbfast/Cargo.toml" | head -1 | cut -d'"' -f2)
# Beta serial rides into Info.plist so the wrapper can compare its
# BUNDLED engine against a running one at attach time (the §98 upgrade
# restart). Same source and same "0/missing = release" rule as the
# engine's own build.rs - the two must agree or the wrapper would
# restart an engine identical to its bundle.
BETA=$(cat "$REPO/packaging/beta-serial.txt" 2>/dev/null | tr -d '[:space:]')
case "$BETA" in ''|*[!0-9]*) BETA=0 ;; esac
echo "== NzbFast.app v$VERSION (beta serial $BETA)"

# --- engine: universal binary via the release lipo recipe -------------
if [ -z "${ENGINE:-}" ]; then
    echo "== building universal engine"
    (cd "$REPO" && MACOSX_DEPLOYMENT_TARGET=$ENGINE_MACOS_FLOOR cargo build --release \
        --target aarch64-apple-darwin --target x86_64-apple-darwin -p nzbfast)
    ENGINE="$REPO/target/nzbfast-universal"
    lipo -create -output "$ENGINE" \
        "$REPO/target/aarch64-apple-darwin/release/nzbfast" \
        "$REPO/target/x86_64-apple-darwin/release/nzbfast"
fi
lipo -info "$ENGINE"

# --- wrapper: universal SwiftPM build ---------------------------------
echo "== building wrapper"
swift build -c release --arch arm64 --arch x86_64
# ASK SwiftPM where it put the product, never spell the folder. The
# universal output was .build/apple/Products/Release through Swift 6.3
# and is .build/out/Products/Release on 6.4's build backend (measured
# 15 Sep 2026). A literal path is worse than a failed build: a checkout
# that last built on the old toolchain still holds a binary at the old
# spelling, and `cp` would ship that stale wrapper with a green log.
WRAPPER=$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/NzbFast
[ -f "$WRAPPER" ] || {
    echo "swift build reported no wrapper at $WRAPPER" >&2; exit 1; }

# --- assemble the bundle ----------------------------------------------
APP=build/NzbFast.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin"
cp "$WRAPPER" "$APP/Contents/MacOS/NzbFast"
cp "$ENGINE" "$APP/Contents/Resources/bin/nzbfast"
chmod +x "$APP/Contents/Resources/bin/nzbfast"

# Icon: iconset from the committed 1024px master (packaging/icon/).
#
# icon-downstream-gate: this iconset is built into a temp directory on
# every run and folded straight into the .app - nothing here is committed,
# so there is no raster that can fall behind the master. That is what makes
# this different from the other two second-generation downscales,
# packaging/flatpak/make-icon.sh and packaging/qnap/make-icons.sh, whose
# outputs ARE committed and are held by tools/icon-downstream-gate.py. If
# an .icns or an iconset is ever committed here, delete this waiver and
# give this script a DERIVATIONS table instead.
ICONSET=$(mktemp -d)/NzbFast.iconset
mkdir -p "$ICONSET"
for entry in 16:icon_16x16 32:icon_16x16@2x 32:icon_32x32 64:icon_32x32@2x \
             128:icon_128x128 256:icon_128x128@2x 256:icon_256x256 \
             512:icon_256x256@2x 512:icon_512x512 1024:icon_512x512@2x; do
    size=${entry%%:*}; name=${entry#*:}
    sips -z "$size" "$size" "$REPO/packaging/icon/icon-1024.png" \
        --out "$ICONSET/$name.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/NzbFast.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>NzbFast</string>
  <key>CFBundleDisplayName</key><string>nzbfast</string>
  <key>CFBundleIdentifier</key><string>com.nzbfast.app</string>
  <key>CFBundleExecutable</key><string>NzbFast</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>NzbFastBetaSerial</key><string>$BETA</string>
  <key>CFBundleIconFile</key><string>NzbFast</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <!-- ONE wrapper per machine. Every instance spawns its own engine over
       the SAME data directory (~/Library/Application Support/nzbfast:
       one spool, one index db, one watch folder), and the attach scan
       cannot save us from a second COPY of this app - it only ever
       probes for an engine, not for another wrapper. LaunchServices
       already refuses a plain second launch; this key is what makes
       \`open -n\` refuse too, which is the spelling a script or a curious
       user reaches for. -->
  <key>LSMultipleInstancesProhibited</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsLocalNetworking</key><true/>
  </dict>
  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeName</key><string>NZB file</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>LSHandlerRank</key><string>Default</string>
      <key>LSItemContentTypes</key><array><string>com.nzbfast.nzb</string></array>
    </dict>
  </array>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key><string>com.nzbfast.nzblnk</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>CFBundleURLSchemes</key><array><string>nzblnk</string></array>
    </dict>
  </array>
  <key>UTImportedTypeDeclarations</key>
  <array>
    <dict>
      <key>UTTypeIdentifier</key><string>com.nzbfast.nzb</string>
      <key>UTTypeDescription</key><string>NZB file</string>
      <key>UTTypeConformsTo</key><array><string>public.xml</string></array>
      <key>UTTypeTagSpecification</key>
      <dict>
        <key>public.filename-extension</key><array><string>nzb</string></array>
      </dict>
    </dict>
  </array>
</dict>
</plist>
PLIST

# --- ad-hoc sign, inside-out ------------------------------------------
# arm64 refuses unsigned Mach-Os, and lipo output loses the linker's
# ad-hoc signature - sign the nested engine FIRST, then the app, so the
# outer seal covers the signed payload (signing can later be swapped for
# a real identity without restructuring).
# STRIP THE DEBUG MAP BEFORE SIGNING, or the wrapper ships this
# machine's absolute paths. `swift build` records one absolute path per
# object file in the linked binary's debug map (the N_OSO stabs) -
# .build/<layout>/Intermediates.noindex/.../Objects-normal/<arch>/<name>.o,
# where <layout> was `apple` through Swift 6.3 and is `out` on 6.4 -
# and nothing in the Rust remap reaches it, because it is the Swift
# linker's output and not cargo's. 30 such paths, naming the build
# worktree, were measured in the 1.5.0 wrapper on 12 Sep 2026 and in
# v1.4.0's PUBLISHED DMG, which had passed the asset scan on the way
# out (that gate read Mach-O files with `strings FILE`, which does not
# see them; fixed the same day).
#
# ORDER IS LOAD-BEARING: strip invalidates a signature, so it must run
# BEFORE codesign and never after. `-S` removes the debug symbol table
# and leaves the universal binary otherwise intact; panic backtraces in
# the ENGINE are unaffected, since that is a separate Rust binary this
# does not touch.
# Named, not globbed, and FATAL if it is not there: a strip that
# silently found nothing is this leak shipping again with a green log.
[ -f "$APP/Contents/MacOS/NzbFast" ] || {
    echo "no wrapper at $APP/Contents/MacOS/NzbFast to strip" >&2; exit 1; }
strip -S "$APP/Contents/MacOS/NzbFast"

# AND PROVE IT, rather than trusting the line above to have worked. The
# strip is what removes the debug map; this is what fails the build if
# it ever stops doing so - a new Swift target, a reordered step, a
# toolchain that records paths somewhere else. It reads the same
# packaging/private-patterns.txt every other gate reads, and it streams
# the binary rather than letting `strings` parse it, which is the exact
# distinction that hid this for 28 releases. Header: that script.
"$REPO/packaging/assert-no-private-strings.sh" \
    "$APP/Contents/MacOS/NzbFast" \
    "$APP/Contents/Resources/bin/nzbfast"

codesign --force -s - "$APP/Contents/Resources/bin/nzbfast"
codesign --force -s - "$APP"
codesign --verify --deep --strict "$APP"

echo "built $APP (v$VERSION)"
