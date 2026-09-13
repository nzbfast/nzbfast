#!/bin/bash
# Build parfast.app - the SwiftUI PAR2 front end
# (research/PLAN-PARFAST-GUI-2026-09-12.md, chip B).
#
#   ./make-app.sh                 universal (arm64 + x86_64)
#   ARCH=arm64 ./make-app.sh      this Mac only, for a quick loop
#
# Modelled on macapp/make-app.sh: no Xcode project, `swift build` plus this
# script, the iconset built into a temp directory and never committed, ad-hoc
# signing inside-out until a Developer ID lands.
#
# The Rust core is built here and linked in. That crate lives in a DETACHED
# cargo workspace (plan 4.4, decision D2a - PUBLIC_MANIFEST ships crates/
# wholesale), so the build line needs `--manifest-path apps/parfast/Cargo.toml`;
# a bare `-p parfast-ffi` from the repo root does not find it.
#
#   NO_FFI=1 ./make-app.sh    skip it and build the MockCore demo instead
#
# Package.swift picks the library up by looking for vendor/lib/libparfast_ffi.a,
# so a tree without it still builds and tests on the mock. Until then the app is built
# on MockCore and says so in its own Settings pane (the engine line reads
# "MockCore (no engine linked)"), so a tester can never mistake a demo for a
# verify.
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd ../../.. && pwd)"

# Version tracks nzbfast's, per SPEC-PARFAST-PUBLICATION D3.
VERSION=$(grep '^version' "$REPO/crates/nzbfast/Cargo.toml" | head -1 | cut -d'"' -f2)
ARCH="${ARCH:-universal}"
echo "== parfast.app v$VERSION ($ARCH)"

# --- the Rust core ----------------------------------------------------
FFI_WS="$REPO/apps/parfast/Cargo.toml"
if [ "${NO_FFI:-0}" = "1" ]; then
    echo "== NO_FFI=1: building the MockCore demo"
    rm -f vendor/lib/libparfast_ffi.a
elif [ -f "$FFI_WS" ]; then
    echo "== building the universal staticlib"
    for target in aarch64-apple-darwin x86_64-apple-darwin; do
        cargo build --manifest-path "$FFI_WS" --release -p parfast-ffi --target "$target"
    done
    mkdir -p vendor/lib
    lipo -create -output vendor/lib/libparfast_ffi.a \
        "$REPO/apps/parfast/target/aarch64-apple-darwin/release/libparfast_ffi.a" \
        "$REPO/apps/parfast/target/x86_64-apple-darwin/release/libparfast_ffi.a"
    lipo -info vendor/lib/libparfast_ffi.a
else
    echo "== no $FFI_WS: building the MockCore demo"
fi

# --- the Swift app ----------------------------------------------------
if [ "$ARCH" = "universal" ]; then
    swift build -c release --arch arm64 --arch x86_64
    BINARY=.build/apple/Products/Release/Parfast
else
    swift build -c release --arch "$ARCH"
    BINARY=$(swift build -c release --arch "$ARCH" --show-bin-path)/Parfast
fi

APP=build/parfast.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINARY" "$APP/Contents/MacOS/parfast"

# The string catalogue rides along for the locales that follow in v1.1. The
# app reads its English out of the generated Swift constants, so a missing
# catalogue degrades to English rather than to blank labels.
cp Sources/ParfastApp/Resources/Localizable.xcstrings "$APP/Contents/Resources/" 2>/dev/null || true

# --- icon -------------------------------------------------------------
# Generated at build time and never committed (see the waiver in the
# generator). The 1024 master takes ~15 s of pure Python, so it is cached in
# build/ - delete build/icon-1024.png to redraw it.
mkdir -p build
MASTER=build/icon-1024.png
if [ ! -f "$MASTER" ]; then
    echo "== drawing the icon master"
    ../shared/icon/make-icon-master.py "$MASTER" --size 1024
fi
ICONSET=$(mktemp -d)/parfast.iconset
mkdir -p "$ICONSET"
for entry in 16:icon_16x16 32:icon_16x16@2x 32:icon_32x32 64:icon_32x32@2x \
             128:icon_128x128 256:icon_128x128@2x 256:icon_256x256 \
             512:icon_256x256@2x 512:icon_512x512 1024:icon_512x512@2x; do
    size=${entry%%:*}; name=${entry#*:}
    sips -z "$size" "$size" "$MASTER" --out "$ICONSET/$name.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/parfast.icns"

# --- Info.plist -------------------------------------------------------
# Plan 6.1: the exported UTI, document types for par2 and the four checksum
# kinds, the parfast:// URL scheme, and the two NSServices entries that become
# Finder Quick Actions. The NSMessage values are the AppDelegate selectors
# minus their argument labels - rename one and the menu item silently stops
# working, which is why they are named here in the same breath.
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>parfast</string>
  <key>CFBundleDisplayName</key><string>parfast</string>
  <key>CFBundleIdentifier</key><string>com.nzbfast.parfast</string>
  <key>CFBundleExecutable</key><string>parfast</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleIconFile</key><string>parfast</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <!-- One window, one instance: a second copy over the same folder would
       have two queues writing the same recovery files. -->
  <key>LSMultipleInstancesProhibited</key><true/>
  <key>NSHumanReadableCopyright</key><string>parfast</string>

  <key>UTExportedTypeDeclarations</key>
  <array>
    <dict>
      <key>UTTypeIdentifier</key><string>com.nzbfast.par2</string>
      <key>UTTypeDescription</key><string>PAR2 recovery file</string>
      <key>UTTypeConformsTo</key><array><string>public.data</string></array>
      <key>UTTypeTagSpecification</key>
      <dict>
        <key>public.filename-extension</key><array><string>par2</string></array>
      </dict>
    </dict>
  </array>

  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeName</key><string>PAR2 recovery file</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>LSHandlerRank</key><string>Owner</string>
      <key>LSItemContentTypes</key><array><string>com.nzbfast.par2</string></array>
    </dict>
    <dict>
      <key>CFBundleTypeName</key><string>Checksum list</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>LSHandlerRank</key><string>Alternate</string>
      <key>CFBundleTypeExtensions</key>
      <array><string>sfv</string><string>md5</string><string>sha1</string><string>sha256</string></array>
    </dict>
  </array>

  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key><string>com.nzbfast.parfast.open</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>CFBundleURLSchemes</key><array><string>parfast</string></array>
    </dict>
  </array>

  <key>NSServices</key>
  <array>
    <dict>
      <key>NSMenuItem</key><dict><key>default</key><string>Verify with parfast</string></dict>
      <key>NSMessage</key><string>verifyWithParfast</string>
      <key>NSPortName</key><string>parfast</string>
      <key>NSRequiredContext</key><dict><key>NSTextContent</key><string>FilePath</string></dict>
      <key>NSSendFileTypes</key><array><string>com.nzbfast.par2</string></array>
    </dict>
    <dict>
      <key>NSMenuItem</key><dict><key>default</key><string>Create PAR2 with parfast</string></dict>
      <key>NSMessage</key><string>createWithParfast</string>
      <key>NSPortName</key><string>parfast</string>
      <key>NSSendFileTypes</key>
      <array><string>public.item</string><string>public.folder</string></array>
    </dict>
  </array>
</dict>
</plist>
PLIST

# --- ad-hoc sign, inside-out ------------------------------------------
# arm64 refuses unsigned Mach-Os and lipo output loses the linker's ad-hoc
# signature. Nothing is nested yet; once the staticlib lands it is linked in
# rather than bundled, so this stays a single seal.
# STRIP THE DEBUG MAP BEFORE SIGNING. `swift build` records one
# absolute path per object file in the linked binary's debug map (the
# N_OSO stabs), so without this the app ships the build machine's
# directory layout - 149 such paths were measured in the 1.5.0-alpha.1
# bundle on 12 Sep 2026, and packaging/scan-release-assets.sh refused
# the zip for them. Nothing in the Rust remap reaches these: they are
# the Swift linker's, not cargo's. Same fix and same reasoning as
# macapp/make-app.sh, which carries the longer note.
#
# ORDER IS LOAD-BEARING: strip invalidates a signature, so it runs
# BEFORE codesign. Named rather than globbed, and fatal if absent - a
# strip that silently found nothing is the leak shipping again with a
# green log.
[ -f "$APP/Contents/MacOS/parfast" ] || {
    echo "no binary at $APP/Contents/MacOS/parfast to strip" >&2; exit 1; }
strip -S "$APP/Contents/MacOS/parfast"

# And prove it. Same reasoning and the same script as
# macapp/make-app.sh, which carries the longer note: the strip removes
# the debug map, this fails the build if it ever stops.
"$REPO/packaging/assert-no-private-strings.sh" "$APP/Contents/MacOS/parfast"

codesign --force -s - "$APP"
codesign --verify --strict "$APP"

echo "built $APP (v$VERSION)"
