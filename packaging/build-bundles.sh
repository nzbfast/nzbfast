#!/usr/bin/env bash
# ############################################################################
# NOT A RELEASE SCRIPT. Do not use this to cut a release.
#
# This is the 19 Jul "friend-shareable bundle" builder, superseded by the
# release conventions of 20 Jul onwards. Its output does NOT match what a
# release consumes, in five ways, every one of which breaks something
# downstream:
#   - zip names carry no version   (release wants nzbfast-X.Y.Z-*.zip)
#   - mac inner dir is nzbfast-mac/    (release wants nzbfast-macos/)
#   - the windows zip is FLAT          (release wants nzbfast-windows/)
#   - no nzbtray.exe                   (the windows zip must carry it)
#   - a getting-started PDF instead of MANUAL.html at the zip root
# It also builds no Linux tarballs (push-image.sh pulls those from the
# release), no DMG, no installer, and no autoupdate payloads.
#
# The live release path is `.claude/skills/publish-release/SKILL.md` §2
# with `.claude/skills/release-bundle/SKILL.md`, i.e.:
#   macapp/make-app.sh + packaging/mac/make-dmg.sh   -> the DMG
#   packaging/windows/make-installer.sh              -> the setup .exe
#   the cargo/lipo/zip recipes in release-bundle     -> the portable zips
# Left in place, unrewritten, because it is still a working way to hand
# someone a test build - just never a release asset.
# ############################################################################
#
# Build the friend-shareable nzbfast bundles (Mac universal + Windows x64).
#
# Produces, in ./dist:
#   nzbfast-mac.zip          (universal: Apple Silicon + Intel)
#   nzbfast-windows-x64.zip  (static x86_64)
# Each contains the binary + README + a double-click
# launcher + the getting-started PDF. Servers are NOT bundled - the
# launcher runs `nzbfast setup` (interactive wizard) on first run.
#
# Prereqs (macOS build host):
#   rustup target add aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-gnu
#   brew install mingw-w64        # Windows cross-linker
#   python3 -m pip install reportlab pypdfium2   # PDF guide generation
#
# (PAR2 verify/repair and RAR extraction are fully native - no
# third-party binaries ship.)
set -euo pipefail
cd "$(dirname "$0")/.."                 # repo root
ROOT=$(pwd); PKG=packaging; DIST=dist; WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$DIST"

echo "== 1. Build binaries =="
# 11.0: the mac CLI floor (research/MAC-DEPLOYMENT-TARGET-2026-09-15.md).
MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target aarch64-apple-darwin -p nzbfast
MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target x86_64-apple-darwin  -p nzbfast
# The static link-arg lives in .cargo/config.toml alongside the
# --remap-path-prefix. Do NOT reintroduce CARGO_TARGET_*_RUSTFLAGS here:
# the env var REPLACES the config flags rather than adding to them, so it
# would silently drop the remap and bake absolute build-host paths into
# the shipped .exe (the v1.0.0 binaries carried 500+ such strings).
cargo build --release --target x86_64-pc-windows-gnu -p nzbfast
lipo -create -output "$WORK/nzbfast" \
  target/aarch64-apple-darwin/release/nzbfast \
  target/x86_64-apple-darwin/release/nzbfast

echo "== 2. Generate PDFs =="
( cd "$PKG/mac"     && python3 make_guide_mac.py )   # -> nzbfast-mac-getting-started.pdf
( cd "$PKG/windows" && python3 make_guide.py )       # -> nzbfast-windows-getting-started.pdf

echo "== 3. Assemble Mac bundle =="
M="$WORK/nzbfast-mac"; mkdir -p "$M"
cp "$WORK/nzbfast"                    "$M/nzbfast"
cp "$PKG/mac/Start nzbfast.command"  "$M/"
cp "$PKG/mac/README.txt"             "$M/"
cp "$PKG/mac/nzbfast-mac-getting-started.pdf" "$M/nzbfast-getting-started.pdf"
chmod +x "$M/nzbfast" "$M/Start nzbfast.command"
( cd "$WORK" && zip -q -r -X "$ROOT/$DIST/nzbfast-mac.zip" nzbfast-mac )

echo "== 4. Assemble Windows bundle =="
W="$WORK/win"; mkdir -p "$W"
cp target/x86_64-pc-windows-gnu/release/nzbfast.exe "$W/nzbfast.exe"
cp "$PKG/windows/Start nzbfast.bat"  "$W/"
cp "$PKG/windows/README.txt"         "$W/"
cp "$PKG/windows/nzbfast-windows-getting-started.pdf" "$W/nzbfast-getting-started.pdf"
( cd "$W" && zip -q -X "$ROOT/$DIST/nzbfast-windows-x64.zip" \
    nzbfast.exe README.txt \
    "Start nzbfast.bat" nzbfast-getting-started.pdf )

echo "== Done =="; ls -lh "$DIST"/*.zip
