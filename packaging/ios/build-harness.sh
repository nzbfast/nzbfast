#!/bin/sh
# Build the A3 spike harness app for the iOS SIMULATOR - no Xcode
# project, mirroring packaging/android's no-gradle stance: cargo builds
# the engine staticlib, swiftc builds the one-file SwiftUI app, and the
# bundle is assembled by hand. Usage:
#   packaging/ios/build-harness.sh [simulator-device-name]
# Then: xcrun simctl install <dev> packaging/ios/NZBFastHarness.app
#       xcrun simctl launch <dev> com.nzbfast.spike-harness
set -eu

cd "$(dirname "$0")/../.."
TARGET=aarch64-apple-ios-sim
APP=packaging/ios/NZBFastHarness.app

# `--features nzbfast/dashboard` is NOT optional for THIS harness, and
# it is the one place in packaging/ios that needs it: HarnessApp.swift's
# whole UI is a WebView pointed at the dashboard the engine serves, and
# since TODO 281 IO3b (28 Aug 2026) the pages are a default feature the
# store build drops - so without this the harness opens on a 404. The
# real app next door correctly builds without them: it is SwiftUI
# throughout and only ever calls the API.
cargo build --release -p nzbfast-ffi --features nzbfast/dashboard --target $TARGET

rm -rf "$APP"
mkdir -p "$APP"
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
xcrun -sdk iphonesimulator swiftc \
    -parse-as-library \
    -target arm64-apple-ios16.0-simulator \
    -sdk "$SDK" \
    packaging/ios/HarnessApp.swift \
    -L target/$TARGET/release -lnzbfast_ffi \
    -o "$APP/NZBFastHarness"

# ATS: the dashboard is plain http on loopback - NSAllowsLocalNetworking
# keeps WKWebView willing without opening arbitrary http.
cat > "$APP/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>NZBFastHarness</string>
    <key>CFBundleIdentifier</key><string>com.nzbfast.spike-harness</string>
    <key>CFBundleName</key><string>NZBFastHarness</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>MinimumOSVersion</key><string>16.0</string>
    <key>UILaunchScreen</key><dict/>
    <key>NSAppTransportSecurity</key>
    <dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict>
</plist>
EOF

echo "built $APP"
ls -lh "$APP/NZBFastHarness"
