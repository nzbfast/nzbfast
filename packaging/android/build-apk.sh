#!/bin/sh
# Build the minimal nzbfast APK without gradle: aapt2 + javac + d8 +
# zipalign + apksigner straight from the SDK. Signed with a THROWAWAY
# debug keystore generated on first run - NOT a release identity; the
# production keystore decision is out of scope here.
#
# Prereqs: ANDROID_HOME (build-tools + a platforms/android-NN), JDK 17+,
# and the slim engine binary built first. `--features dashboard` is NOT
# optional for THIS kit: its whole UI is the embedded dashboard in a
# WebView, and since TODO 281 IO3b (28 Aug 2026) the pages are a default
# feature that `--no-default-features` drops - so without it the WebView
# opens on a 404. The compose app next door correctly builds without it:
# its UI is native and it only ever calls the API.
#   cargo ndk -t arm64-v8a --platform 26 build --release -p nzbfast \
#     --no-default-features --features dashboard
#
# Usage: ./build-apk.sh [path-to-engine-binary]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BIN="${1:-$REPO/target/aarch64-linux-android/release/nzbfast}"

: "${ANDROID_HOME:?set ANDROID_HOME (e.g. /opt/homebrew/share/android-commandlinetools)}"
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
PLATFORM=$(ls -d "$ANDROID_HOME"/platforms/android-* | sort -V | tail -1)
echo "==> build-tools: $BT"
echo "==> platform:    $PLATFORM"
[ -f "$BIN" ] || { echo "engine binary not found: $BIN (build it first)" >&2; exit 1; }

OUT="$HERE/build"
rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex" "$OUT/stage/lib/arm64-v8a"

echo "==> aapt2 link (manifest + R)"
"$BT/aapt2" link \
    -I "$PLATFORM/android.jar" \
    --manifest "$HERE/app/AndroidManifest.xml" \
    --min-sdk-version 26 --target-sdk-version 34 \
    --version-code 1 --version-name 0.0.1-test \
    -o "$OUT/base.apk"

echo "==> javac + d8"
find "$HERE/app/java" -name "*.java" > "$OUT/sources.txt"
# --release 8 keeps the JDK's own lambda plumbing visible to javac
# (android.jar carries no LambdaMetafactory); d8 desugars to min-api 26.
javac --release 8 -classpath "$PLATFORM/android.jar" \
    -d "$OUT/classes" @"$OUT/sources.txt"
"$BT/d8" --release --min-api 26 --lib "$PLATFORM/android.jar" \
    --output "$OUT/dex" $(find "$OUT/classes" -name "*.class")

echo "==> assemble"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
cp "$OUT/dex/classes.dex" "$OUT/stage/"
cp "$BIN" "$OUT/stage/lib/arm64-v8a/libnzbfast.so"
(cd "$OUT/stage" && zip -q -X -r ../unsigned.apk classes.dex lib)

echo "==> zipalign + sign (throwaway debug key)"
KS="$HERE/build/debug.keystore"
keytool -genkeypair -keystore "$KS" -storepass android -keypass android \
    -alias debug -keyalg RSA -keysize 2048 -validity 30 \
    -dname "CN=debug" >/dev/null 2>&1
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --out "$HERE/nzbfast-test.apk" "$OUT/aligned.apk"

echo
echo "built: $HERE/nzbfast-test.apk"
echo "install: adb install -r $HERE/nzbfast-test.apk"
