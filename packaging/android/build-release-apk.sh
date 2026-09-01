#!/bin/sh
# build-release-apk.sh - the Android release asset, end to end.
#
#   packaging/android/build-release-apk.sh              # build + sign + verify
#   packaging/android/build-release-apk.sh --skip-engine  # reuse target/
#   packaging/android/build-release-apk.sh --self-test    # arms only, no build
#
# Output: packaging/android/out/nzbfast-<VER>-android-arm64.apk, where
# <VER> is crates/nzbfast/Cargo.toml's version. That name matters twice:
# packaging/bump-version.sh rewrites every `nzbfast-<dotted>-` token on the
# sixteen website/download*.html pages, and tools/check-site-version.sh
# refuses a tree whose pages name a different one. Neither needed a line
# adding for this asset and neither may be worked around by renaming it.
#
# WHY THIS IS A SCRIPT AND NOT THREE LINES IN A SKILL. Two of the steps
# fail SILENTLY if you skip them.
#   * The engine is a SEPARATE cross-build that gradle knows nothing
#     about. `assembleRelease` over a stale (or absent) engine/ directory
#     succeeds and produces an APK, so the failure is a phone running last
#     week's engine, or an app that dies the moment it execs a .so that is
#     not there. This script builds the engine, stages it, and asserts the
#     staged bytes are the ones it just built.
#   * `assembleRelease` with no keystore produces an UNSIGNED apk (see the
#     comment at signingConfigs in app/build.gradle.kts for why that is
#     deliberate). An unsigned APK looks exactly like a signed one until a
#     phone refuses it. This refuses BEFORE the build, and verifies the
#     signature with apksigner afterwards.
#
# The keystore is the maintainer's and lives outside this repo. Android
# identifies an
# app by its signing key forever: a second key is a second app, and every
# user has to uninstall and lose their settings, queue and downloads. So it
# is handed in by path and never generated here.
#
#   NZBFAST_ANDROID_KEYSTORE            path to the PKCS12 keystore
#   NZBFAST_ANDROID_KEYSTORE_PASS_FILE  file holding the password
#   NZBFAST_ANDROID_KEYSTORE_PASS       or the password itself (CI secrets)
#   NZBFAST_ANDROID_KEY_ALIAS           defaults to nzbfast
#   ANDROID_HOME / ANDROID_SDK_ROOT     the SDK (build-tools + a platform)
#   ANDROID_NDK / $ANDROID_HOME/ndk/*   the NDK, for the engine cross-build
#
# macOS or Linux; the NDK prebuilt directory is picked by uname. No
# cargo-ndk: the four env vars below are the whole of what it does for a
# single target, and one fewer tool on the release box is one fewer thing
# to have a version of.
set -eu
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
APP="$HERE/compose-app"
TARGET=aarch64-linux-android
OUT="$HERE/out"

SKIP_ENGINE=0
SELF_TEST=0
for a in "$@"; do
    case "$a" in
        --skip-engine) SKIP_ENGINE=1 ;;
        --self-test|--selftest) SELF_TEST=1 ;;
        --help|-h) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done

die() { echo "✗ $*" >&2; exit 1; }

# ---- version, from the crate and nowhere else ------------------------
crate_version() {
    sed -n 's/^version = "\([0-9][0-9.]*\)"/\1/p' \
        "$ROOT/crates/nzbfast/Cargo.toml" | head -1
}

# ---- the NDK's clang, by host ----------------------------------------
ndk_bin() {
    _ndk=$1
    case "$(uname -s)" in
        Darwin) _host=darwin-x86_64 ;;
        Linux)  _host=linux-x86_64 ;;
        *) echo "" ; return ;;
    esac
    echo "$_ndk/toolchains/llvm/prebuilt/$_host/bin"
}

# ---- self-test: the refusals, without a toolchain --------------------
# What this protects is the two silent failures above. Both are guarded by
# a refusal, and a refusal that has stopped refusing reads exactly like a
# clean build - so each one is driven here.
if [ "$SELF_TEST" -eq 1 ]; then
    cases=0; bad=0
    ok()   { cases=$((cases+1)); echo "  ok   $1"; }
    fail() { cases=$((cases+1)); bad=1; echo "  FAIL $1"; }

    v=$(crate_version)
    case "$v" in
        [0-9]*.[0-9]*.[0-9]*) ok "crate version parses ($v)" ;;
        *) fail "crate version did not parse out of crates/nzbfast/Cargo.toml" ;;
    esac

    # The gradle build reads the SAME file. A version that moved in one
    # place and not the other is the defect bump-version.sh exists to
    # prevent, so the two readers are held to each other here.
    if grep -q 'crates/nzbfast/Cargo.toml' "$APP/app/build.gradle.kts"; then
        ok "build.gradle.kts takes its version from the crate"
    else
        fail "build.gradle.kts no longer reads crates/nzbfast/Cargo.toml - the APK version has drifted off the crate"
    fi

    if grep -q 'NZBFAST_ANDROID_KEYSTORE' "$APP/app/build.gradle.kts"; then
        ok "build.gradle.kts takes the keystore from the environment"
    else
        fail "build.gradle.kts no longer reads NZBFAST_ANDROID_KEYSTORE"
    fi

    # A debug-signed release is the one outcome that must be impossible.
    if grep -q 'signingConfigs.getByName("debug")' "$APP/app/build.gradle.kts"; then
        fail "the release build type has been pointed at the DEBUG signing config"
    else
        ok "no debug signing config on the release build type"
    fi

    # The keystore must never be reachable from the repo.
    if git -C "$ROOT" ls-files --error-unmatch \
            'packaging/android/**/*.jks' 'packaging/android/**/*.keystore' \
            >/dev/null 2>&1; then
        fail "a keystore is TRACKED under packaging/android - remove it and rotate the key"
    else
        ok "no keystore tracked under packaging/android"
    fi

    # The asset name is the one bump-version.sh and check-site-version.sh
    # both rewrite and both judge. Spelled here so a rename has to move
    # this line too, at which point the two of them are in the diff.
    if grep -q 'nzbfast-\$VERSION-android-arm64\.apk' "$0"; then
        ok "asset name is nzbfast-<VER>-android-arm64.apk"
    else
        fail "the asset name in this script is no longer the version-pinned one the website pages and check-site-version.sh expect"
    fi

    # Refusing with no keystore is the whole point of the wrapper; drive
    # the guard itself rather than trusting it is still there.
    if ( unset NZBFAST_ANDROID_KEYSTORE
         NZBFAST_ANDROID_KEYSTORE= sh "$0" --skip-engine >/dev/null 2>&1 ); then
        fail "a build with no keystore was NOT refused"
    else
        ok "a build with no keystore is refused"
    fi

    # `--skip-engine` promises to reuse the engine already in target/,
    # and until 29 Aug 2026 it resolved the NDK anyway - so a packaging
    # or signing host with everything BUT an NDK exited before it reached
    # the Gradle and signing steps it had all the parts for. Driven with
    # a bare SDK directory (no ndk/ under it, ANDROID_NDK unset): the run
    # must get PAST the NDK ladder. It still fails afterwards - there is
    # no build-tools and no engine in this fixture - so what is asserted
    # is which refusal comes back, not that the build succeeds.
    probe=$(mktemp -d)
    mkdir -p "$probe/sdk" "$probe/ks"
    : > "$probe/ks/fake.jks"
    out=$( unset ANDROID_NDK ANDROID_SDK_ROOT
           NZBFAST_ANDROID_KEYSTORE="$probe/ks/fake.jks" \
           NZBFAST_ANDROID_KEYSTORE_PASS=x \
           ANDROID_HOME="$probe/sdk" \
           sh "$0" --skip-engine 2>&1 || true )
    rm -rf "$probe"
    case "$out" in
        *"no NDK found"*) fail "--skip-engine still demands an NDK it does not use" ;;
        *) ok "--skip-engine reaches past the NDK ladder without one" ;;
    esac

    echo ""
    if [ "$bad" -ne 0 ]; then
        echo "SELF-TEST FAILED ($cases cases)"; exit 1
    fi
    echo "self-test OK ($cases cases)"; exit 0
fi

# ---- refuse before building, never after -----------------------------
KS=${NZBFAST_ANDROID_KEYSTORE:-}
[ -n "$KS" ] || die "NZBFAST_ANDROID_KEYSTORE is not set.
    The release APK is signed with the project's Android release key, which
    lives OUTSIDE this repo. Android identifies an app by its signing key
    forever: build this with a different key and every existing user has to
    uninstall, losing their settings, queue and downloads.
    Point it at the keystore and give the password:
      NZBFAST_ANDROID_KEYSTORE=~/.config/nzbfast/android-release.jks \\
      NZBFAST_ANDROID_KEYSTORE_PASS_FILE=~/.config/nzbfast/android-release.pass \\
      packaging/android/build-release-apk.sh"
[ -f "$KS" ] || die "NZBFAST_ANDROID_KEYSTORE points at nothing: $KS"

if [ -n "${NZBFAST_ANDROID_KEYSTORE_PASS_FILE:-}" ]; then
    [ -f "$NZBFAST_ANDROID_KEYSTORE_PASS_FILE" ] \
        || die "NZBFAST_ANDROID_KEYSTORE_PASS_FILE points at nothing: $NZBFAST_ANDROID_KEYSTORE_PASS_FILE"
elif [ -z "${NZBFAST_ANDROID_KEYSTORE_PASS:-}" ]; then
    die "the keystore needs a password: NZBFAST_ANDROID_KEYSTORE_PASS_FILE (preferred) or NZBFAST_ANDROID_KEYSTORE_PASS"
fi

SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
[ -n "$SDK" ] || die "set ANDROID_HOME (or ANDROID_SDK_ROOT) to the Android SDK"
[ -d "$SDK" ] || die "ANDROID_HOME points at nothing: $SDK"
export ANDROID_HOME="$SDK"

# THE NDK IS THE ENGINE'S, so it is resolved only when the engine is
# being built. `--skip-engine` documents itself as reusing an existing
# target/ binary, and the whole NDK ladder below ran anyway - so a
# packaging or signing host with the SDK, build-tools, a JDK, the
# keystore and the prepared arm64 binary, but no NDK, exited here rather
# than reaching the Gradle and signing steps it had everything for. The
# SDK and build-tools checks stay unconditional: gradle and apksigner
# need them either way.
NDK=""
TC=""
CLANG=""
if [ "$SKIP_ENGINE" -eq 0 ]; then
    NDK=${ANDROID_NDK:-}
    if [ -z "$NDK" ]; then
        NDK=$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1 || true)
    fi
    [ -n "$NDK" ] && [ -d "$NDK" ] \
        || die "no NDK found. Install one:
      sdkmanager 'ndk;28.2.13676358'
    or point ANDROID_NDK at an existing one, or pass --skip-engine to
    reuse the engine already in target/."

    TC=$(ndk_bin "$NDK")
    [ -n "$TC" ] || die "unsupported build host $(uname -s) - this needs the NDK's darwin-x86_64 or linux-x86_64 prebuilt toolchain."
    CLANG="$TC/aarch64-linux-android26-clang"
    [ -x "$CLANG" ] || die "no $CLANG - is $NDK a complete NDK?"
fi

VERSION=$(crate_version)
case "$VERSION" in
    ""|*[!0-9.]*) die "cannot read a dotted version out of crates/nzbfast/Cargo.toml" ;;
esac

BT=$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1 || true)
[ -n "$BT" ] || die "no build-tools under $SDK - sdkmanager 'build-tools;35.0.0'"
APKSIGNER="$BT/apksigner"
[ -x "$APKSIGNER" ] || die "no apksigner in $BT"

echo "== nzbfast $VERSION -> android arm64 =="
echo "   sdk        $SDK"
echo "   ndk        ${NDK:-(not needed - reusing the built engine)}"
echo "   keystore   $KS"

# ---- 1. the engine ---------------------------------------------------
BIN="$ROOT/target/$TARGET/release/nzbfast"
if [ "$SKIP_ENGINE" -eq 0 ]; then
    echo "== 1. engine (slim, $TARGET) =="
    # --no-default-features is the SLIM build: no indexer, which is a
    # desktop surface and drags in the whole SQLite index for nothing on a
    # phone. The four env vars are what cargo-ndk would set for one target.
    (
        cd "$ROOT"
        CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG" \
        CC_aarch64_linux_android="$CLANG" \
        CXX_aarch64_linux_android="$TC/aarch64-linux-android26-clang++" \
        AR_aarch64_linux_android="$TC/llvm-ar" \
        RANLIB_aarch64_linux_android="$TC/llvm-ranlib" \
        cargo build --release -p nzbfast \
            --no-default-features --target "$TARGET"
    )
else
    echo "== 1. engine: SKIPPED (--skip-engine) =="
fi
[ -f "$BIN" ] || die "no engine at $BIN"

echo "== 2. stage the engine =="
sh "$APP/fetch-engine.sh" "$BIN"
STAGED="$APP/app/engine/arm64-v8a/libnzbfast.so"
# The engine is a separate build gradle knows nothing about, so a stale
# staged copy is invisible to it. Assert the bytes, not the timestamp.
if ! cmp -s "$BIN" "$STAGED"; then
    die "the staged engine is not the binary just built:
      built  $BIN
      staged $STAGED
    fetch-engine.sh did not do what it says. Do NOT ship this APK."
fi

echo "== 3. assembleRelease =="
rm -rf "$APP/app/build/outputs/apk/release"
( cd "$APP" && ./gradlew --quiet --console=plain :app:assembleRelease )

APK=$(ls "$APP"/app/build/outputs/apk/release/*.apk 2>/dev/null | head -1 || true)
[ -n "$APK" ] || die "assembleRelease produced no apk under $APP/app/build/outputs/apk/release"
case "$APK" in
    *-unsigned.apk)
        die "gradle produced an UNSIGNED apk ($APK).
    That means the signingConfig did not apply - check
    NZBFAST_ANDROID_KEYSTORE and its password. Never ship this file and
    never sign it by hand as an afterthought: the build is the record." ;;
esac

echo "== 4. verify the signature =="
# A signature that is present is not a signature that verifies, and this
# is the last moment anything looks. --min-sdk-version matches minSdk, so
# apksigner judges the schemes an API 26 phone will actually use.
"$APKSIGNER" verify --min-sdk-version 26 --verbose "$APK" \
    || die "apksigner refuses the apk this build just produced"
echo "   certificate:"
"$APKSIGNER" verify --print-certs "$APK" | sed 's/^/     /'

mkdir -p "$OUT"
DEST="$OUT/nzbfast-$VERSION-android-arm64.apk"
cp "$APK" "$DEST"

echo ""
echo "built: $DEST"
ls -lh "$DEST" | awk '{print "  " $5}'
echo ""
echo "Next, per .claude/skills/publish-release:"
echo "  packaging/scan-release-assets.sh $DEST"
echo "  upload it with the rest of the human downloads"
echo "  do NOT add it to latest.json - the daemon's updater has no android key"
