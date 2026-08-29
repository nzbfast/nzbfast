#!/bin/sh
# Build crates/nzbfast-ffi as a staticlib for whatever the Xcode build is
# targeting, and leave it where the linker's LIBRARY_SEARCH_PATHS expects
# it. Run as a build phase of the NzbfastMobile target (TODO 281 IO1);
# also runnable by hand:
#
#   packaging/ios/build-ffi.sh iphonesimulator arm64 Debug
#
# WHY A SCRIPT AND NOT A CHECKED-IN .a: the engine is the product, it
# changes every day, and a stale binary in the tree is the one failure
# nobody notices - the app would keep working while testing a build from
# last week. Cargo's own freshness check makes the rebuild free when
# nothing moved.
set -eu

PLATFORM="${1:-${PLATFORM_NAME:-iphonesimulator}}"
# ARCHS is a space-separated LIST: one entry on an Apple silicon
# Simulator build, one per slice on a generic or universal build
# ("arm64 x86_64" is what a generic simulator/CI build hands us). Each
# slice maps to its own Rust target below and the results are lipo'd
# into ONE per-platform output directory - which is where the project's
# LIBRARY_SEARCH_PATHS point, so the linker never has to know which
# slices this invocation built. A one-entry list takes the same path
# (lipo -create accepts a single input), so the common single-arch
# build costs one extra copy and nothing else.
ARCHLIST="${2:-${ARCHS:-arm64}}"
CONFIG="${3:-${CONFIGURATION:-Debug}}"

cd "$(dirname "$0")/../.."

# Xcode hands a build phase a minimal PATH with no ~/.cargo/bin in it.
PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
export PATH
command -v cargo >/dev/null 2>&1 || {
    echo "error: cargo is not on PATH - install Rust, then add the targets with" >&2
    echo "       rustup target add <target> (the mapping is the case table below)" >&2
    exit 1
}

# Debug builds of the ENGINE are unusably slow (yEnc and PAR2 are the
# whole product and both are hot loops), so the staticlib is release
# whatever the app is built as. The app's own Swift keeps the
# configuration Xcode asked for - only this dependency is pinned.
PROFILE=release
FLAGS="--release"

LIBS=""
for ARCH in $ARCHLIST; do
    case "$PLATFORM:$ARCH" in
        iphonesimulator:arm64)  TARGET=aarch64-apple-ios-sim ;;
        iphonesimulator:x86_64) TARGET=x86_64-apple-ios ;;
        iphoneos:arm64)         TARGET=aarch64-apple-ios ;;
        *)
            echo "error: no Rust target for $PLATFORM/$ARCH" >&2
            exit 1
            ;;
    esac

    # CARGO_TARGET_DIR is deliberately NOT redirected into DerivedData: a
    # shared checkout already carries one target/ per worktree (CLAUDE.md's
    # disk section), and a second copy per DerivedData directory is the same
    # multiplication one level down.
    # `-p nzbfast-ffi` ALONE, and that is load-bearing rather than tidy:
    # the store binary carries no web dashboard because nzbfast-ffi asks
    # for nzbfast with `default-features = false` (TODO 281 IO3b), and
    # cargo resolves features per invocation. Add `--workspace`, or a
    # second `-p nzbfast`, and unification with the bin's `default` puts
    # 10.5 MB of pages back into the app with nothing to say so.
    cargo build $FLAGS -p nzbfast-ffi --target "$TARGET"

    LIB="target/$TARGET/$PROFILE/libnzbfast_ffi.a"
    [ -f "$LIB" ] || { echo "error: $LIB was not produced" >&2; exit 1; }
    LIBS="$LIBS $LIB"
done

# target/ios/ collides with no cargo triple directory, so cargo never
# writes here and this script owns the path.
OUT="target/ios/$PLATFORM/$PROFILE"
mkdir -p "$OUT"
xcrun lipo -create $LIBS -output "$OUT/libnzbfast_ffi.a"
echo "nzbfast-ffi: $OUT/libnzbfast_ffi.a ($(du -h "$OUT/libnzbfast_ffi.a" | cut -f1)) for $PLATFORM/[$ARCHLIST]"
