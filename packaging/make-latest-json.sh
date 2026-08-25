#!/bin/sh
# make-latest-json.sh <dist-dir> [notes]
#
# Generate the auto-update manifest (latest.json) from a dist directory
# containing the autoupdate payload binaries. Platform keys are the
# manifest contract for update clients (docs/UPDATE-DESIGN.md): a
# client picks its exact key (macos-arm64, macos-x64, ...) and falls
# back to macos-universal. The windows payload carries an .exe suffix
# (see the v1.0.0 release assets).
#
# Version comes from crates/nzbfast/Cargo.toml (the source of truth).
#
# EVERY platform payload must be present. A missing one used to be a
# warning on stderr, which meant a typo in the asset names (a stray `v`,
# say) produced a manifest that was written, valid JSON, signed, and
# exited 0 while advertising nothing - a dead release that looks like a
# success at every step. Missing payloads are now fatal. Omit a platform
# on purpose by naming it:
#   ALLOW_MISSING="linux-arm64 windows-x64" packaging/make-latest-json.sh dist
# ALLOW_MISSING=all waives them all, but an EMPTY payloads map is always
# fatal - a manifest that installs nowhere is never what anyone meant.
#
# <dist-dir>/RELEASE_NOTES.md must ALREADY EXIST (write the notes before
# the manifest). It is validated here, and its first body line becomes
# the manifest's `notes` when [notes] is not given. Builds with no
# release notes at all - tester bundles, work-in-progress cuts - say so:
#   SKIP_NOTES_CHECK=1 packaging/make-latest-json.sh dist
set -eu

DIST=${1:?usage: make-latest-json.sh <dist-dir> [notes]}
NOTES=${2:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/nzbfast/Cargo.toml" | head -1)
[ -n "$VERSION" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }
BASE="https://github.com/nzbfast/nzbfast/releases/download/v$VERSION"

# Gate the notes here because this is the one step every release runs
# and cannot skip: the manifest must be signed, and the notes sit right
# next to it. Nothing else reads this file - no CI job, no other script -
# so when this gate does not fire, a platform can be dropped from the
# download table and the only reviewer is whoever happens to read the
# release page.
#
# The file is REQUIRED, not "checked if it happens to be there". This
# block used to be wrapped in `if [ -f ... ]`, which made the gate
# fail-open: publish-release documented the manifest step BEFORE the
# notes step, so a straight top-to-bottom run signed a manifest with an
# empty `notes` field, exited 0, and never validated anything. The
# sentence promising a release "cannot be signed past" bad notes was
# false for exactly the run the skill told you to make.
#
# SKIP_NOTES_CHECK=1 is the only waiver, and it says so on stderr. It is
# for builds that legitimately have no release notes: work-in-progress
# cuts, and the tester bundles release-bundle produces. Never a release.
NOTES_FILE="$DIST/RELEASE_NOTES.md"
if [ "${SKIP_NOTES_CHECK:-0}" = "1" ]; then
    echo "! SKIP_NOTES_CHECK=1 - release notes NOT validated" >&2
elif [ -f "$NOTES_FILE" ]; then
    python3 "$ROOT/packaging/check-release-notes.py" "$NOTES_FILE" "$VERSION"
else
    echo "ERROR: $NOTES_FILE is missing - the notes gate cannot run." >&2
    echo "       Write the notes BEFORE the manifest:" >&2
    echo "         packaging/make-release-notes.sh $VERSION <body-file> \\" >&2
    echo "             > $NOTES_FILE" >&2
    echo "       Tester and work-in-progress bundles have no release" >&2
    echo "       notes and waive this loudly: SKIP_NOTES_CHECK=1 $0 $DIST" >&2
    exit 1
fi
if [ -z "$NOTES" ] && [ -f "$NOTES_FILE" ]; then
    # First non-heading, non-blank line of the release notes.
    NOTES=$(grep -v '^#' "$NOTES_FILE" | grep -m1 . || true)
fi

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# Updater payloads carry the product name + `updater` + version so a
# human who stumbles on the raw binary can tell what it is, while the
# lack of a .dmg/.zip/.tar.gz extension keeps it visibly distinct from
# the human download. The word order is load-bearing: GitHub sorts the
# assets box alphabetically and collapses it to ten rows, and the older
# `nzbfast-X.Y.Z-autoupdate-*` names sorted ABOVE every human download
# (`autoupdate` < `linux/macos/windows`), burying the Windows installer
# behind "Show all". `nzbfast-updater-...` sorts after `nzbfast-X.Y.Z-*`
# (digits before letters), so the payloads sit below the fold where they
# belong. Renaming is safe for deployed clients: the updater reads full
# URLs from this manifest, and latest.json itself keeps its name.
# NOTE: no `v` in the asset name. The tag is vX.Y.Z; the files are not.
#
# TODO 107: payloads ship per-arch and GZIPPED. Measured on the real
# v1.0.15 asset: universal raw 51.4 MB -> arm64 thin + gzipped 10.6 MB,
# a 79% cut per update fetch. (`strip` buys nothing - the release
# profile already strips.) macos-universal STAYS in the map: a future
# client with an unrecognised arch needs a fallback, and the DMG story
# for humans is unchanged either way. The manifest's sha256 is of the
# COMPRESSED bytes - the client verifies what it fetched, then
# decompresses, never the reverse. Format changes are free only while
# self-update is notify-only (today: the daemon reads version/serial/
# notes and never touches this map); the moment the opt-in updater
# ships, this shape is frozen.
#
# WINDOWS-ARM64 IS DELIBERATELY ABSENT FROM THIS LIST. The Windows on ARM
# package ships as a clearly-labelled BETA asset on the release page
# (nzbfast-X.Y.Z-windows-arm64-beta.zip and its -setup.exe, built by the
# windows-arm64-beta job in .github/workflows/release.yml) and nowhere
# else, because nobody has yet run it on ARM64 hardware.
#
# Adding a key here is not a small step and is not easily undone. Every
# entry is ed25519-signed inside a body that also carries the monotonic
# anti-rollback serial above, and clients ratchet that serial one way
# with no server-side reset - so a payload that turns out to be broken
# cannot be withdrawn by publishing a corrected manifest that clients
# would accept as older. An asset on the release page, by contrast, is
# deleted with one gh command and nothing has ever ratcheted on it.
#
# The order is therefore: a tester confirms the beta actually runs on a
# Snapdragon X box -> drop the `-beta` suffix from installer.iss's
# AssetArch and the release job -> build a `nzbfast-updater-$VERSION-
# windows-arm64.exe` payload -> and only then add `windows-arm64` here.
# Until that first step happens, this line is the gate.
#
# NEITHER NAS PACKAGE IS IN THIS LIST EITHER, and for the Synology .spk
# that has always been true: a package manager owns the binary it
# installed, so the update story there is "install the new package", not
# a payload this manifest hands to an updater. The QNAP .qpkg
# (packaging/qnap/, shipped as a clearly-labelled beta) inherits that,
# with the reasoning above on top - nobody has run it on real hardware,
# and this is the one place a mistake cannot be withdrawn. There is no
# `qnap` or `synology` key to add and no work here to do when a tester
# confirms the beta; the checklist in packaging/qnap/README.md says so,
# so that nobody reads the absence as an oversight and "fixes" it.
#
# THE FLATPAK IS NOT IN THIS LIST EITHER, and never will be, for the
# same reason as the packages below plus one of its own: Flatpak owns the
# files it installed AND runs them in a sandbox where the daemon cannot
# write its own binary at all. It has its own update channel, so an
# updater that fought it would be fighting the thing the user actually
# uses. The daemon detects the sandbox (serve/update.rs
# `flatpak_install`) and the dashboard shows `flatpak update` instead of
# the download page, which is the whole of the in-app story. There is no
# `flatpak` key to add and nothing here to do when the beta graduates -
# packaging/flatpak/README.md says so, so the absence does not read as an
# oversight.
#
# THE .deb AND .rpm ARE NOT IN THIS LIST, and never will be, for the
# first of those two reasons: dpkg and rpm own the binary they installed,
# and a self-updater that swapped /usr/bin/nzbfast underneath them would
# leave the package database describing a file that is no longer there.
# `apt upgrade` / `dnf upgrade` is the update path (they are
# download-and-install packages today, so in practice: install the newer
# package). Nothing to add here when the beta graduates - see
# packaging/linux/README.md.
#
# LINUX-ARMV7 IS ABSENT FOR THE SAME REASON AS WINDOWS-ARM64, and the
# same order applies. The 32-bit ARM build (TODO 178) ships as
# nzbfast-X.Y.Z-linux-armv7-beta.tar.gz and nowhere else. Its whole test
# record is emulation - qemu-user, where the full suite passes with zero
# armv7-only failures - and emulation cannot answer what a real Pi 3
# does under sustained load on 1 GB of RAM. A Pi is also the worst place
# to be wrong: headless, unattended, and rarely watched. A tester
# confirms it on hardware -> drop `-beta` from
# packaging/build-linux-tarballs.sh and the release job -> build a
# `nzbfast-updater-$VERSION-linux-armv7` payload -> and only then add
# `linux-armv7` here.
#
# THE FREEBSD TARBALL IS NOT IN THIS LIST EITHER, for the Windows-ARM64
# reason exactly: nobody has run it on a real FreeBSD machine. It is
# built and end-to-end smoke-tested inside a FreeBSD VM on every release
# (the freebsd-beta job in .github/workflows/release.yml), which is more
# than the ARM64 build gets, and it is still not a NAS with real disks -
# so it ships as `nzbfast-X.Y.Z-freebsd-x64-beta.tar.gz` on the release
# page and nowhere else. The order is the same: a tester confirms it runs
# on real FreeBSD -> drop `-beta` from the asset name -> build a
# `nzbfast-updater-$VERSION-freebsd-x64` payload -> and only then add a
# `freebsd-x64` key here. Until that first step happens, this line is the
# gate. The tester checklist is in packaging/freebsd/README.md.
PLATFORMS='macos-universal macos-arm64 macos-x64 windows-x64 linux-x64 linux-arm64'
payload() {   # $1 = platform key -> path of its RAW autoupdate payload
    if [ "$1" = windows-x64 ]; then
        printf '%s' "$DIST/nzbfast-updater-$VERSION-$1.exe"
    else
        printf '%s' "$DIST/nzbfast-updater-$VERSION-$1"
    fi
}

# The mac thin payloads are derived, not built: build-bundles.sh emits
# the universal binary, and `lipo -thin` here cuts the two arch slices
# from it. Derivation is skipped only when the thin file is NEWER than
# the universal (a future build-bundles.sh may emit them directly); a
# thin file older than the universal is a leftover from a previous run
# and re-deriving it is what keeps a same-version re-cut honest - a
# stale slice would sha-match and sign cleanly, and nothing downstream
# could catch it. Loudly fatal when lipo cannot extract a slice - a
# universal payload missing an arch is a broken build, not a waivable
# absence.
UNI=$(payload macos-universal)
if [ -f "$UNI" ] && command -v lipo >/dev/null 2>&1; then
    for arch in arm64 x64; do
        thin=$(payload "macos-$arch")
        [ -f "$thin" ] && [ "$thin" -nt "$UNI" ] && continue
        lipo_arch=$arch
        [ "$arch" = x64 ] && lipo_arch=x86_64
        lipo "$UNI" -thin "$lipo_arch" -output "$thin" || {
            echo "ERROR: lipo could not extract $lipo_arch from $(basename "$UNI")" >&2
            exit 1
        }
        echo "derived $(basename "$thin") from the universal payload" >&2
    done
fi

# ---- Pre-flight: refuse to build a manifest that installs nowhere ------
WAIVED=$(printf ' %s ' "${ALLOW_MISSING:-}" | tr ',' ' ')
missing=''
waived=''
present=0
for plat in $PLATFORMS; do
    f=$(payload "$plat")
    if [ -f "$f" ]; then
        present=$((present + 1))
    elif [ "${ALLOW_MISSING:-}" = all ] || printf '%s' "$WAIVED" | grep -q " $plat "; then
        waived="$waived    $plat  ($(basename "$f"))
"
    else
        missing="$missing    $plat  ($(basename "$f"))
"
    fi
done

if [ -n "$missing" ]; then
    echo "ERROR: autoupdate payload(s) not found in $DIST:" >&2
    printf '%s' "$missing" >&2
    echo "       A manifest without them is still valid JSON and still" >&2
    echo "       signs fine - it just never carries those payloads." >&2
    echo "       Build the missing payloads, check the names (no 'v'," >&2
    echo "       version $VERSION), or waive them deliberately with:" >&2
    echo "         ALLOW_MISSING=\"<platform> ...\" $0 $DIST" >&2
    exit 1
fi
if [ "$present" -eq 0 ]; then
    echo "ERROR: no autoupdate payloads at all in $DIST - the payloads" >&2
    echo "       map would be empty. A signed, valid manifest advertising" >&2
    echo "       no downloads is a dead release, so this is never allowed" >&2
    echo "       (not even with ALLOW_MISSING). Expected one or more of:" >&2
    for plat in $PLATFORMS; do echo "         $(basename "$(payload "$plat")")" >&2; done
    exit 1
fi
if [ -n "$waived" ]; then
    echo "note: platform(s) deliberately omitted via ALLOW_MISSING:" >&2
    printf '%s' "$waived" >&2
fi

# ---- Anti-rollback serial ---------------------------------------------
# A monotonic integer INSIDE the signed body. Clients keep the highest one
# they have ever seen, so a replayed old-but-validly-signed manifest is
# recognisable as stale. Signing alone cannot catch that: a replay really
# was signed by us.
#
# The value is generation time in epoch seconds. That needs no counter
# state to lose, and it is only ever compared against a client's own
# stored value - never against a client's clock - so a user with a wrong
# clock is never locked out. It is a serial that happens to be a
# timestamp, not a `not_before`.
#
# THE ONE WAY THIS GOES WRONG is a serial that goes backwards (a release
# manager's clock set back, or a manifest rebuilt from an old checkout).
# Clients ratchet one way and there is no server-side reset, so once
# enforcement lands, a regressed serial would wedge the update channel on
# every install that recorded the higher one - permanently, and no later
# release could fix it. So the last shipped serial is committed here and
# a regression is fatal at generation time, where it is still cheap.
SERIAL_FILE="$ROOT/packaging/update-serial.txt"
SERIAL=$(date +%s)
if [ -f "$SERIAL_FILE" ]; then
    PREV=$(tr -dc '0-9' < "$SERIAL_FILE")
    if [ -n "$PREV" ] && [ "$SERIAL" -le "$PREV" ]; then
        echo "ERROR: update serial would go BACKWARDS: $SERIAL <= $PREV" >&2
        echo "       ($SERIAL_FILE holds the last shipped serial.)" >&2
        echo "       Clients keep the highest serial they have seen and" >&2
        echo "       never lower it, so publishing this would wedge the" >&2
        echo "       update channel for everyone who saw $PREV." >&2
        echo "       Check this machine's clock before doing anything else." >&2
        exit 1
    fi
fi

# ---- Compress the payloads; the .gz files are the release assets ------
# `gzip -9 -n`: -n drops the name+mtime header fields, so the same input
# bytes always give the same .gz bytes and a re-run cannot silently
# change a sha256 the manifest already advertised.
for plat in $PLATFORMS; do
    f=$(payload "$plat")
    [ -f "$f" ] || continue
    gzip -9 -n -c "$f" > "$f.gz"
done

OUT="$DIST/latest.json"
first=1
{
    # "payloads", NOT "platforms": the pre-1.0.5 self-updater read
    # `platforms[<key>].url`, hashed whatever bytes it fetched, and
    # wrote them over the executable - so a gzip payload under the OLD
    # field name would sha-verify and get installed as the binary
    # (brick on restart). Under the new name those ghost clients find
    # nothing, do nothing, and keep their notify banner. Every client
    # shipped since 1.0.5 reads only version/serial/notes.
    printf '{\n  "version": "%s",\n  "serial": %s,\n  "notes": %s,\n  "payloads": {' \
        "$VERSION" "$SERIAL" "$(printf '%s' "$NOTES" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
    for plat in $PLATFORMS; do
        # Absence is already decided above: anything still missing here
        # was explicitly waived via ALLOW_MISSING.
        f=$(payload "$plat")
        if [ ! -f "$f" ]; then
            continue
        fi
        # sha256 is of the COMPRESSED bytes: the client checks exactly
        # what it fetched, before any byte reaches a decompressor.
        [ $first = 1 ] || printf ','
        first=0
        printf '\n    "%s": {\n      "url": "%s/%s",\n      "sha256": "%s",\n      "compression": "gzip"\n    }' \
            "$plat" "$BASE" "$(basename "$f").gz" "$(sha "$f.gz")"
    done
    printf '\n  }\n}\n'
} > "$OUT"

python3 -c "import json; json.load(open('$OUT'))" || { echo "generated manifest is invalid JSON" >&2; exit 1; }
echo "wrote $OUT (version $VERSION)"

# Sign the manifest. The daemon REFUSES any manifest without a valid
# ed25519 signature by the key embedded in the binary (serve.rs
# UPDATE_PUBKEY_HEX), so an unsigned release is a broken release: no client
# will ever accept it. The private key lives only in $NZBFAST_UPDATE_SIGNING_KEY
# (a path to the offline hex key), never in the repo or CI.
if [ -z "${NZBFAST_UPDATE_SIGNING_KEY:-}" ]; then
    echo "" >&2
    echo "ERROR: NZBFAST_UPDATE_SIGNING_KEY is not set - $OUT is UNSIGNED." >&2
    echo "       Clients refuse unsigned manifests. Set it to the path of the" >&2
    echo "       offline ed25519 private key (hex) and re-run. Generate a pair" >&2
    echo "       with: cargo run -p nzbfast --example update_sign -- keygen" >&2
    exit 1
fi
SIGNER="$ROOT/target/release/examples/update_sign"
[ -x "$SIGNER" ] || SIGNER="$ROOT/target/debug/examples/update_sign"
if [ ! -x "$SIGNER" ]; then
    echo "building update_sign tool…" >&2
    ( cd "$ROOT" && cargo build --release -p nzbfast --example update_sign >&2 )
    SIGNER="$ROOT/target/release/examples/update_sign"
fi
# The signer's own self-check verifies with the key it just used, which
# proves the crypto library works and nothing about WHICH key was used:
# any well-formed ed25519 private key passes it. A stale, rotated or test
# key therefore produced a green "signed" line, a manifest every shipped
# client rejects, and a burned serial (Codex sweep 24 Aug, F-15). Hold
# the supplied key to the ONE key clients actually trust, read out of
# serve/update.rs so the two cannot drift, BEFORE anything is signed or
# recorded.
EXPECTED_PUB=$(grep -A1 'UPDATE_PUBKEY_HEX: &str =' "$ROOT/crates/nzbfast/src/serve/update.rs" \
    | grep -o '"[0-9a-f]\{64\}"' | tr -d '"')
if [ -z "$EXPECTED_PUB" ]; then
    echo "ERROR: could not read UPDATE_PUBKEY_HEX out of crates/nzbfast/src/serve/update.rs" >&2
    echo "       (did the constant move or change shape? fix this extraction with it)" >&2
    exit 1
fi
GOT_PUB=$("$SIGNER" pubkey "$NZBFAST_UPDATE_SIGNING_KEY") || {
    echo "ERROR: could not derive a public key from NZBFAST_UPDATE_SIGNING_KEY" >&2
    exit 1
}
if [ "$GOT_PUB" != "$EXPECTED_PUB" ]; then
    echo "" >&2
    echo "ERROR: NZBFAST_UPDATE_SIGNING_KEY is NOT the production update key." >&2
    echo "       it derives  $GOT_PUB" >&2
    echo "       clients trust $EXPECTED_PUB (serve/update.rs UPDATE_PUBKEY_HEX)" >&2
    echo "       Signing with it would produce a manifest every client rejects" >&2
    echo "       and burn a release serial. Nothing was signed or recorded." >&2
    exit 1
fi
"$SIGNER" sign "$NZBFAST_UPDATE_SIGNING_KEY" "$OUT" || { echo "signing failed" >&2; exit 1; }
echo "signed $OUT -> $OUT.sig (key verified against the embedded UPDATE_PUBKEY_HEX)"

# Only now, once a signed manifest actually exists, record the serial as
# shipped. Doing it earlier would raise the floor on a run that died before
# producing anything - harmless with timestamps, but it would mean the file
# no longer says what it claims to say.
printf '%s\n' "$SERIAL" > "$SERIAL_FILE"
echo "recorded serial $SERIAL in $SERIAL_FILE - COMMIT THIS with the release" >&2
