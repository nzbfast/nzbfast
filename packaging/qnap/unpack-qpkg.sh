#!/bin/sh
# Take a .qpkg apart, without QDK.
#
#   packaging/qnap/unpack-qpkg.sh [--parts] <file.qpkg> <outdir>
#
# Writes <outdir>/control/ (qpkg.cfg, package_routines, qinstall.sh,
# icons) and <outdir>/data/ (everything that lands in the installed
# package directory).
#
# With --parts it writes the two inner archives THEMSELVES -
# <outdir>/control.tar and <outdir>/data.tar.gz - and extracts nothing.
# A gate that reads what a member header STORES has to have that, because
# extracting destroys the two fields such gates look at:
#
#   - bsdtar CONSUMES AppleDouble `._name` members on read, so a
#     junk-carrying archive unpacked on the release Mac leaves no trace of
#     them in the tree. That asymmetry is why v1.1.2 shipped five of them
#     in each Linux tarball with every inspection reporting clean.
#   - a non-root tar cannot restore uid/gid, so the builder identity in
#     the headers is gone from anything unpacked from them.
#
# packaging/upload-release-assets.sh's macOS-metadata gate is the caller:
# it hands both parts to python's tarfile, which reads stored headers.
#
# A .qpkg is three things concatenated:
#     [ installer shell script ][ control tar ][ data tar.gz ]
# and the script carries both lengths it needs, so both are recoverable
# from the file itself:
#     script_len=NNNN                          <- the shell script's size
#     offset=$(/usr/bin/expr $script_len + NN) <- the control tar's size
#     dd bs=1024 count=NN                      <- the data archive's size
# The control tar holds one member, itself a .tgz, which is why the
# installer pipes `tar -xO | tar -xz`.
#
# The data archive's length matters because it is NOT the end of the
# file: qbuild appends a 100-byte trailer (the QNAPQPKG marker App Center
# identifies the package by). Reading to EOF hands gzip that trailer as
# trailing garbage, and tar exits non-zero on it - so the extraction has
# to stop where the archive stops. The dd count is rounded UP to a
# kibibyte and so is not that stop; the trailer's own fixed size is.
#
# `qbuild --extract` does the same job, and needs QDK present. This is
# used where QDK is not: verifying a freshly built package, and
# packaging/scan-release-assets.sh, which has to be able to look inside
# every asset before it is uploaded - a leak gate that cannot open a file
# must never report it clean.
set -eu

MODE=extract
if [ "${1:-}" = "--parts" ]; then
    MODE=parts
    shift
fi

QPKG="${1:?usage: unpack-qpkg.sh [--parts] <file.qpkg> <outdir>}"
OUT="${2:?usage: unpack-qpkg.sh [--parts] <file.qpkg> <outdir>}"
[ -f "$QPKG" ] || { echo "✗ no such file: $QPKG" >&2; exit 1; }

# Read only the head of the file: the lengths are in the generated
# script and the rest is binary. NULs are stripped before sed sees them -
# the control tar starts a few kilobytes in, and a command substitution
# over binary is how this reads a length as empty and fails obscurely.
head_text() { head -c 65536 "$QPKG" | LC_ALL=C tr -d '\000'; }

SCRIPT_LEN=$(head_text | sed -n 's/^[[:space:]]*script_len=\([0-9][0-9]*\)[[:space:]]*$/\1/p' | head -1)
CTRL_LEN=$(head_text \
    | sed -n 's/^[[:space:]]*offset=\$(\/usr\/bin\/expr \$script_len + \([0-9][0-9]*\))[[:space:]]*$/\1/p' \
    | head -1)
# The installer copies the data archive out with `dd bs=1024 count=N`, so
# N kibibytes is its length rounded up - near enough to leave the trailer
# behind, which is all this needs.
DATA_KIB=$(head_text | sed -n 's/.*bs=1024 count=\([0-9][0-9]*\).*/\1/p' | head -1)

if [ -z "$SCRIPT_LEN" ] || [ -z "$CTRL_LEN" ]; then
    echo "✗ $QPKG does not look like a QDK package: no script_len/offset" >&2
    echo "  header found. If QDK changed its self-extractor format, this" >&2
    echo "  script has to change with it - see packaging/qnap/qdk-pin.txt." >&2
    exit 1
fi

# What is at each computed boundary, for when one of them is wrong. A
# .qpkg is three concatenated parts and a byte offset that is off by
# anything at all fails as "not an archive", which says nothing about
# which of the three lengths was misread.
#
# Defined BEFORE the first caller, which it was not until 23 Aug 2026:
# the control-archive failure below called it while the definition was
# still eleven lines further down the file, so sh had never executed it
# and the one path most likely to need the dump printed "boundaries: not
# found" instead.
boundaries() {
    echo "  size=$(wc -c < "$QPKG") script_len=$SCRIPT_LEN ctrl_len=$CTRL_LEN data_kib=${DATA_KIB:-?}" >&2
    for _o in "$SCRIPT_LEN" "$((SCRIPT_LEN + CTRL_LEN))"; do
        echo "  at $_o: $(tail -c "+$((_o + 1))" "$QPKG" | od -An -tx1 -N 8 | tr -s ' ')" >&2
    done
    echo "  (a gzip stream starts 1f 8b; a tar member is printable ASCII)" >&2
}

# An unsigned package is exactly script + control + data + trailer, so
# the data archive ends 100 bytes before the end of the file. The dd
# count is the cross-check on that: it is the same length rounded up to a
# kibibyte, so the two must agree to within one. When they do not, the
# package carries something this does not know about (QDK can append a
# code-signing or gpg area between the data and the trailer) - in which
# case fall back to the rounded count and let the emptiness check below
# be the judge, rather than reporting a package unreadable because it was
# signed.
SIZE=$(wc -c < "$QPKG")
DATA_LEN=$((SIZE - SCRIPT_LEN - CTRL_LEN - 100))
STRICT=1
if [ -n "$DATA_KIB" ] && [ "$(( (DATA_LEN + 1023) / 1024 ))" != "$DATA_KIB" ]; then
    DATA_LEN=$((DATA_KIB * 1024))
    STRICT=0
fi
if [ "$DATA_LEN" -le 0 ]; then
    echo "✗ $QPKG: computed a data archive of $DATA_LEN bytes." >&2
    boundaries
    exit 1
fi

if [ "$MODE" = parts ]; then
    mkdir -p "$OUT"
    tail -c "+$((SCRIPT_LEN + 1))" "$QPKG" | head -c "$CTRL_LEN" > "$OUT/control.tar"
    tail -c "+$((SCRIPT_LEN + CTRL_LEN + 1))" "$QPKG" | head -c "$DATA_LEN" \
        > "$OUT/data.tar.gz"
    # The same "it untarred is not proof" check the extract path makes
    # below, one level earlier and all this mode can make: a misread
    # length yields a short or empty part, and a caller handed an empty
    # archive would find no junk in it and call the package clean.
    for _p in "$OUT/control.tar" "$OUT/data.tar.gz"; do
        if [ ! -s "$_p" ]; then
            echo "✗ $QPKG: $_p came out empty." >&2
            boundaries
            exit 1
        fi
    done
    exit 0
fi

mkdir -p "$OUT/control" "$OUT/data"

# tail -c +N is 1-based, so the byte after a header of length N is N+1.
tail -c "+$((SCRIPT_LEN + 1))" "$QPKG" | tar -xO 2>/dev/null \
    | tar -xz -C "$OUT/control" 2>/dev/null \
    || { echo "✗ could not read the control archive of $QPKG" >&2; boundaries; exit 1; }

tail -c "+$((SCRIPT_LEN + CTRL_LEN + 1))" "$QPKG" | head -c "$DATA_LEN" \
    | tar -xz -C "$OUT/data" 2>/dev/null || {
        if [ "$STRICT" = 1 ]; then
            echo "✗ could not read the data archive of $QPKG" >&2
            boundaries
            exit 1
        fi
    }

# "It untarred" is not proof the payload was reached: a truncated stream
# gives tar a valid-looking first member and nothing else.
if [ -z "$(ls -A "$OUT/data" 2>/dev/null)" ]; then
    echo "✗ the data archive of $QPKG unpacked to nothing." >&2
    boundaries
    exit 1
fi
