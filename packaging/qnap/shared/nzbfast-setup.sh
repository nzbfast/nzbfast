#!/bin/sh
# Everything the install has to decide once the payload is on disk:
# which binary this NAS can run, and where the data goes.
#
# Kept out of package_routines and shipped in the package so it can be
# run on its own - the folder choice is the one part of a NAS package
# that cannot be tried out before a NAS installs it, and nobody on the
# team has a QNAP. packaging/tests/qnap-install.sh drives this file
# directly against fake volume trees.
#
# Runs as root, from pkg_post_install in package_routines. Every input is
# a variable qinstall.sh has already resolved and that hook passes in the
# environment (qinstall does not export them itself - a new input has to
# be added there too), which is also how the test harness fakes a NAS.
set -e

PORT="@@PORT@@"
QPKG_DIR="${SYS_QPKG_DIR:?SYS_QPKG_DIR is not set}"
ENVFILE="$QPKG_DIR/nzbfast.env"

say() { /bin/echo "nzbfast: $*"; }

# ---- architecture -----------------------------------------------------
#
# One package covers every model (see qpkg.cfg), so it arrives carrying
# both 64-bit binaries. Link the one this NAS can run and delete the
# other, so the install does not sit on twice the disk it needs for the
# rest of its life. package_routines has already refused the models that
# match neither, before any of this was unpacked.
machine="${QNAP_TEST_UNAME:-$(/bin/uname -m 2>/dev/null || echo unknown)}"
case "$machine" in
    x86_64|amd64)  want=nzbfast-x86_64 ;;
    aarch64|arm64) want=nzbfast-aarch64 ;;
    *)
        say "unsupported architecture '$machine' - this should have been"
        say "refused before unpacking. Not installing a broken package."
        exit 1
        ;;
esac
if [ ! -f "$QPKG_DIR/bin/$want" ]; then
    say "package is missing bin/$want - the build is broken."
    exit 1
fi
ln -sf "$want" "$QPKG_DIR/bin/nzbfast"
for other in nzbfast-x86_64 nzbfast-aarch64; do
    [ "$other" = "$want" ] || rm -f "$QPKG_DIR/bin/$other"
done
chmod 755 "$QPKG_DIR/bin/$want" "$QPKG_DIR/nzbfast.sh" 2>/dev/null || true

# ---- where the data goes ----------------------------------------------
#
# NOT inside the package directory, and this is the whole reason the
# layout looks the way it does. QDK's generated uninstall script does
# `rsync -a --delete` followed by `rm -rf` over $QPKG_DIR - so anything
# kept in there is deleted by a single click in the App Center, with no
# undo and no warning that mentions downloads. An upgrade is safe (QDK
# only removes files the PREVIOUS package shipped and this one does not),
# but uninstall is not, and one wrong click should not cost somebody a
# terabyte and their server passwords.
#
# The layout is the container's, exactly:
#     <data>/config      config.json, settings.json, apikey, index.db, .spool
#     <data>/downloads
#     <data>/watch
# which is what the compose file maps at /config, /downloads and /watch.
# Anyone moving off Container Station already has that folder, and the
# reuse pass below picks it up as it stands rather than starting them
# over with an empty install.

# An upgrade must never move somebody's data. If the env file is there,
# it is the source of truth and nothing here gets a vote.
if [ -f "$ENVFILE" ]; then
    # shellcheck disable=SC1090
    . "$ENVFILE"
    if [ -n "${NZBFAST_DATA:-}" ]; then
        say "keeping the existing data folder: $NZBFAST_DATA"
        mkdir -p "$NZBFAST_DATA/config" "$NZBFAST_DATA/downloads" \
                 "$NZBFAST_DATA/watch" 2>/dev/null || true
        exit 0
    fi
    say "$ENVFILE names no data folder - choosing one again."
fi

# Candidate roots, best first. $SYS_DOWNLOAD_PATH and $SYS_PUBLIC_PATH
# are resolved by qinstall from the NAS's own share definitions, so they
# are right even on a NAS whose shares were renamed or built in another
# language. The install volume comes first: QPKG_VOLUME_SELECT lets the
# user pick where this is going, and that answer is a statement about
# which volume has the room.
candidates=""
# Takes a SHARE, and only one that is already there. A shared folder is
# created in Control Panel, not with mkdir: a bare directory made here
# would not be a share at all, and File Station cannot show one - which
# for a NAS downloader means a user who cannot find their downloads would
# reasonably conclude that nothing downloaded. So an absent share is not
# a location we can choose, it is a candidate that does not exist.
add_candidate() {
    if [ -n "$1" ] && [ -d "$1" ]; then
        # NEWLINE separated, not space. A QNAP share is named in Control
        # Panel and "My Downloads" is a perfectly ordinary thing to call
        # one; with a space separator `for c in $candidates` split it
        # into "/share/My" and "Downloads/nzbfast" and tested neither of
        # the two against the share that actually exists.
        candidates="$candidates$1/nzbfast
"
    fi
    return 0
}

install_vol=""
[ -z "${SYS_QPKG_INSTALL_PATH:-}" ] || install_vol=$(dirname "$SYS_QPKG_INSTALL_PATH")
if [ -n "$install_vol" ]; then
    for share in "${SYS_DOWNLOAD_PATH:-}" "${SYS_PUBLIC_PATH:-}"; do
        [ -n "$share" ] || continue
        add_candidate "$install_vol/$(basename "$share")"
    done
    # Named shares, for a NAS where the definitions did not resolve.
    for name in Download Public Multimedia; do
        add_candidate "$install_vol/$name"
    done
fi
add_candidate "${SYS_DOWNLOAD_PATH:-}"
add_candidate "${SYS_PUBLIC_PATH:-}"

# Pass one: is one of them already an nzbfast install? A Container
# Station user's folder, or the leftovers of a package they removed and
# are now putting back. Reusing it is what makes a reinstall find the
# settings that were there before, so it beats every preference below.
DATA=""
while IFS= read -r c; do
    [ -n "$c" ] || continue
    for marker in config/config.json config/settings.json config/apikey; do
        if [ -f "$c/$marker" ]; then
            DATA="$c"
            say "found an existing nzbfast folder - reusing it: $DATA"
            break
        fi
    done
    [ -z "$DATA" ] || break
done <<EOF
$candidates
EOF

# Pass two: first candidate we can actually write to. A volume can be
# full, read only, or in the middle of a rebuild, and finding that out
# now beats installing cleanly and failing every job afterwards with the
# reason in a log the App Center does not show.
#
# Create, rename, then delete: this runs inside somebody's download
# share, so it cleans up after itself on every path.
writable() {
    _p="$1/.nzbfast-write-test.$$"
    mkdir -p "$1" 2>/dev/null || return 1
    ( umask 077; : > "$_p" ) 2>/dev/null || { rm -f "$_p" 2>/dev/null; return 1; }
    mv "$_p" "$_p.2" 2>/dev/null || { rm -f "$_p" 2>/dev/null; return 1; }
    rm -f "$_p.2" 2>/dev/null
    [ ! -e "$_p.2" ] || return 1
    return 0
}
if [ -z "$DATA" ]; then
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        if writable "$c"; then
            DATA="$c"
            break
        fi
        say "cannot write to $c - trying the next folder."
    done <<EOF
$candidates
EOF
fi

# Last resort: the package's own directory. It works everywhere, and it
# is the one location an uninstall takes with it, so say so plainly
# rather than letting somebody find out by losing it.
if [ -z "$DATA" ]; then
    DATA="$QPKG_DIR/data"
    writable "$DATA" || { say "cannot write to $DATA either - giving up."; exit 1; }
    say "no download or Public shared folder was usable, so downloads and"
    say "settings will live in $DATA."
    say "That folder is INSIDE the app, and removing the app in App Center"
    say "deletes it. Point Settings > Folders at a shared folder to move"
    say "them somewhere File Station can see and an uninstall cannot touch."
fi

# Only ever create. Never chown, never chmod, never recurse: the folder
# we just picked may be a live Container Station install, full of files
# owned by that container's user, and taking those away from a running
# install to fix a problem nobody had is not a repair.
for d in "$DATA/config" "$DATA/downloads" "$DATA/watch"; do
    mkdir -p "$d" 2>/dev/null || { say "cannot create $d"; exit 1; }
done

# Single-quote a value only if it contains anything the shell would
# act on, and escape any embedded single quote the POSIX way.
shq() {
    case "$1" in
        *[!A-Za-z0-9_/.:@%+-]*)
            printf "'"
            printf '%s' "$1" | sed "s/'/'\\\\''/g"
            printf "'"
            ;;
        *) printf '%s' "$1" ;;
    esac
}

umask 077
cat > "$ENVFILE" <<EOF
# nzbfast service settings. Edit and restart the app to change them.
# This file is written once, at install; an upgrade reads it and leaves
# it exactly as it is.
NZBFAST_DATA=$(shq "$DATA")
NZBFAST_PORT=$(shq "$PORT")
NZBFAST_CONFIG=$(shq "$DATA/config/config.json")
NZBFAST_OUT=$(shq "$DATA/downloads")
NZBFAST_WATCH=$(shq "$DATA/watch")
EOF

say "data folder: $DATA"
exit 0
