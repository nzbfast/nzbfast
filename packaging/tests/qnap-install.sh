#!/bin/sh
# Exercise the QNAP package's install-time decisions against fake NAS
# layouts.
#
# This is the whole reason those decisions live in nzbfast-setup.sh and
# package_routines rather than being spread through the package: where a
# user's downloads land, which binary gets kept, and what an upgrade is
# forbidden to touch are the parts that cannot be tried out before a NAS
# installs it - and nobody on this team owns a QNAP. Run:
#
#   packaging/tests/qnap-install.sh
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
QNAP="$SELF/../qnap"
[ -f "$QNAP/shared/nzbfast-setup.sh" ] || { echo "missing $QNAP/shared/nzbfast-setup.sh" >&2; exit 1; }

# make-qpkg.sh bakes the port in before shipping, so test what ships
# rather than the template - with the placeholder left in, every port
# comparison is against a literal "@@PORT@@".
SUBST="$(mktemp -d)"
T="$(mktemp -d)"
trap 'rm -rf "$SUBST" "$T"' EXIT
SETUP="$SUBST/nzbfast-setup.sh"
sed -e 's/@@PORT@@/6789/g' -e 's/@@VERSION@@/9.9.9/g' \
    "$QNAP/shared/nzbfast-setup.sh" > "$SETUP"
ROUTINES="$SUBST/package_routines"
sed -e 's/@@PORT@@/6789/g' -e 's/@@VERSION@@/9.9.9/g' \
    "$QNAP/package_routines" > "$ROUTINES"

pass=0; fail=0
check() {
    name="$1"; want="$2"; got="$3"
    if [ "$want" = "$got" ]; then
        pass=$((pass + 1)); echo "  ok   $name"
    else
        fail=$((fail + 1)); echo "  FAIL $name: want '$want' got '$got'" >&2
    fi
}
ok()  { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL $1" >&2; }

# A fake install: the package directory as qinstall would have left it
# after unpacking, on a volume with whatever shares the caller asked for.
#   make_nas <root> [share...]
make_nas() {
    _root="$1"; shift
    mkdir -p "$_root/volume/.qpkg/nzbfast/bin"
    : > "$_root/volume/.qpkg/nzbfast/bin/nzbfast-x86_64"
    : > "$_root/volume/.qpkg/nzbfast/bin/nzbfast-aarch64"
    : > "$_root/volume/.qpkg/nzbfast/nzbfast.sh"
    for _s in "$@"; do mkdir -p "$_root/volume/$_s"; done
}

# Run the setup script the way pkg_post_install does.
#   run_setup <root> [uname] [download-share-path]
run_setup() {
    _root="$1"
    SYS_QPKG_DIR="$_root/volume/.qpkg/nzbfast" \
    SYS_QPKG_INSTALL_PATH="$_root/volume/.qpkg" \
    SYS_DOWNLOAD_PATH="${3-$_root/volume/Download}" \
    SYS_PUBLIC_PATH="$_root/volume/Public" \
    QNAP_TEST_UNAME="${2:-x86_64}" \
        sh "$SETUP" >"$_root/out.log" 2>&1
}

envval() { grep "^$2=" "$1/volume/.qpkg/nzbfast/nzbfast.env" | cut -d= -f2-; }

echo "qnap install-time decisions"

# --- where the data goes ------------------------------------------------

# 1. The Download share is what QNAP owners already point everything at,
#    and it is visible in File Station. It wins.
r="$T/a"; make_nas "$r" Download Public
run_setup "$r"
check "download share chosen" "$r/volume/Download/nzbfast" "$(envval "$r" NZBFAST_DATA)"
check "  out under it" "$r/volume/Download/nzbfast/downloads" "$(envval "$r" NZBFAST_OUT)"
check "  config under it" "$r/volume/Download/nzbfast/config/config.json" "$(envval "$r" NZBFAST_CONFIG)"

# 2. Public is the fallback while a share still exists, because anything
#    inside the package directory dies with the package.
r="$T/b"; make_nas "$r" Public
run_setup "$r"
check "public share when no Download" "$r/volume/Public/nzbfast" "$(envval "$r" NZBFAST_DATA)"

# 3. No share at all: the package's own directory, which an uninstall
#    deletes - so it has to SAY so, not just do it.
r="$T/c"; make_nas "$r"
run_setup "$r"
check "no share falls back to the package dir" \
    "$r/volume/.qpkg/nzbfast/data" "$(envval "$r" NZBFAST_DATA)"
if grep -q "deletes it" "$r/out.log"; then
    ok "  and warns that removing the app deletes it"
else
    bad "  fallback did not warn that an uninstall deletes the data"
fi

# 4. All three folders are created, not just named.
r="$T/d"; make_nas "$r" Download
run_setup "$r"
for d in config downloads watch; do
    if [ -d "$r/volume/Download/nzbfast/$d" ]; then ok "creates $d/"
    else bad "did not create $d/"; fi
done

# 5. An existing install is REUSED, wherever it is. This is the migration
#    from Container Station (whose compose file maps exactly this shape)
#    and the reinstall-after-uninstall case: the settings are still on
#    disk, and an install that ignored them would read as a wipe.
r="$T/e"; make_nas "$r" Download Public
mkdir -p "$r/volume/Public/nzbfast/config"
echo '{"port":6789}' > "$r/volume/Public/nzbfast/config/settings.json"
run_setup "$r"
check "existing install beats the preferred share" \
    "$r/volume/Public/nzbfast" "$(envval "$r" NZBFAST_DATA)"
check "  and its settings.json is untouched" '{"port":6789}' \
    "$(cat "$r/volume/Public/nzbfast/config/settings.json")"

# 6. An unwritable candidate is stepped over rather than installed into.
#    A volume can be full, read only, or rebuilding, and finding out now
#    beats failing every job afterwards with the reason in a log the App
#    Center does not show. (Skipped as root, which can write anywhere -
#    CI runs this as a normal user.)
if [ "$(id -u)" != "0" ]; then
    r="$T/f"; make_nas "$r" Download Public
    chmod 555 "$r/volume/Download"
    run_setup "$r"
    check "unwritable share is stepped over" \
        "$r/volume/Public/nzbfast" "$(envval "$r" NZBFAST_DATA)"
    chmod 755 "$r/volume/Download"
else
    ok "unwritable share is stepped over (skipped: running as root)"
fi

# --- upgrades -----------------------------------------------------------

# 7. THE ONE THAT MATTERS. An upgrade re-runs all of this, and it must
#    not move anybody's data or touch a single setting. QDK's own upgrade
#    path only deletes files the PREVIOUS package shipped and this one
#    does not, so the way to keep settings safe is to make sure the
#    package never ships anything into the data folder and never rewrites
#    a choice already made.
r="$T/g"; make_nas "$r" Download
run_setup "$r"                             # first install
DATA="$(envval "$r" NZBFAST_DATA)"
printf '{"servers":"secret"}\n' > "$DATA/config/settings.json"
printf 'KEY\n' > "$DATA/config/apikey"
mkdir -p "$DATA/downloads/a-finished-job"
cp "$r/volume/.qpkg/nzbfast/nzbfast.env" "$SUBST/env.before"
# A new payload arrives: both binaries back, symlink gone.
: > "$r/volume/.qpkg/nzbfast/bin/nzbfast-aarch64"
rm -f "$r/volume/.qpkg/nzbfast/bin/nzbfast"
run_setup "$r"                             # upgrade
check "upgrade keeps the data folder" "$DATA" "$(envval "$r" NZBFAST_DATA)"
check "upgrade keeps settings.json byte for byte" '{"servers":"secret"}' \
    "$(cat "$DATA/config/settings.json")"
check "upgrade keeps the api key" "KEY" "$(cat "$DATA/config/apikey")"
if [ -d "$DATA/downloads/a-finished-job" ]; then ok "upgrade keeps downloads"
else bad "upgrade removed downloads"; fi
if cmp -s "$SUBST/env.before" "$r/volume/.qpkg/nzbfast/nzbfast.env"; then
    ok "upgrade leaves nzbfast.env alone"
else
    bad "upgrade rewrote nzbfast.env"
fi
check "upgrade relinks the binary" "nzbfast-x86_64" \
    "$(readlink "$r/volume/.qpkg/nzbfast/bin/nzbfast")"

# 7b. The env file is the source of truth even when it names somewhere
#     the chooser would never have picked - a user who edited it, or a
#     share that has since been renamed. Re-deriving the path is how an
#     upgrade quietly starts a fresh install next to somebody's real one.
r="$T/g2"; make_nas "$r" Download
run_setup "$r"
CUSTOM="$r/volume/somewhere-else/nzbfast"
mkdir -p "$CUSTOM/config"
printf 'MOVED\n' > "$CUSTOM/config/settings.json"
sed "s|^NZBFAST_DATA=.*|NZBFAST_DATA=$CUSTOM|" \
    "$r/volume/.qpkg/nzbfast/nzbfast.env" > "$SUBST/env.custom"
cp "$SUBST/env.custom" "$r/volume/.qpkg/nzbfast/nzbfast.env"
run_setup "$r"
check "upgrade honours a hand-edited data folder" "$CUSTOM" \
    "$(envval "$r" NZBFAST_DATA)"
check "  and its settings survive" "MOVED" "$(cat "$CUSTOM/config/settings.json")"

# 8. An upgrade that finds an env file naming a folder that has since
#    been deleted must put it back, not silently start with no folders.
r="$T/h"; make_nas "$r" Download
run_setup "$r"
DATA="$(envval "$r" NZBFAST_DATA)"
rm -rf "$DATA"
run_setup "$r"
if [ -d "$DATA/downloads" ] && [ -d "$DATA/config" ]; then
    ok "a deleted data folder is recreated in place"
else
    bad "a deleted data folder was not recreated"
fi

# 9. Nothing the package SHIPS may land in the data folder. QDK's
#    remove_obsolete_files deletes, on upgrade, every file the previous
#    package shipped that the new one does not - so a settings file
#    shipped once and dropped later would be deleted out from under the
#    user. The rule is structural: the payload contains no config at all.
if find "$QNAP/shared" -name '*.json' -o -name 'settings*' -o -name 'config*' \
        | grep -q .; then
    bad "the package payload ships a config file - see QDK's remove_obsolete_files"
else
    ok "the payload ships no config file for an upgrade to delete"
fi

# 10. And QPKG_CONFIG must stay unset, for the same reason from the other
#     direction: qinstall compares each listed file against the copy
#     SHIPPED IN THE PACKAGE, and for a file that is in no package it
#     renames the user's live one to .qdkorig on the first upgrade.
if grep -q '^QPKG_CONFIG=' "$QNAP/qpkg.cfg"; then
    bad "qpkg.cfg sets QPKG_CONFIG - that RENAMES settings.json on upgrade"
else
    ok "qpkg.cfg leaves QPKG_CONFIG unset"
fi

# --- architecture -------------------------------------------------------

# 11. One package carries both binaries; keep one, delete the other.
r="$T/i"; make_nas "$r" Download
run_setup "$r" x86_64
check "x86_64 links the x86_64 binary" "nzbfast-x86_64" \
    "$(readlink "$r/volume/.qpkg/nzbfast/bin/nzbfast")"
if [ -e "$r/volume/.qpkg/nzbfast/bin/nzbfast-aarch64" ]; then
    bad "unused aarch64 binary left on disk"
else
    ok "unused binary removed"
fi

r="$T/j"; make_nas "$r" Download
run_setup "$r" aarch64
check "aarch64 links the aarch64 binary" "nzbfast-aarch64" \
    "$(readlink "$r/volume/.qpkg/nzbfast/bin/nzbfast")"

# 12. And a model we ship no binary for must fail, not install.
r="$T/k"; make_nas "$r" Download
if run_setup "$r" armv7l; then
    bad "armv7l setup was allowed to succeed"
else
    ok "armv7l setup refuses"
fi

# --- the pre-unpack gate (package_routines) -----------------------------

# The real refusal happens before anything is written to disk. Source the
# routines with stand-ins for the two things qinstall would provide.
routines_case() {
    # $1 = uname, $2 = /proc/net fixture dir, $3 = qpkg dir (may not exist)
    (
        set +e
        err_log() { echo "ERR: $1"; exit 1; }
        QPKG_NAME=nzbfast
        SYS_QPKG_DIR="$3"
        SYS_QPKG_CONFIG_FILE="$T/qpkg.conf"
        CMD_GETCFG=false
        . "$ROUTINES"
        QNAP_TEST_UNAME="$1" QNAP_TEST_PROCNET="$2" pkg_check_requirement
        echo OK
    ) 2>&1
}

# A /proc/net/tcp with one LISTEN on 6789 (0x1A85), and one with an
# ESTABLISHED connection to it instead - a browser tab on somebody's
# dashboard is not a reason to refuse an install.
mkdir -p "$T/net-listen" "$T/net-conn" "$T/net-empty"
printf '  sl  local_address rem_address   st\n' > "$T/net-listen/tcp"
printf '   0: 00000000:1A85 00000000:0000 0A\n' >> "$T/net-listen/tcp"
printf '  sl  local_address rem_address   st\n' > "$T/net-conn/tcp"
printf '   0: 0100007F:C350 0100007F:1A85 01\n' >> "$T/net-conn/tcp"
printf '  sl  local_address rem_address   st\n' > "$T/net-empty/tcp"

case "$(routines_case x86_64 "$T/net-empty" "$T/nope")" in
    *OK*) ok "clean NAS passes the pre-unpack gate" ;;
    *)    bad "clean NAS was refused: $(routines_case x86_64 "$T/net-empty" "$T/nope")" ;;
esac
case "$(routines_case armv7l "$T/net-empty" "$T/nope")" in
    *"64-bit builds only"*) ok "32-bit ARM is refused before unpacking" ;;
    *) bad "32-bit ARM was not refused with an explanation" ;;
esac
case "$(routines_case x86_64 "$T/net-listen" "$T/nope")" in
    *"already listening"*) ok "a port already served refuses the install" ;;
    *) bad "an occupied port did not refuse the install" ;;
esac
case "$(routines_case x86_64 "$T/net-conn" "$T/nope")" in
    *OK*) ok "a CONNECTION to the port is not an occupied port" ;;
    *) bad "an established connection was mistaken for a listener" ;;
esac
# An upgrade reaches the gate with our own daemon still listening -
# qinstall does not stop the service until after this runs - so the port
# check has to apply to first installs only.
mkdir -p "$T/installed"
case "$(routines_case x86_64 "$T/net-listen" "$T/installed")" in
    *OK*) ok "an upgrade is not refused by its own running daemon" ;;
    *) bad "an upgrade was refused because it was already running" ;;
esac

# --- the hook that runs the setup script --------------------------------

# qinstall.sh SETS the SYS_* variables but never EXPORTS them, and the
# setup script is a child process, so the hook has to hand each one over.
# Every run_setup case above passes them in the environment itself, which
# is how a hook that handed over nothing shipped: setup died on its first
# line on every NAS (issue #134). So run the real hook, with the variables
# as plain unexported shell variables. `unset` first, because assigning to
# a name this shell inherited as exported would leave it exported.
#
# Each share path is checked on its own, outside the install volume, so a
# hook that drops just that one cannot pass on the volume-relative
# fallback.
#   hook_case <root> <download-path> <public-path>
hook_case() {
    (
        unset SYS_QPKG_DIR SYS_QPKG_INSTALL_PATH SYS_DOWNLOAD_PATH SYS_PUBLIC_PATH
        err_log() { echo "ERR: $1"; exit 1; }
        SYS_QPKG_DIR="$1/volume/.qpkg/nzbfast"
        SYS_QPKG_INSTALL_PATH="$1/volume/.qpkg"
        SYS_DOWNLOAD_PATH="$2"
        SYS_PUBLIC_PATH="$3"
        cp "$SETUP" "$SYS_QPKG_DIR/nzbfast-setup.sh"
        QNAP_TEST_UNAME=x86_64
        export QNAP_TEST_UNAME
        . "$ROUTINES"
        pkg_post_install
    ) >"$1/hook.log" 2>&1
}
#   hook_check <name> <root> <expected data folder> <download> <public>
hook_check() {
    if hook_case "$2" "$4" "$5"; then
        check "$1" "$3" "$(envval "$2" NZBFAST_DATA)"
    else
        bad "$1: $(cat "$2/hook.log")"
    fi
}
r="$T/hook-vol"; make_nas "$r" Download
hook_check "the hook passes the install volume" "$r" \
    "$r/volume/Download/nzbfast" "" ""
r="$T/hook-dl"; make_nas "$r"; mkdir -p "$r/other/My Downloads"
hook_check "the hook passes the download share" "$r" \
    "'$r/other/My Downloads/nzbfast'" "$r/other/My Downloads" ""
r="$T/hook-pub"; make_nas "$r"; mkdir -p "$r/other/Shared"
hook_check "the hook passes the public share" "$r" \
    "$r/other/Shared/nzbfast" "" "$r/other/Shared"
# And a setup that really fails still aborts the install.
r="$T/hook-fail"; make_nas "$r" Download
rm -f "$r/volume/.qpkg/nzbfast/bin/nzbfast-x86_64"
if hook_case "$r" "" ""; then
    bad "the hook swallowed a failed setup"
elif grep -q "bin/nzbfast-x86_64 - the build is broken" "$r/hook.log"; then
    ok "the hook aborts when setup fails"
else
    bad "the hook failed for the wrong reason: $(cat "$r/hook.log")"
fi

# --- starting the service ----------------------------------------------

# QTS has no `nohup` (seen on a TS-X53B, QTS 5.2.11), so a start that
# needs it dies with "command not found" after an install that looked
# fine. Run the real service script with a PATH holding only commands
# that were confirmed on that NAS, and check the daemon comes up, ignores
# SIGHUP (nohup's job) and stops. Linux only: the script reads /proc.
if [ -r /proc/self/cmdline ]; then
    svc="$T/svc"; r="$svc/nas"; make_nas "$r" Download
    root="$r/volume/.qpkg/nzbfast"
    mkdir -p "$svc/path"
    for c in cat grep kill mkdir rm sh sleep tail tr; do
        p=$(command -v "$c") || continue
        case "$p" in /*) ln -sf "$p" "$svc/path/$c" ;; esac
    done
    printf '#!/bin/sh\ncase "$2" in Install_Path) echo "%s" ;; Enable) echo TRUE ;; esac\n' \
        "$root" > "$svc/getcfg"
    chmod 755 "$svc/getcfg"
    printf '#!/bin/sh\nwhile :; do sleep 1; done\n' > "$root/bin/nzbfast"
    chmod 755 "$root/bin/nzbfast"
    printf 'NZBFAST_DATA=%s\nNZBFAST_CONFIG=%s\nNZBFAST_OUT=%s\nNZBFAST_WATCH=%s\n' \
        "$svc/data" "$svc/data/config/config.json" "$svc/data/downloads" \
        "$svc/data/watch" > "$root/nzbfast.env"
    sed -e 's/@@PORT@@/6789/g' -e "s#/sbin/getcfg#$svc/getcfg#" \
        -e "s#^PIDFILE=.*#PIDFILE=$svc/pid#" \
        "$QNAP/shared/nzbfast.sh" > "$svc/nzbfast.sh"
    service() { PATH="$svc/path" "$svc/path/sh" "$svc/nzbfast.sh" "$1" >"$svc/out" 2>&1; }
    if service start; then
        ok "the service starts with only the commands QTS has"
        daemon=$(cat "$svc/pid")
        kill -HUP "$daemon"; sleep 1
        if service status; then ok "  and survives a hangup"
        else bad "  a hangup killed the service"; fi
        service stop || true
        if service status; then
            kill -9 "$daemon"; bad "  stop left the daemon running"
        else
            ok "  and stops"
        fi
    else
        bad "the service did not start: $(cat "$svc/out" "$root/nzbfast.log" 2>/dev/null)"
    fi
else
    echo "  skip the service start cases (no /proc here)"
fi

# --- the package format -------------------------------------------------

# unpack-qpkg.sh is the only thing that can open a .qpkg where QDK is not
# installed, which is both the release leak scanner and the check that a
# freshly built package contains what it should. It knows the format by
# hand, so the format gets a test: build a package with the same three
# parts qbuild concatenates - installer script, control tar, gzipped data
# tar - and the 100-byte QNAPQPKG trailer that comes after them, then
# take it apart again. The trailer is the interesting part. It is why
# reading the data archive to end-of-file does not work, and why the dd
# count in the installer's own header is not the answer either: that
# count is rounded up to a kibibyte, so it reaches past the archive and
# into the trailer on any package whose payload is not an exact multiple.
FAKE="$T/fake"
mkdir -p "$FAKE/data/bin" "$FAKE/ctrl"
echo "not really a binary" > "$FAKE/data/bin/nzbfast-x86_64"
echo "not really a service" > "$FAKE/data/nzbfast.sh"
echo 'QPKG_VER="9.9.9"' > "$FAKE/ctrl/qpkg.cfg"
( cd "$FAKE/data" && tar czf ../data.tar.gz . )
( cd "$FAKE/ctrl" && tar czf ../control.tar.gz . )
( cd "$FAKE" && tar cf control.tar control.tar.gz )
python3 - "$FAKE" <<'PY'
import os, sys
d = sys.argv[1]
dl = os.path.getsize(d + "/data.tar.gz")
cl = os.path.getsize(d + "/control.tar")
kib = (dl + 1023) // 1024
# The shape qbuild emits, down to the two lines the lengths are read from.
tpl = ("#!/bin/sh\nfind_base(){ :; }\nfind_base\n_EXTRACT_DIR=/tmp/x\n"
       "script_len=%d\n"
       "/bin/dd if=\"${0}\" bs=$script_len skip=1 | /bin/tar -xO | /bin/tar -xzv -C $_EXTRACT_DIR || exit 1\n"
       "offset=$(/usr/bin/expr $script_len + %d)\n"
       "/bin/dd if=\"${0}\" bs=$offset skip=1 | /bin/cat | /bin/dd bs=1024 count=%d of=$_EXTRACT_DIR/data.tar.gz || exit 1\n"
       "exit 1\n")
# qbuild patches its own length in afterwards; settle on the fixpoint.
n = len(tpl % (0, cl, kib))
for _ in range(4):
    if len(tpl % (n, cl, kib)) == n:
        break
    n = len(tpl % (n, cl, kib))
script = (tpl % (n, cl, kib)).encode()
assert len(script) == n
# [MODEL(10)|RESERVED(40)|FW_VERSION(10)|NAME(20)|VERSION(10)|FLAG(10)]
trailer = b" " * 60 + b"nzbfast".ljust(20) + b"9.9.9".ljust(10) + b"QNAPQPKG  "
assert len(trailer) == 100
with open(d + "/fake.qpkg", "wb") as out:
    out.write(script)
    out.write(open(d + "/control.tar", "rb").read())
    out.write(open(d + "/data.tar.gz", "rb").read())
    out.write(trailer)
PY
if "$QNAP/unpack-qpkg.sh" "$FAKE/fake.qpkg" "$FAKE/out" >/dev/null 2>&1; then
    ok "unpack-qpkg.sh opens a package built the way qbuild builds one"
else
    bad "unpack-qpkg.sh could not open a synthetic package"
fi
for f in control/qpkg.cfg data/nzbfast.sh data/bin/nzbfast-x86_64; do
    if [ -f "$FAKE/out/$f" ]; then ok "  recovered $f"
    else bad "  did not recover $f"; fi
done
# And the trailer must not have been swept into the payload.
if [ -z "$(grep -rl QNAPQPKG "$FAKE/out" 2>/dev/null)" ]; then
    ok "  the trailer stayed out of the extracted files"
else
    bad "  the trailer was extracted as part of the payload"
fi
# A file that is not a QDK package has to be refused, not half-read.
head -c 4000 /dev/zero > "$FAKE/notapkg.qpkg"
if "$QNAP/unpack-qpkg.sh" "$FAKE/notapkg.qpkg" "$FAKE/out2" >/dev/null 2>&1; then
    bad "  a file with no QDK header was accepted"
else
    ok "  a file with no QDK header is refused"
fi

# --- share names with whitespace ----------------------------------------

# A QNAP share is named in Control Panel, and "My Downloads" is an
# ordinary thing to call one. Two separate defects met on that path: the
# candidate list was one space-separated scalar walked with `for c in
# $candidates`, so the share was split into fragments and neither
# fragment was the directory that exists; and the env file was written
# with bare values, so nzbfast.sh sourcing it ran the suffix after the
# space as a command. Check the end state the service actually sees:
# source the generated file in POSIX sh and compare byte for byte.
r="$T/ws"; make_nas "$r" "My Downloads"
run_setup "$r" x86_64 "$r/volume/My Downloads"
ENVF="$r/volume/.qpkg/nzbfast/nzbfast.env"
if [ -f "$ENVF" ]; then
    ok "setup completed with a share name containing a space"
    got=$(sh -c '. "$1" 2>/dev/null; printf "%s" "$NZBFAST_DATA"' _ "$ENVF")
    want="$r/volume/My Downloads/nzbfast"
    if [ "$got" = "$want" ]; then
        ok "  sourcing the env file yields the whitespace path intact"
    else
        bad "  sourced NZBFAST_DATA is '$got', wanted '$want'"
    fi
    goto=$(sh -c '. "$1" 2>/dev/null; printf "%s" "$NZBFAST_OUT"' _ "$ENVF")
    if [ "$goto" = "$want/downloads" ]; then
        ok "  and NZBFAST_OUT with it"
    else
        bad "  sourced NZBFAST_OUT is '$goto', wanted '$want/downloads'"
    fi
    # Sourcing must not have executed anything. A bare assignment with a
    # space would have tried to run "Downloads/nzbfast".
    if sh -c '. "$1"' _ "$ENVF" 2>&1 | grep -qi "not found\|No such file"; then
        bad "  sourcing the env file tried to run part of the path"
    else
        ok "  sourcing it runs no command"
    fi
    if [ -d "$want/config" ] && [ -d "$want/downloads" ]; then
        ok "  the folders were created under the real share"
    else
        bad "  the data folders were not created at $want"
    fi
else
    bad "setup produced no env file for a share name containing a space"
fi

# --- uninstall ----------------------------------------------------------

# QDK builds the uninstall script by expanding $PKG_PRE_REMOVE into a
# heredoc, so what is written there is shell source assembled by string
# substitution - and a quoting mistake in it is not discovered until
# somebody removes the package. Render it the way qinstall does and check
# it parses, and that the two expansions land on opposite sides: the
# package directory resolved at install time, the data folder left for
# the uninstall script to read out of nzbfast.env at removal time.
UNINST="$T/uninstall.sh"
(
    SYS_QPKG_DIR=/share/CACHEDEV1_DATA/.qpkg/nzbfast
    QPKG_NAME=nzbfast
    . "$ROUTINES"
    printf '#!/bin/sh\n%s\n' "$PKG_PRE_REMOVE" > "$UNINST"
)
if sh -n "$UNINST" 2>/dev/null; then ok "the uninstall fragment parses"
else bad "the uninstall fragment is not valid shell"; fi
if grep -q '/share/CACHEDEV1_DATA/.qpkg/nzbfast/nzbfast.env' "$UNINST"; then
    ok "  package directory is resolved at install time"
else
    bad "  package directory did not expand into the uninstall script"
fi
if grep -q '\$NZBFAST_DATA' "$UNINST"; then
    ok "  data folder is read at removal time, not baked in"
else
    bad "  \$NZBFAST_DATA was expanded too early"
fi
if grep -qi 'rm ' "$UNINST"; then
    bad "  the uninstall fragment deletes something - it must not"
else
    ok "  and it deletes nothing"
fi

# The message has to be decided by the recorded path, because it is not
# always true that the data survives. nzbfast-setup.sh falls back to
# $QPKG_DIR/data when no shared folder is usable, and QDK removes that
# directory - so on exactly those installs the old unconditional
# "untouched" line told the user the opposite of what had happened.
# Run the rendered fragment against both layouts and read what it says.
run_uninst() {   # $1 = NZBFAST_DATA to record in the env file
    _d="$T/removal"; rm -rf "$_d"
    mkdir -p "$_d/share/CACHEDEV1_DATA/.qpkg/nzbfast"
    echo "NZBFAST_DATA=$1" > "$_d/share/CACHEDEV1_DATA/.qpkg/nzbfast/nzbfast.env"
    (
        SYS_QPKG_DIR="$_d/share/CACHEDEV1_DATA/.qpkg/nzbfast"
        QPKG_NAME=nzbfast
        . "$ROUTINES"
        printf '#!/bin/sh\n%s\n' "$PKG_PRE_REMOVE" > "$_d/u.sh"
    )
    sh "$_d/u.sh" 2>/dev/null
}
OUTSIDE=$(run_uninst "/share/CACHEDEV1_DATA/Download/nzbfast")
case "$OUTSIDE" in
    *"left in /share/CACHEDEV1_DATA/Download/nzbfast"*)
        ok "  data outside the package: says it is left alone" ;;
    *) bad "  data outside the package: wrong message: $OUTSIDE" ;;
esac
case "$OUTSIDE" in
    *WARNING*|*DELET*) bad "  data outside the package: warned about deletion it is not doing" ;;
    *) ok "  data outside the package: no false alarm" ;;
esac
INSIDE=$(run_uninst "$T/removal/share/CACHEDEV1_DATA/.qpkg/nzbfast/data")
case "$INSIDE" in
    *"being DELETED"*) ok "  fallback data inside the package: says it is being deleted" ;;
    *) bad "  fallback data inside the package: did not warn: $INSIDE" ;;
esac
case "$INSIDE" in
    *"left in"*|*untouched*)
        bad "  fallback data inside the package: still claims it survives" ;;
    *) ok "  fallback data inside the package: does not claim it survives" ;;
esac

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
