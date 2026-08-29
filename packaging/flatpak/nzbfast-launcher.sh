#!/usr/bin/env bash
# nzbfast Flatpak launcher - BETA
#
# nzbfast is a daemon with a web dashboard, not a windowed program, so
# there is nothing to put on screen. This script is what the desktop
# entry runs, and it gives the icon the behaviour a desktop user expects
# from clicking it: the dashboard opens in their browser.
#
# The shape is copied from SABnzbd's Flathub package rather than invented
# (org.sabnzbd.sabnzbd runs `SABnzbd.py --browser 1` from its .desktop
# file): one foreground process per launch, the browser opened once the
# listener is up, and no background service that outlives the session.
# nzbfast already has the flag for the second half - `serve --open` opens
# the dashboard when the port is listening, and is what the macOS and
# Windows double-click launchers use - so the only thing this adds is the
# second-launch case below.
#
# Clicking the icon twice must not try to bind the port twice. A daemon
# that is already listening is the common case (the first click left one
# running), and starting a second one would fail on the bind and show the
# user an error about a program that is working perfectly. So: if the
# port answers, just open the dashboard and exit.
set -eu

APP_ID=io.github.nzbfast.nzbfast

# Inside the sandbox XDG_CONFIG_HOME is already the app's own private
# directory (~/.var/app/$APP_ID/config on the host), so the data
# directory needs no filesystem permission at all and cannot collide with
# a tarball or .deb install of nzbfast on the same machine. The daemon
# derives the whole data directory from the config file's parent, which
# is why only NZBFAST_CONFIG is set rather than four separate paths.
CONF_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
DATA_DIR="$CONF_HOME/nzbfast"
CONFIG="$DATA_DIR/config.json"
mkdir -p "$DATA_DIR"

# The port to TALK to, which is not always the port to start on. A port
# changed in the dashboard is saved in settings.json and wins over the
# --port flag on every later start, so a launcher that only ever knew
# 6789 would probe a dead port, decide nothing was running, start a
# second daemon, and watch it fail the bind on the port the first one
# actually holds. The daemon records where it really landed in
# runtime.json beside its settings; that file is rewritten on every start
# and can be stale after a crash, which is why the port it names is
# probed rather than trusted.
#
# An explicitly set NZBFAST_PORT does NOT overrule that here, and the
# escape hatch below is why it does not have to: the recorded port is
# probed first for ATTACH, and only once that port turns out to hold a
# stranger is the requested one tried instead. Letting the environment
# win outright would put back the exact bug this file records - a saved
# port of 6790 with NZBFAST_PORT still naming 6789 would probe a dead
# port, decide nothing was running, and start a second daemon into a
# failed bind.
RUNTIME="$DATA_DIR/runtime.json"
PORT="${NZBFAST_PORT:-6789}"
SCHEME=http
# The port the user ASKED for, empty unless they set one. Kept apart
# from PORT because "unset" and "set to the default" are different
# instructions here: only an explicit request may re-aim the probe.
# Validated the same way the recorded port is, so a typo'd value cannot
# steer anything.
WANT=""
case "${NZBFAST_PORT:-}" in
    ''|*[!0-9]*) ;;
    *) [ "$NZBFAST_PORT" -ge 1 ] && [ "$NZBFAST_PORT" -le 65535 ] && WANT="$NZBFAST_PORT" ;;
esac
# The daemon also writes a per-start secret beside the port. It is what
# turns "something answered in our shape" into "this is the daemon that
# wrote this file" - see port_is_ours. A token proves nothing about a
# port it was not written about, so the port it came with is kept and
# checked against the port actually probed.
TOKEN=""
_rtport=""
if [ -r "$RUNTIME" ]; then
    _p=$(grep -o '"port":[0-9]*' "$RUNTIME" | head -1 | cut -d: -f2)
    case "$_p" in
        ''|*[!0-9]*) ;;                      # absent or not a number: keep the default
        *) PORT="$_p"; _rtport="$_p" ;;
    esac
    grep -q '"tls":true' "$RUNTIME" && SCHEME=https
    _t=$(grep -o '"token":"[0-9a-f]*"' "$RUNTIME" | head -1 | cut -d'"' -f4)
    case "$_t" in
        ''|*[!0-9a-f]*) ;;                   # absent, empty or not hex: no proof to ask for
        *) TOKEN="$_t" ;;
    esac
fi
[ "$_rtport" = "$PORT" ] || TOKEN=""

# The user's real Downloads folder, which on a localised desktop is not
# called "Downloads". xdg-user-dir cannot answer this inside the sandbox:
# it reads $XDG_CONFIG_HOME/user-dirs.dirs, and that variable now points
# at the app's private config directory, where there is no such file. The
# host's copy is still readable through the home permission, so read it
# from its real path and fall back to the English default.
download_dir() {
    _d=""
    if [ -r "$HOME/.config/user-dirs.dirs" ]; then
        _d=$(
            XDG_DOWNLOAD_DIR=""
            # shellcheck disable=SC1091  # the host's user-dirs file
            . "$HOME/.config/user-dirs.dirs" 2>/dev/null || true
            eval printf '%s' "\"${XDG_DOWNLOAD_DIR:-}\"" 2>/dev/null || true
        )
    fi
    [ -n "$_d" ] || _d="$HOME/Downloads"
    printf '%s' "$_d"
}

DL=$(download_dir)
OUT="${NZBFAST_OUT:-$DL/nzbfast}"
WATCH="${NZBFAST_WATCH:-$DL/nzbfast/watch}"

# Is a daemon already listening? The runtime carries neither curl nor ss,
# so ask the shell for a TCP connect - which is why this script is bash
# and not sh: /dev/tcp is a bash feature and dash returns "no such file"
# for it, which would read here as "the port is free" and send every
# second click into a doomed bind.
port_is_up() {
    (exec 3<>/dev/tcp/127.0.0.1/"$PORT") >/dev/null 2>&1
}

# ...and is it OURS? A listener is not an identity. Anything at all on
# 6789 used to be treated as nzbfast, which meant a different local
# service on that port stopped nzbfast from ever starting AND got opened
# in the user's browser by us. INSTALLER-SPEC.md is explicit: attach
# only when the port answers mode=version and reports nzbfast.
#
# AND ANSWERING IN OUR SHAPE IS NOT IDENTITY EITHER. mode=version is
# answered without an API key by design (the container healthcheck
# depends on it), so any local process at all can print the word
# nzbfast into a reply and be attached to - and attaching means opening
# it in the user's browser under our name. The daemon's own note on
# write_runtime_file says this in as many words. So the probe carries a
# CHALLENGE: it sends `mode=version&hs=<nonce>` and the daemon answers
# `hs_proof = sha256(token:nonce)`, where the token is the per-start
# secret it wrote into runtime.json - 0600, inside this app's own
# private config directory. The token never crosses the wire in either
# direction, so sending the challenge to an impostor teaches it
# nothing, and only a process that can read our runtime.json can
# produce the answer. Same wire format and same reasoning as the
# Windows tray's probe (crates/nzbtray/src/probe_body.rs,
# `proof_matches`), which arrived at it from the other side: an
# attached engine dying and something else taking the port.
#
# Same /dev/tcp as port_is_up, because the runtime has neither curl nor
# wget; read with a timeout so a socket that accepts and says nothing
# cannot hang the launcher.

# sha256 of stdin, hex, bare. sha256sum is coreutils, which is what the
# Flatpak runtime has. The shasum fallback is not for the sandbox: it is
# so packaging/tests/flatpak-launcher.sh can drive this script on the
# dev Mac, where the alternative is a gate that cannot exercise the one
# thing it exists for.
sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | cut -d' ' -f1
    else
        return 1
    fi
}

# A fresh challenge per launch, so a proof captured off an earlier one
# is worth nothing. Minted from /dev/urandom rather than $RANDOM, which
# is 15 bits seeded from pid and time and so is guessable by whatever
# else is on this machine. Empty when there is no sha256 to hand, which
# is also the case where no proof could be checked anyway.
NONCE=""
mint_nonce() {
    NONCE=$(head -c 32 /dev/urandom 2>/dev/null | sha256_hex 2>/dev/null | cut -c1-32) || NONCE=""
    case "$NONCE" in
        *[!0-9a-f]*) NONCE="" ;;
    esac
    [ "${#NONCE}" -eq 32 ] || NONCE=""
}

# The answer the daemon that wrote runtime.json would give.
challenge_proof() {
    printf '%s:%s' "$TOKEN" "$NONCE" | sha256_hex
}

# Ask the port in plaintext and keep whatever came back, headers and
# all. Sets PROBE_BODY rather than printing it so the caller stays in
# this shell and can correct SCHEME.
#
# THE BRACES AROUND EVERY BARE `exec` HERE ARE LOAD-BEARING. `exec` with
# no command applies its redirections to the SHELL, permanently, so the
# obvious `exec 3<>/dev/tcp/... 2>/dev/null` sends this script's stderr
# to /dev/null for the rest of its life the moment the connect succeeds.
# That is not theoretical: it is what the version before this one did,
# and it meant the foreign-listener refusal below - the whole of what the
# user is told about why nothing opened - was printed into /dev/null.
# Exit 1 and not one word on the terminal. A brace group scopes the
# redirection to the group and still leaves fd 3 open in this shell,
# which is the one thing a subshell could not do.
probe_close() { { exec 3<&- 3>&-; } 2>/dev/null; }

PROBE_BODY=""
plaintext_probe() {
    local line="" hs=""
    PROBE_BODY=""
    [ -n "$NONCE" ] && hs="&hs=$NONCE"
    { exec 3<>/dev/tcp/127.0.0.1/"$PORT"; } 2>/dev/null || return 1
    printf 'GET /api?mode=version&output=json%s HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' "$hs" >&3 2>/dev/null || {
        probe_close; return 1; }
    # `|| [ -n "$line" ]` is load-bearing: the body's last line carries no
    # trailing newline, and a plain `read` returns false on that EOF -
    # dropping the one line the JSON is on. Without it this probe says
    # "not nzbfast" about a real daemon, which would break attach for
    # every user instead of only the ones with a port conflict.
    # `2>/dev/null` on the READ, not on a bare `exec` - see probe_close.
    # A listener that closes abruptly (which is what a stranger on the
    # port does) makes bash print "read error: Connection reset by peer",
    # and that is a HANDLED condition: it means the same thing to us as a
    # clean EOF. Before the redirection bug above was fixed it was hidden
    # by accident, because the bare exec had already silenced the whole
    # script; with stderr working again it would print raw bash
    # diagnostics ahead of our own refusal message and make a handled
    # case look like a crash.
    while IFS= read -r -t 3 line <&3 2>/dev/null || [ -n "$line" ]; do
        PROBE_BODY="$PROBE_BODY$line"
        line=""
    done
    probe_close
}

# §129 2a: THE TLS ARM IS WEAKER THAN THE PLAINTEXT ONE, AND SAYING SO
# HERE IS THE POINT OF THIS BLOCK.
#
# A plaintext probe cannot get a sensible answer out of a native-TLS
# daemon: the listener accepts the TCP connection and then answers a
# plaintext HTTP request with a TLS alert or nothing at all. There is no
# openssl, curl or wget in this runtime to speak TLS instead, and no pid
# to fall back on either - the sandbox gets a fresh pid namespace on
# every `flatpak run`, so a second launch's /proc cannot see the first
# launch's daemon at all. So under TLS the challenge above cannot be
# sent, and what is left is a NEGATIVE test:
#
#   * anything that answers this probe with readable text is NOT our TLS
#     daemon, whatever it says about itself, and is refused - unless it
#     proves the token, which means runtime.json's scheme is stale
#     rather than the listener being a stranger;
#   * silence, or bytes that are not text, is consistent with our TLS
#     daemon and is accepted.
#
# What that CANNOT tell apart is our TLS daemon from some other TLS
# service on the port, or from a socket that accepts and says nothing.
# Both are accepted. That is strictly weaker than the http case, where
# a listener must prove it holds the secret from our own private config
# directory, and it is the price of having no TLS client in the
# sandbox. It is not silent: it is written here, and the earlier version
# of this arm - which accepted ANY listener the moment runtime.json said
# tls, including a plaintext one - is what this replaced.
port_is_ours() {
    local want got
    [ -n "$TOKEN" ] && mint_nonce
    plaintext_probe || PROBE_BODY=""

    case "$PROBE_BODY" in
        # Nothing came back, or what came back is not text. See above.
        ""|*[![:print:][:space:]]*)
            [ "$SCHEME" = https ] && return 0
            return 1
            ;;
    esac

    # Text came back, so something here speaks plaintext - and plaintext
    # is therefore what we would be opening, whatever runtime.json says
    # the scheme is. It has to prove itself first.
    if [ -n "$TOKEN" ] && [ -n "$NONCE" ]; then
        want=$(challenge_proof) || want=""
        # The daemon writes this compact (httputil.rs, json_resp is
        # serde_json's Value::to_string), so the space is not there today.
        # Tolerated anyway because the failure mode of an extraction that
        # stops matching is not a wrong answer, it is a permanent refusal
        # to attach - the lockout this whole block exists to end.
        got=$(printf '%s' "$PROBE_BODY" | grep -o '"hs_proof": *"[0-9a-f]*"' | head -1 | cut -d'"' -f4)
        if [ -n "$want" ] && [ "$want" = "$got" ]; then
            # Proven ours. If runtime.json said tls, it is stale - a
            # daemon that stopped serving TLS and could not rewrite the
            # file. Open what actually answered, not what the file
            # remembers.
            SCHEME=http
            return 0
        fi
        return 1
    fi

    # No token to hold it to: runtime.json is missing, names another
    # port, or was written by a daemon whose key mint failed. The reply
    # shape is all there is, which is the pre-handshake daemon the
    # tray's probe calls "adopted" - permissive on purpose, because
    # refusing would break attaching to a release older than the
    # handshake.
    case "$PROBE_BODY" in
        *'"nzbfast"'*) SCHEME=http; return 0 ;;
    esac
    return 1
}

# The two halves of the foreign-listener refusal, shared because it is
# printed from two places and a user who hits the second one has already
# read the first.
#
# The suggested port is derived rather than fixed: the old message always
# said 6790, which is useless advice to somebody who is already on 6790,
# and it named `com.nzbfast.nzbfast`, which is not this application - the
# id is io.github.nzbfast.nzbfast, so the one command the user was handed
# could not run at all.
refuse_head() {
    echo "nzbfast: something else is already listening on port $1," >&2
    echo "  and it is not nzbfast, so there is nothing here to attach to." >&2
}
# PORT is only known to be a number when it came from runtime.json or
# passed the NZBFAST_PORT check above; a hand-set NZBFAST_PORT=6789x
# reaches here as itself, and `$((PORT + 1))` on that is a bash syntax
# error, which under `set -e` would kill the script in the middle of
# explaining itself.
refuse_tail() {
    local _sug
    case "$PORT" in
        ''|*[!0-9]*) _sug=6790 ;;
        *) _sug=$((PORT + 1)); [ "$_sug" -le 65535 ] || _sug=6790 ;;
    esac
    echo "  Ask for a free port and start again:" >&2
    echo "    flatpak run --env=NZBFAST_PORT=$_sug $APP_ID" >&2
    echo "  (a port saved in settings.json beats that on later runs)." >&2
}

open_dashboard() {
    # xdg-open in the runtime is a shim onto the OpenURI portal, so this
    # reaches the user's real browser on the host without the sandbox
    # holding any display socket or bus name of its own.
    xdg-open "$SCHEME://127.0.0.1:$PORT/" >/dev/null 2>&1 || true
}

# A .nzb passed by the file manager ("Open with nzbfast"). There is no
# CLI verb that hands a file to a running daemon, so it goes through the
# watch folder, which is the mechanism the daemon already polls - and it
# works whether or not the daemon is up yet.
#
# THREE THINGS THIS USED TO GET WRONG, all of them silent.
#
# `*.nzb.gz` was accepted and copied through unchanged, and the watch
# folder only ever consumes files whose extension is `nzb` - so a
# gzipped NZB was copied into a folder that would never look at it and
# the download simply never started. Nothing in the product
# decompresses one, so the honest fix is to stop claiming to take it.
#
# `cp ... || true` swallowed every failure, so a full or unwritable
# watch directory answered a double-click with nothing at all.
#
# And a bare `cp` into `$WATCH/` OVERWRITES: two opens of different
# files that happen to share a basename - `nzb` from two indexers is
# the everyday case - meant the second one destroyed the first, which
# may already have been picked up. The " (2)" convention is the
# daemon's own, from `watchfolder.rs`'s quarantine path, and it matters
# that it is that one: the filename becomes the job name.
for arg in "$@"; do
    case "$arg" in
        *.nzb)
            mkdir -p "$WATCH" || {
                echo "nzbfast: cannot create the watch folder at $WATCH" >&2
                exit 1
            }
            base=${arg##*/}
            dest="$WATCH/$base"
            n=1
            while [ -e "$dest" ] && [ "$n" -lt 1000 ]; do
                n=$((n + 1))
                dest="$WATCH/${base%.nzb} ($n).nzb"
            done
            cp -f -- "$arg" "$dest" || {
                echo "nzbfast: could not copy $arg into $WATCH" >&2
                exit 1
            }
            ;;
        *.nzb.gz)
            echo "nzbfast: $arg is gzipped - decompress it first" >&2
            echo "  (gunzip \"$arg\") and open the .nzb." >&2
            exit 1
            ;;
    esac
done

if port_is_up; then
    if port_is_ours; then
        open_dashboard
        exit 0
    fi
    # Somebody else owns the port. Do NOT open it in the browser: that
    # would hand the user a stranger's service under our name. Do not
    # kill it either - "never kill a daemon you didn't spawn".
    #
    # THE ESCAPE HATCH, and the reason this is not simply a refusal. The
    # port just refused came from runtime.json in the case that matters,
    # and runtime.json is rewritten on every start - so a user whose last
    # daemon ran on the now-squatted port gets that port named again on
    # every launch. Refusing here and telling them to set NZBFAST_PORT
    # was advice that could not work: the block at the top would read
    # runtime.json over the top of it, probe the squatted port again, and
    # reprint the same message forever, with the only way out - deleting
    # runtime.json - never mentioned. Measured 27 Aug 2026.
    #
    # So a port the user explicitly ASKED for is tried now. Attaching is
    # still runtime.json's job and has already had its turn; what is left
    # is where to START, and the start below has always used
    # NZBFAST_PORT. This makes the probe agree with it instead of
    # contradicting it.
    #
    # The token and the scheme do NOT carry over. Both were written about
    # the recorded port, and a proof proves nothing about a port it was
    # not written about - the same rule as `[ "$_rtport" = "$PORT" ]`
    # above. Under http a listener has to look like us to be attached to,
    # which is the stronger of the two arms in port_is_ours.
    if [ -n "$WANT" ] && [ "$WANT" != "$PORT" ]; then
        _held="$PORT"
        PORT="$WANT"
        TOKEN=""
        SCHEME=http
        if port_is_up; then
            if port_is_ours; then
                open_dashboard
                exit 0
            fi
            refuse_head "$PORT"
            echo "  Port $_held, where nzbfast last ran, is taken too." >&2
            refuse_tail
            exit 1
        fi
        # Free: fall through and start there.
    else
        refuse_head "$PORT"
        [ "$_rtport" = "$PORT" ] && \
            echo "  That is where nzbfast last ran, recorded in $RUNTIME." >&2
        refuse_tail
        exit 1
    fi
fi

mkdir -p "$OUT" "$WATCH"

# --bind 0.0.0.0 is the house default on every other platform and is kept
# here on purpose: this is the same daemon a phone remote or a Sonarr on
# another box talks to, and a desktop install is no different. The API
# key the daemon mints on first run is what protects it; the dashboard
# says so loudly if one is ever missing.
# --port is the FIRST-RUN default only: a port saved in settings.json
# beats it, which is the behaviour every other launcher relies on. So
# this passes the plain default rather than whatever runtime.json said,
# and lets the daemon resolve where it belongs.
exec nzbfast serve \
    --config "$CONFIG" \
    --port "${NZBFAST_PORT:-6789}" \
    --out "$OUT" \
    --watch "$WATCH" \
    --index-db "$DATA_DIR/index.db" \
    --open
