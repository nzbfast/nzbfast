#!/bin/sh
# QPKG service program. QTS links this into /etc/init.d and calls it with
# start, stop, restart or remove - at boot, from the App Center's buttons,
# and from the uninstall script.
#
# It launches the daemon directly, with a pidfile, rather than handing it
# to an init system. QTS has no per-package supervisor to hand it to:
# App Center reads the pidfile named in qpkg.cfg to decide whether the app
# is running, and that is the whole contract. (The Synology package next
# door arrives at the same shape from the opposite direction - DSM HAS
# systemd and will not let an unsigned package near it.)
#
# What is given up is automatic restart on a crash. QTS does start the
# package at boot by calling this script, which is the part that matters.
CONF=/etc/config/qpkg.conf
QPKG_NAME=nzbfast
QPKG_ROOT=$(/sbin/getcfg "$QPKG_NAME" Install_Path -f "$CONF")
export QNAP_QPKG=$QPKG_NAME

BIN="$QPKG_ROOT/bin/nzbfast"
ENVFILE="$QPKG_ROOT/nzbfast.env"
PIDFILE=/var/run/nzbfast.pid
LOGFILE="$QPKG_ROOT/nzbfast.log"

# Defaults matter: a missing env file must not silently start the daemon
# with empty paths, which would drop downloads in the working directory.
NZBFAST_DATA="$QPKG_ROOT/data"
NZBFAST_PORT=@@PORT@@
NZBFAST_CONFIG="$NZBFAST_DATA/config/config.json"
NZBFAST_OUT="$NZBFAST_DATA/downloads"
NZBFAST_WATCH="$NZBFAST_DATA/watch"
# shellcheck disable=SC1090  # written at install time, not in the repo
[ -f "$ENVFILE" ] && . "$ENVFILE"

running() {
    [ -f "$PIDFILE" ] || return 1
    pid=$(cat "$PIDFILE" 2>/dev/null)
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    # /proc rather than `kill -0`, which also succeeds for a process we do
    # not own, and rather than pgrep, which QTS does not always ship.
    [ -d "/proc/$pid" ] || return 1
    # Match on OUR config path, not just the process name. A NAS running
    # nzbfast in Container Station as well as this package has two
    # processes both called "nzbfast", and a recycled pid landing on the
    # container's daemon would have this report "running" while nothing
    # served our port. The config path is unique to this install.
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "$NZBFAST_CONFIG"
}

case "$1" in
  start)
    ENABLED=$(/sbin/getcfg "$QPKG_NAME" Enable -u -d FALSE -f "$CONF")
    if [ "$ENABLED" != "TRUE" ]; then
        echo "$QPKG_NAME is disabled."
        exit 1
    fi
    if running; then
        echo "nzbfast is already running."
        exit 0
    fi
    if [ ! -x "$BIN" ]; then
        echo "nzbfast: $BIN is missing or not executable." >&2
        exit 1
    fi
    mkdir -p "$NZBFAST_DATA/config" "$NZBFAST_DATA/downloads" "$NZBFAST_WATCH" 2>/dev/null
    # Working directory is the config folder so relative state lands with
    # the config, matching the container's WORKDIR.
    cd "$NZBFAST_DATA/config" 2>/dev/null || cd "$QPKG_ROOT" || exit 1
    # QTS owns this port. It is registered in /etc/config/qpkg.conf as
    # Web_Port and Service_Port, which is what the App Center's Open
    # button uses, and neither of those can be rewritten from inside
    # nzbfast. A port saved in the dashboard would move the listener away
    # from both, so the setting is refused with an explanation instead.
    NZBFAST_PORT_LOCKED=1
    export NZBFAST_PORT_LOCKED
    # QTS ships no nohup. An ignored signal stays ignored across exec, so
    # this does the same job without one: closing the SSH session or App
    # Center's shell does not take the daemon with it.
    trap '' HUP
    "$BIN" serve \
        --config "$NZBFAST_CONFIG" \
        --port "$NZBFAST_PORT" \
        --out "$NZBFAST_OUT" \
        --watch "$NZBFAST_WATCH" \
        </dev/null >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    # Confirm it is still alive rather than reporting success for a
    # process that exited immediately - the failure mode that makes a
    # broken package look installed.
    #
    # It has to DWELL. `running` is satisfied the moment the forked
    # process exists, microseconds after the `&` above, so a single check
    # reports a successful start for a daemon that then dies on an
    # unreadable config, a rejected API key or a bound port. Only
    # CONSECUTIVE seconds of life count.
    i=0
    alive=0
    while [ "$i" -lt 15 ]; do
        sleep 1
        i=$((i + 1))
        if running; then
            alive=$((alive + 1))
            if [ "$alive" -ge 3 ]; then
                echo "nzbfast started on port $NZBFAST_PORT."
                exit 0
            fi
        else
            alive=0
        fi
    done
    echo "nzbfast failed to stay running - see $LOGFILE" >&2
    tail -5 "$LOGFILE" 2>/dev/null >&2
    rm -f "$PIDFILE"
    exit 1
    ;;

  stop)
    if ! running; then
        rm -f "$PIDFILE"
        echo "nzbfast is not running."
        exit 0
    fi
    pid=$(cat "$PIDFILE")
    kill "$pid" 2>/dev/null
    i=0
    while [ "$i" -lt 20 ]; do
        running || break
        i=$((i + 1))
        sleep 1
    done
    if running; then
        kill -9 "$pid" 2>/dev/null
        sleep 1
    fi
    rm -f "$PIDFILE"
    echo "nzbfast stopped."
    exit 0
    ;;

  restart)
    $0 stop
    $0 start
    ;;

  status)
    # Not part of the QPKG contract - App Center reads the pidfile - but
    # this script is also the only handle anyone has over SSH.
    if running; then
        echo "nzbfast is running on port $NZBFAST_PORT."
        exit 0
    fi
    echo "nzbfast is not running."
    exit 1
    ;;

  remove)
    # Called by the uninstall script, before it deletes $QPKG_ROOT.
    # Deliberately does NOT touch the data folder: it lives outside the
    # package for exactly this reason, and uninstalling a downloader is
    # not a request to delete the downloads.
    exit 0
    ;;

  *)
    echo "Usage: $0 {start|stop|restart|status|remove}" >&2
    exit 1
    ;;
esac

exit 0
