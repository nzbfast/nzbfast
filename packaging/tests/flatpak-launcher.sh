#!/usr/bin/env bash
# Guard tests for packaging/flatpak/nzbfast-launcher.sh's attach decision.
#
# The launcher has one branch that matters and two ways to get it wrong.
# When something is already listening on the port it either attaches -
# opens that listener in the user's browser under our name - or refuses
# and tells them to move. A false REFUSE locks a user out of their own
# working daemon; a false ACCEPT points their browser at a stranger's
# service and, on the next dashboard open, hands it the stored API key.
#
# Both have shipped. The refuse case was TODO 290 finding F-17: a
# native-TLS daemon could never answer the plaintext /dev/tcp probe, so
# a healthy daemon read as a stranger and every second launch was
# refused. The accept case was the first fix for it, which trusted ANY
# listener the moment runtime.json said tls - including a plaintext one
# that is provably not the TLS daemon that wrote the file.
#
# So the cases below drive both axes at once: what runtime.json records
# (tls on/off, a usable token or not) against what is actually on the
# port (our daemon proving the challenge, our shape without a proof, a
# TLS listener, a silent socket, an unrelated web service).
#
# A THIRD AXIS ARRIVED 27 Aug 2026: which port is probed at all. Every
# case here asked for the port runtime.json already named, so nothing in
# this file could see that the probe and the start resolved their port by
# different rules - the probe took runtime.json's unconditionally, the
# start took NZBFAST_PORT. That made the refusal's own advice impossible
# to follow: setting NZBFAST_PORT was read straight back over, and the
# same refusal printed forever. So a case now says what NZBFAST_PORT
# asks for, separately from what the record says.
#
# THE ASSERTIONS ARE NARROWER THAN THEY LOOK, on purpose, and each one
# was verified to bite. A refusal is not just "exited non-zero": it must
# name the port it is refusing about (a refusal naming the recorded port
# when the user asked for another one IS the lockout, and reads
# identically without this) and it must still carry the escape advice at
# the end (a message that stops half way through leaves the user with
# nothing, and that one only showed up under mutation). A start is not
# just "STARTED": it must name the port asked for. Before those three
# lines existed, three of the mutations below were survived.
#
# There is no Flatpak here and none is needed: the launcher is a bash
# script, its inputs are XDG_CONFIG_HOME and a TCP port, and `nzbfast`
# and `xdg-open` are stubs on PATH. Run: packaging/tests/flatpak-launcher.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LAUNCHER="$ROOT/packaging/flatpak/nzbfast-launcher.sh"
[ -f "$LAUNCHER" ] || { echo "cannot find nzbfast-launcher.sh"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is needed for the fake listener"; exit 1; }

PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# Not a credential: a fixture value for a secret this test both writes
# and checks the answer to. The real one is 24 random bytes minted per
# daemon start (serve/bootstrap.rs, random_apikey).
FIXTURE_TOKEN=0123456789abcdef0123456789abcdef0123456789abcdef

TMPROOT=$(mktemp -d)
trap 'rm -rf "$TMPROOT"' EXIT

# The listener under test. One process per case, bound on an ephemeral
# port it reports back, so nothing here collides with a real daemon or
# with another lane's test on this shared checkout.
#
# `silent` closes rather than holding the socket open. A held socket
# would exercise the launcher's 3s read timeout and cost that on every
# run; what the launcher concludes - nothing readable came back - is the
# same either way.
cat > "$TMPROOT/listener.py" <<'PY'
import hashlib, os, socket, struct, sys, threading

behaviour, token, portfile = sys.argv[1], sys.argv[2], sys.argv[3]

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(8)
with open(portfile + '.tmp', 'w') as f:
    f.write(str(srv.getsockname()[1]))
os.rename(portfile + '.tmp', portfile)


def handle(c):
    try:
        c.settimeout(2)
        if behaviour == 'silent':
            return
        data = b''
        try:
            while b'\r\n\r\n' not in data:
                chunk = c.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        if behaviour == 'tls_alert':
            # What rustls answers a plaintext request with: a fatal
            # handshake_failure alert record, then close.
            c.sendall(b'\x15\x03\x03\x00\x02\x02\x28')
            return
        if behaviour == 'foreign_http':
            c.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n'
                      b'<html>some other service</html>')
            return
        if behaviour == 'foreign_reset':
            # Answers, then RSTs instead of closing cleanly - SO_LINGER
            # with a zero timeout. This is the shape that makes bash
            # print its own "read error: Connection reset by peer" out of
            # the probe's read loop, which is a HANDLED condition and
            # must not reach the user ahead of our explanation.
            c.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n'
                      b'<html>some other service</html>')
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack('ii', 1, 0))
            return
        nonce = ''
        try:
            query = data.decode('latin-1').split(' ', 2)[1].split('?', 1)[-1]
        except IndexError:
            query = ''
        for part in query.split('&'):
            if part.startswith('hs='):
                nonce = part[3:]
        # Compact, because that is what the daemon puts on the wire:
        # httputil.rs's json_resp is serde_json's Value::to_string.
        fields = ['"nzbfast":"0.0.0-fixture"', '"version":"4.5.2"']
        if behaviour == 'nzbfast_proof' and nonce:
            proof = hashlib.sha256((token + ':' + nonce).encode()).hexdigest()
            fields.append('"hs_proof":"%s"' % proof)
        body = ('{' + ','.join(fields) + '}').encode()
        c.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n' + body)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


while True:
    try:
        conn, _ = srv.accept()
    except Exception:
        break
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY

# A port nothing is on: take one, learn its number, give it back.
free_port() {
  python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# One case.
#   $1 description
#   $2 listener behaviour, or "none" for a free port
#   $3 what runtime.json records: tls|notls|tls-untokened|noport
#   $4 expected outcome: http|https|refuse|start
#   $5 what NZBFAST_PORT asks for, default "same" (the recorded port,
#      which is what every case did before the escape hatch existed):
#      "free" for a port nothing is on, or a listener behaviour to put a
#      SECOND listener on the asked-for port.
#   $6 which port the outcome is expected on, "rec" (default) or "want"
run_case() {
  local desc=$1 behaviour=$2 record=$3 expect=$4 want=${5:-same} on=${6:-rec}
  local tmp bin port pidfile portfile out rc url i
  local wantport wantpid wantfile expport

  tmp=$(mktemp -d "$TMPROOT/case.XXXXXX")
  bin="$tmp/bin"
  mkdir -p "$bin" "$tmp/home" "$tmp/config/nzbfast"
  printf '#!/bin/sh\necho "STARTED $*"\n' > "$bin/nzbfast"
  # The launcher sends xdg-open's own output to /dev/null, so the URL it
  # was handed has to be recorded in a file to be visible here at all.
  printf '#!/bin/sh\nprintf "%%s" "$1" > "%s/xdg.url"\n' "$tmp" > "$bin/xdg-open"
  chmod +x "$bin/nzbfast" "$bin/xdg-open"

  portfile="$tmp/port"
  if [ "$behaviour" = none ]; then
    port=$(free_port)
  else
    python3 "$TMPROOT/listener.py" "$behaviour" "$FIXTURE_TOKEN" "$portfile" &
    pidfile=$!
    # Otherwise the shell announces "Terminated" for every listener this
    # reaps, and thirteen of those bury the result lines.
    disown "$pidfile" 2>/dev/null
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      [ -f "$portfile" ] && break
      sleep 0.1
    done
    [ -f "$portfile" ] || { bad "$desc: the fake listener never came up"; kill "$pidfile" 2>/dev/null; return; }
    port=$(cat "$portfile")
  fi

  case "$record" in
    tls)            printf '{"pid":1,"port":%s,"tls":true,"token":"%s","version":"0.0.0"}' "$port" "$FIXTURE_TOKEN" ;;
    notls)          printf '{"pid":1,"port":%s,"tls":false,"token":"%s","version":"0.0.0"}' "$port" "$FIXTURE_TOKEN" ;;
    tls-untokened)  printf '{"pid":1,"port":%s,"tls":false,"token":"","version":"0.0.0"}' "$port" ;;
    noport)         printf '{"pid":1,"tls":false,"token":"%s","version":"0.0.0"}' "$FIXTURE_TOKEN" ;;
  esac > "$tmp/config/nzbfast/runtime.json"

  # The port the launch ASKS for. Every case before the escape hatch
  # asked for the port runtime.json already named, which is why nothing
  # in this file could see that the two were resolved by different rules.
  case "$want" in
    same) wantport="$port" ;;
    free) wantport=$(free_port) ;;
    *)
      wantfile="$tmp/wantport"
      python3 "$TMPROOT/listener.py" "$want" "$FIXTURE_TOKEN" "$wantfile" &
      wantpid=$!
      disown "$wantpid" 2>/dev/null
      for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -f "$wantfile" ] && break
        sleep 0.1
      done
      [ -f "$wantfile" ] || {
        bad "$desc: the second fake listener never came up"
        [ "$behaviour" = none ] || kill "$pidfile" 2>/dev/null
        kill "$wantpid" 2>/dev/null
        return
      }
      wantport=$(cat "$wantfile")
      ;;
  esac
  case "$on" in
    want) expport="$wantport" ;;
    *)    expport="$port" ;;
  esac

  out=$(cd "$tmp" && env -i PATH="$bin:/usr/bin:/bin" HOME="$tmp/home" \
        XDG_CONFIG_HOME="$tmp/config" NZBFAST_PORT="$wantport" \
        bash "$LAUNCHER" 2>&1)
  rc=$?
  [ "$behaviour" = none ] || kill "$pidfile" 2>/dev/null
  [ -n "${wantpid:-}" ] && kill "$wantpid" 2>/dev/null
  url=""
  [ -f "$tmp/xdg.url" ] && url=$(cat "$tmp/xdg.url")

  case "$expect" in
    http|https)
      if [ "$rc" -ne 0 ]; then
        bad "$desc: expected to attach, exited $rc ($out)"
      elif [ "$url" != "$expect://127.0.0.1:$expport/" ]; then
        bad "$desc: expected to open $expect://127.0.0.1:$expport/, opened '${url:-nothing}'"
      else
        ok "$desc: attached over $expect"
      fi
      ;;
    refuse)
      if [ "$rc" -eq 0 ]; then
        bad "$desc: expected a refusal, exited 0 ($out)"
      elif [ -n "$url" ]; then
        bad "$desc: refused but still opened '$url' in the browser"
      elif ! printf '%s' "$out" | grep -q 'it is not nzbfast'; then
        bad "$desc: refused without saying why ($out)"
      # WHICH port it refused about is the assertion, not a nicety. A
      # refusal naming the recorded port when the user asked for another
      # one is the lockout this suite grew the escape-hatch cases for,
      # and it reads identically to a correct refusal without this line.
      elif ! printf '%s' "$out" | head -1 | grep -q "port $expport,"; then
        bad "$desc: refused about the wrong port, wanted $expport ($(printf '%s' "$out" | head -1))"
      # A refusal that stops before saying how to get out of it is the
      # defect this file's escape-hatch cases exist for, one step
      # earlier. The advice has to survive to the end of the message AND
      # name an application that exists: it named com.nzbfast.nzbfast for
      # a while, and this app is io.github.nzbfast.nzbfast, so the one
      # command the user was handed could not run.
      elif ! printf '%s' "$out" | grep -q -- '--env=NZBFAST_PORT=[0-9]* io.github.nzbfast.nzbfast'; then
        bad "$desc: refused without usable advice ($out)"
      # Nothing may precede our own message. A listener that closes
      # abruptly - which is exactly what a stranger on the port does -
      # makes bash print its own "read error" diagnostic, and a handled
      # condition that prints a raw shell error ahead of the explanation
      # reads as a crash.
      elif [ "$(printf '%s' "$out" | head -1 | cut -c1-9)" != "nzbfast: " ]; then
        bad "$desc: shell noise ahead of the message ($(printf '%s' "$out" | head -1))"
      else
        ok "$desc: refused"
      fi
      ;;
    start)
      # The port is part of the assertion, not decoration: the whole of
      # the escape hatch is that a daemon is started on the port the user
      # ASKED for rather than on the one runtime.json remembers, and a
      # bare grep for STARTED cannot tell those apart.
      if ! printf '%s' "$out" | grep -q STARTED; then
        bad "$desc: expected to start a daemon, got rc=$rc ($out)"
      elif ! printf '%s' "$out" | grep -q -- "--port $expport"; then
        bad "$desc: started on the wrong port, wanted --port $expport ($out)"
      else
        ok "$desc: started a daemon on $expport"
      fi
      ;;
  esac
}

echo "flatpak launcher attach decision"

# The bug this exists for: a healthy daemon serving TLS. It cannot answer
# a plaintext probe, and it must still be recognised as ours.
run_case "tls daemon, TLS alert to a plaintext probe" tls_alert       tls           https
run_case "tls daemon, socket accepts and says nothing" silent         tls           https

# ...and the false accept the first fix for it introduced. Under tls,
# anything that answers plaintext is provably not the TLS listener
# runtime.json describes.
run_case "tls recorded, unrelated web service on the port" foreign_http tls         refuse
run_case "tls recorded, plaintext impostor printing our name" nzbfast_noproof tls   refuse

# Except when it proves the token: then it IS our daemon and the record's
# scheme is what is stale.
run_case "tls recorded, but our daemon answering plaintext" nzbfast_proof tls       http

# The plaintext side. A token in runtime.json makes the proof mandatory.
run_case "no tls, our daemon proving the challenge" nzbfast_proof     notls         http
run_case "no tls, our shape with no proof"          nzbfast_noproof   notls         refuse
run_case "no tls, unrelated web service"            foreign_http      notls         refuse
run_case "no tls, a TLS listener on the port"       tls_alert         notls         refuse
run_case "no tls, a stranger that resets the socket" foreign_reset    notls         refuse

# No token to hold it to - a daemon older than the handshake, or one
# whose key mint failed. The reply shape is all there is, and refusing
# would break attaching to it at all.
run_case "untokened record, our shape"              nzbfast_noproof   tls-untokened http
run_case "untokened record, unrelated web service"  foreign_http      tls-untokened refuse

# A token says nothing about a port it was not written about, so a
# record naming no port falls back to the shape check.
run_case "record names no port, our shape"          nzbfast_noproof   noport        http
# ...and the refusal that goes with it, which has its own hazard: the
# "that is where nzbfast last ran" line is a `[ test ] && echo`, and
# under `set -e` a version of that which exits on the false branch would
# kill the script part way through explaining itself. Only a record with
# no port takes the false branch.
run_case "record names no port, unrelated web service" foreign_http   noport        refuse

# And the ordinary first click.
run_case "nothing listening"                        none              notls         start

# THE ESCAPE HATCH. Every case above asks for the port runtime.json
# already names, so none of them could see that the two are resolved by
# different rules: the probe took runtime.json's port unconditionally
# while the start took NZBFAST_PORT. A user whose last daemon ran on a
# port something else has since taken was therefore told to set
# NZBFAST_PORT and then had it read straight back over, refusing on the
# same port forever - measured 27 Aug 2026, the launcher never touched
# the port it was asked for.
run_case "stranger on the recorded port, a free port asked for" \
    foreign_http notls start        free         want
run_case "stranger on the recorded port, our daemon on the asked-for one" \
    foreign_http notls http         nzbfast_noproof want
run_case "stranger on the recorded port, a stranger on the asked-for one too" \
    foreign_http notls refuse       foreign_http want

# ...and the bug runtime.json was introduced to fix, which the escape
# hatch must not put back. A daemon of ours is running on the recorded
# port (a port saved in settings.json, which beats --port on every later
# start) while NZBFAST_PORT still names something else. Attach to the
# daemon that exists; do NOT start a second one into a doomed bind.
run_case "our daemon on the recorded port, a different port asked for" \
    nzbfast_proof notls http        free         rec

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
