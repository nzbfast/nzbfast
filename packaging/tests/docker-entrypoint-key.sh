#!/bin/zsh
# Guard tests for docker-entrypoint.sh's API-key pre-flight.
#
# The container refuses to publish the control API on 0.0.0.0 when the
# operator BELIEVES a key is set and it is not. It does NOT refuse merely
# because an existing install has never had one: that install was already
# open, has been for its whole life, and refusing to boot does not close
# it - it just takes the box away, with the reason readable only over SSH.
# 1.0.10 got this wrong and restart-looped every keyless container on
# update, so the second half of that distinction is what these cases pin
# down. Too loose opens provider passwords to the LAN; too strict makes
# the container unstartable with no console to explain it.
#
# The daemon owns the policy (see first_run_apikey in serve.rs: an
# existing install is left "EXACTLY as it was"); this script must agree
# with it rather than override it.
#
# The entrypoint execs `nzbfast` last, so a stub on PATH stands in for
# the daemon and "STARTED" in the output means the pre-flight let it
# through. Run: packaging/tests/docker-entrypoint-key.sh
set -uo pipefail

SCRIPT=$(cd "$(dirname "$0")/.." && pwd)/docker-entrypoint.sh
[ -f "$SCRIPT" ] || { echo "cannot find docker-entrypoint.sh"; exit 1; }

PASS=0
FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# One case: build a /config, run the entrypoint against it with a stub
# daemon on PATH, and say whether it started or refused.
#
# $2 is shell run inside the config dir to set the install's state.
# $4, when "warn", additionally requires the keyless WARNING to be
# printed. Starting silently on an open API is its own failure: the
# banner is the only thing standing between the owner and not knowing.
#
# Matched on the warning's OWN words ("no API key at"), not on the string
# "WARNING". The entrypoint now legitimately prints a second, unrelated
# warning - a config directory that is not a mounted volume, which is
# exactly what a mktemp fixture has - so a bare WARNING match made every
# KEYED case fail while claiming the opposite of what it found (review
# sweep 12 Aug, packaging red 1).
run_case() {
  local desc=$1 setup=$2 expect=$3 wantwarn=${4:-}
  local tmp cfgdir out
  tmp=$(mktemp -d)
  cfgdir="$tmp/config"
  mkdir -p "$cfgdir" "$tmp/bin"
  printf '#!/bin/sh\necho STARTED\n' > "$tmp/bin/nzbfast"
  chmod +x "$tmp/bin/nzbfast"
  echo '{"servers":[]}' > "$cfgdir/config.json"
  ( cd "$cfgdir" && eval "$setup" )

  out=$(PATH="$tmp/bin:$PATH" NZBFAST_CONFIG="$cfgdir/config.json" \
        NZBFAST_APIKEY= NZBFAST_OPEN=0 sh "$SCRIPT" 2>&1)

  if [ "$expect" = "start" ]; then
    if ! echo "$out" | grep -q STARTED; then
      bad "$desc: refused when it should have started: $(echo "$out" | head -2)"
    elif [ "$wantwarn" = "warn" ] && ! echo "$out" | grep -q "no API key at"; then
      bad "$desc: started but did not warn that it is running keyless"
    elif [ "$wantwarn" != "warn" ] && echo "$out" | grep -q "no API key at"; then
      bad "$desc: warned about a keyless API when a key is set"
    else
      ok "$desc"
    fi
  else
    if echo "$out" | grep -q STARTED; then
      bad "$desc: started when it should have refused"
    elif echo "$out" | grep -q "ERROR"; then
      ok "$desc"
    else
      bad "$desc: neither started nor refused: $(echo "$out" | head -2)"
    fi
  fi
  rm -rf "$tmp"
}

echo "docker-entrypoint.sh API-key pre-flight"

# The states that must still refuse: a key file is there, so the operator
# believes the API is authenticated, and it is not. Starting would be a
# silent lie. Nothing is holding a working key in these states either, so
# refusing costs no one their *arr wiring.
run_case "key file exists but is empty" \
  'echo "{}" > settings.json; : > apikey' refuse

# The states that must START, keyless, having said so.
#
# These were the 1.0.10 brick. An install that has run and has never had
# a key is keyless BY HISTORY, not by fault: its *arrs authenticate with
# nothing, and its dashboard is reachable without a key, which is the one
# route by which the owner can actually fix it. Mint a key for them and
# every connected app breaks at once; refuse to boot and they lose the
# box. So: start, warn, and let the daemon's open-API banner carry it
# into the dashboard log where it can be acted on.
run_case "established install, no key anywhere" \
  'echo "{}" > settings.json' start warn
run_case "spool only, no key anywhere" \
  'mkdir -p .spool' start warn
# An empty or null apikey in settings.json is the same thing said a
# different way: no key. The daemon filters both to None, so the
# entrypoint must not treat them as a fault either.
run_case "settings.json holds an EMPTY apikey" \
  'printf "{\"apikey\": \"\"}\n" > settings.json' start warn
run_case "settings.json holds a null apikey" \
  'printf "{\"apikey\": null}\n" > settings.json' start warn
run_case "first run, writable /config" \
  'true' start
run_case "key file present and non-empty" \
  'echo "{}" > settings.json; echo deadbeef > apikey' start

# THE REGRESSION: clearing the key in the dashboard deletes the key file,
# and re-setting one used to write only settings.json. settings.json WINS
# at load, so that install is keyed - but the entrypoint looked only at
# the file and refused, leaving the container unable to restart at all.
run_case "settings.json holds a key, key file was cleared away" \
  'printf "{\n  \"apikey\": \"deadbeef\"\n}\n" > settings.json' start
run_case "same, written compactly by hand" \
  'printf "{\"apikey\":\"deadbeef\"}\n" > settings.json' start

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
