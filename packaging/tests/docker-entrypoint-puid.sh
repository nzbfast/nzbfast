#!/bin/sh
# Guard tests for how docker-entrypoint.sh decides which uid:gid to run as.
#
# packaging-tests-roster: needs a container to exercise the root-only uid
# branch. It SKIPS cleanly with no daemon, so a developer Mac proves
# nothing, and on a runner docker IS present, so wiring it would run it for
# real for the first time. That wants its own change and its own
# verification cycle, priced rather than waved through. See the roster of
# deliberate exclusions in size-gate.yml's `packaging-gates` job.
#
# This only matters on NAS bind mounts, and it is invisible when wrong: the
# daemon starts fine, downloads just land owned by a uid the NAS does not
# recognise, so File Station shows files the owner cannot manage and the
# *arrs cannot move. Two bugs this pins down, both found by running it
# rather than reading it:
#
#   - The group used to be DERIVED from the uid (PGID defaulted to PUID),
#     so a folder owned 1026:100 - the Synology default, uid 1026 in group
#     `users` - produced 1026:1026. The group is now read off the folder.
#   - Only /config was consulted. A user who made /downloads themselves
#     but let Docker create /config got the 1000 fallback, because Docker
#     creates a missing bind-mount source as root.
#
# The uid branch only runs as root, so this needs a container; it is not
# testable from a shell on the host. The entrypoint execs `nzbfast` last,
# so a stub that prints its own uid/gid says what the pre-flight chose.
#
# Run: packaging/tests/docker-entrypoint-puid.sh
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
EP="$SELF/../docker-entrypoint.sh"
BASE="${NZBFAST_TEST_IMAGE:-nzbfast/nzbfast:latest}"
[ -f "$EP" ] || { echo "cannot find docker-entrypoint.sh" >&2; exit 1; }

if ! docker info >/dev/null 2>&1; then
    echo "SKIP: no working docker daemon" >&2
    exit 0
fi

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"; docker rmi -f nzbfast-puidtest >/dev/null 2>&1 || true' EXIT
cp "$EP" "$CTX/docker-entrypoint.sh"
cat > "$CTX/Dockerfile" <<EOF
FROM $BASE
COPY docker-entrypoint.sh /test-entrypoint.sh
RUN printf '#!/bin/sh\necho "RANAS uid=\$(id -u) gid=\$(id -g)"\nexit 0\n' \
      > /usr/local/bin/nzbfast && chmod +x /usr/local/bin/nzbfast \
 && chmod +x /test-entrypoint.sh
ENTRYPOINT ["/bin/sh"]
EOF
docker build -q -t nzbfast-puidtest "$CTX" >/dev/null

pass=0; fail=0
check() {
    desc="$1"; want="$2"; setup="$3"
    got=$(docker run --rm nzbfast-puidtest -c "
        rm -rf /config /downloads /watch
        mkdir -p /config /downloads /watch /incomplete
        $setup
        NZBFAST_OPEN=1 /test-entrypoint.sh serve 2>/dev/null | grep RANAS
    " 2>/dev/null | sed 's/^RANAS //')
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1)); echo "  ok   $desc"
    else
        fail=$((fail + 1)); echo "  FAIL $desc: want '$want' got '$got'" >&2
    fi
}

# Nothing to read an owner from: Docker made every folder as root and the
# container cannot see the host directory above a mount. 1000 is the only
# answer left, and it is the one a plain `docker run` has always given.
check "all folders root-owned falls back to 1000" \
      "uid=1000 gid=1000" "true"

# The group comes off the folder, not the uid. 1026:100 is the Synology
# shape; deriving it would give 1026:1026 and quietly break group access.
check "adopts the folder's group, not the uid" \
      "uid=1026 gid=100" "chown 1026:100 /config"

# Any of the three mounts will do - a user who pre-made only one of them
# should not get the fallback.
check "adopts owner from /downloads alone" \
      "uid=1026 gid=100" "chown 1026:100 /downloads"
check "adopts owner from /watch alone" \
      "uid=1026 gid=100" "chown 1026:100 /watch"

# An explicit request always wins over anything inferred.
check "explicit PUID/PGID wins over folder owners" \
      "uid=1500 gid=1600" \
      "chown 1026:100 /config; export PUID=1500 PGID=1600"

# PUID alone still gets a sensible group rather than refusing.
check "explicit PUID alone still starts" \
      "uid=1500 gid=1500" "export PUID=1500"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
