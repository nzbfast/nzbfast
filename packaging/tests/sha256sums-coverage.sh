#!/bin/sh
# make-sha256sums.sh has to cover every download, the updater payloads
# included (issue 107), leave the metadata out, and print the same bytes
# whatever the locale: the release Mac `cmp`s its run against the file
# provenance-release.yml's `sums` job published.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
for f in nzbfast-1.0.0-linux-x64.tar.gz nzbfast_1.0.0_amd64.deb \
         nzbfast-updater-1.0.0-linux-x64.gz nzbfast-1.0.0-android-arm64.apk \
         nzbfast-1.0.0-linux-x64.tar.gz.intoto.jsonl \
         nzbfast-1.0.0-linux-x64.tar.gz.spdx.json \
         nzbfast-x.tar.gz.sha256 latest.json latest.json.sig; do
  printf '%s' "$f" > "$f"
done
LC_ALL=en_US.UTF-8 sh "$here/packaging/make-sha256sums.sh" . >/dev/null
cp SHA256SUMS first
LC_ALL=POSIX sh "$here/packaging/make-sha256sums.sh" . >/dev/null
cmp first SHA256SUMS
cmp SHA256SUMS SHA256SUMS.txt
got=$(awk '{print $2}' SHA256SUMS)
want='nzbfast-1.0.0-android-arm64.apk
nzbfast-1.0.0-linux-x64.tar.gz
nzbfast-updater-1.0.0-linux-x64.gz
nzbfast_1.0.0_amd64.deb'
[ "$got" = "$want" ] || { printf 'wrong set:\n%s\n' "$got" >&2; exit 1; }
shasum -a 256 -c SHA256SUMS >/dev/null
echo "sha256sums-coverage: ok"
