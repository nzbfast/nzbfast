#!/bin/sh
# make-sha256sums.sh <dist-dir>
#
# Write SHA256SUMS and SHA256SUMS.txt over the HUMAN DOWNLOADS in a dist
# directory. Two files, byte-identical, because both names are in the
# field: SECURITY.md and push-image.sh document `SHA256SUMS.txt`, older
# releases carry the bare `SHA256SUMS`, and packaging/av-scan.sh falls
# back from one to the other so it still works on past releases.
#
# WHY THIS EXISTS. Nothing generated these until 12 Sep 2026; the
# publish-release runbook simply globbed `<dist-dir>/SHA256SUMS*` at the
# upload step and left an operator to have made them. v1.4.0 went public
# WITHOUT BOTH of them - the operator improvised the upload globs - and
# that is not a cosmetic loss: `packaging/make-spk.sh` and
# `packaging/make-qpkg.sh` fetch `SHA256SUMS.txt` off the release to
# verify their payload, so both NAS packages died at step 4c with a bare
# `curl: (56) ... 404`, and three rows of the download table 404'd for
# about twenty minutes. `tools/release-asset-parity.py` refuses the
# regression now; this is the other half, so there is nothing to
# improvise.
#
# WHAT GOES IN, and the rule is the release notes' own: the files a
# PERSON downloads. The `nzbfast-updater-*` payloads, `latest.json`,
# `latest.json.sig` and `RELEASE_NOTES.md` are machine-only or not
# assets, and none of them has ever been in this file - the manifest
# carries its own signed sha256 per payload, which is the check that
# matters there.
#
# NOT IN IT EITHER: the Synology `.spk` and the QNAP `.qpkg`. They are
# built AFTER the release is published (publish-release section 4c) by
# scripts that READ this file, so an entry for them here could only ever
# be a hash of something that does not exist yet.
#
# Order is the directory's, sorted - `sha256sum -c` does not care, and a
# deterministic order keeps a re-run diffable against the last one.
#
# RUN IT LAST. Every asset must be in its final form: regenerate after
# any rebuild, or the file attests bytes that are no longer there.
set -eu

DIST=${1:?usage: make-sha256sums.sh <dist-dir>}
[ -d "$DIST" ] || { echo "no such directory: $DIST" >&2; exit 1; }
cd "$DIST"

# Everything that is an asset, minus the machine-only ones. A leading
# `nzbfast` covers the dmg, the zips, the tarballs, the apk, the rpms and
# the debs (`nzbfast_1.5.0-0beta1_amd64.deb` included - the separator is
# `_`, so the glob is deliberately not `nzbfast-`).
list=$(ls -1 2>/dev/null | grep '^nzbfast' \
    | grep -v '^nzbfast-updater-' \
    | grep -v '\.sha256$' | grep -v '\.intoto\.jsonl$' | sort || true)

[ -n "$list" ] || {
    echo "x no human downloads found in $DIST - refusing to write an empty" \
         "SHA256SUMS, which would publish as a checksum file attesting" \
         "nothing" >&2
    exit 1
}

: > SHA256SUMS
for f in $list; do
    shasum -a 256 "$f" >> SHA256SUMS
done
cp SHA256SUMS SHA256SUMS.txt

echo "== wrote SHA256SUMS and SHA256SUMS.txt over $(wc -l < SHA256SUMS | tr -d ' ') asset(s) =="
cat SHA256SUMS
