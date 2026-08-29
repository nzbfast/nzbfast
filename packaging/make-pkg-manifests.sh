#!/bin/sh
# make-pkg-manifests.sh [version]
#
# Regenerate the Windows package-manager manifests (winget + Scoop) from a
# PUBLISHED GitHub release. Run it AFTER the release exists, because it reads
# the release's SHA256SUMS.txt back off the release page - the hashes do not
# exist before the assets are uploaded.
#
#   packaging/make-pkg-manifests.sh            # version from Cargo.toml
#   packaging/make-pkg-manifests.sh 1.0.13     # explicit version
#
# Outputs:
#   packaging/winget/manifests/<version>/nzbfast.nzbfast.yaml
#   packaging/winget/manifests/<version>/nzbfast.nzbfast.installer.yaml
#   packaging/winget/manifests/<version>/nzbfast.nzbfast.locale.en-US.yaml
#   packaging/scoop/nzbfast.json               (rewritten in place)
#
# Neither output publishes anything by itself. Submission is a separate,
# deliberate step - see packaging/winget/README.md and
# packaging/scoop/README.md for each ecosystem's process.
set -eu

REPO=nzbfast/nzbfast
ROOT=$(cd "$(dirname "$0")/.." && pwd)

VER="${1:-}"
if [ -z "$VER" ]; then
  VER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/nzbfast/Cargo.toml" | head -1)
fi
case "$VER" in
  v*) echo "version must not carry the v prefix (assets never do): $VER" >&2; exit 1 ;;
esac

BASE="https://github.com/$REPO/releases/download/v$VER"
SETUP="nzbfast-$VER-windows-x64-setup.exe"
ZIP="nzbfast-$VER-windows-x64.zip"

SUMS=$(curl -fsSL "$BASE/SHA256SUMS.txt") || {
  echo "cannot fetch $BASE/SHA256SUMS.txt - is v$VER published?" >&2; exit 1; }

hash_for() {
  h=$(printf '%s\n' "$SUMS" | awk -v f="$1" '$2 == f { print $1 }')
  if [ -z "$h" ]; then
    echo "no SHA256SUMS.txt entry for $1" >&2; exit 1
  fi
  printf '%s' "$h"
}

SETUP_SHA=$(hash_for "$SETUP" | tr 'a-f' 'A-F')
ZIP_SHA=$(hash_for "$ZIP")

# Release publish date, for the winget ReleaseDate field. Best-effort: an
# API hiccup should not block manifest generation, so fall back to today.
REL_DATE=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/tags/v$VER" 2>/dev/null \
  | sed -n 's/.*"published_at": *"\([0-9-]*\)T.*/\1/p' | head -1)
[ -n "$REL_DATE" ] || REL_DATE=$(date +%Y-%m-%d)

WG="$ROOT/packaging/winget/manifests/$VER"
mkdir -p "$WG" "$ROOT/packaging/scoop"

cat > "$WG/nzbfast.nzbfast.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.1.12.0.schema.json

PackageIdentifier: nzbfast.nzbfast
PackageVersion: $VER
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.12.0
EOF

cat > "$WG/nzbfast.nzbfast.installer.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.1.12.0.schema.json

PackageIdentifier: nzbfast.nzbfast
PackageVersion: $VER
InstallerLocale: en-US
Platform:
- Windows.Desktop
InstallerType: inno
Scope: machine
InstallModes:
- interactive
- silent
- silentWithProgress
UpgradeBehavior: install
ReleaseDate: $REL_DATE
AppsAndFeaturesEntries:
- DisplayName: nzbfast
  Publisher: nzbfast
  ProductCode: '{72B5B673-54D7-46ED-BDDC-C7D3E571D242}_is1'
Installers:
- Architecture: x64
  InstallerUrl: $BASE/$SETUP
  InstallerSha256: $SETUP_SHA
ManifestType: installer
ManifestVersion: 1.12.0
EOF

cat > "$WG/nzbfast.nzbfast.locale.en-US.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.1.12.0.schema.json

PackageIdentifier: nzbfast.nzbfast
PackageVersion: $VER
PackageLocale: en-US
Publisher: nzbfast
PublisherUrl: https://github.com/nzbfast/nzbfast
PublisherSupportUrl: https://github.com/nzbfast/nzbfast/issues
PackageName: nzbfast
PackageUrl: https://nzbfast.github.io/nzbfast/
License: GPL-3.0
LicenseUrl: https://github.com/nzbfast/nzbfast/blob/main/LICENSE
ShortDescription: The fast Usenet downloader
Description: |-
  One self-contained executable: line-rate downloads, one-pass verify and
  extract, a poster wall, and a built-in indexer. Speaks the SABnzbd and
  NZBGet APIs, so Sonarr and Radarr connect unmodified.
Moniker: nzbfast
Tags:
- downloader
- nzb
- nzbget
- sabnzbd
- usenet
ReleaseNotesUrl: https://github.com/nzbfast/nzbfast/releases/tag/v$VER
ManifestType: defaultLocale
ManifestVersion: 1.12.0
EOF

cat > "$ROOT/packaging/scoop/nzbfast.json" <<EOF
{
    "version": "$VER",
    "description": "The fast Usenet downloader. One self-contained executable: line-rate downloads, one-pass verify and extract, a poster wall, and a built-in indexer.",
    "homepage": "https://nzbfast.github.io/nzbfast/",
    "license": "GPL-3.0-only",
    "url": "$BASE/$ZIP",
    "hash": "$ZIP_SHA",
    "extract_dir": "nzbfast-windows",
    "bin": [
        "nzbfast.exe",
        "nzbtray.exe"
    ],
    "shortcuts": [
        [
            "nzbtray.exe",
            "nzbfast"
        ]
    ],
    "checkver": {
        "github": "https://github.com/nzbfast/nzbfast"
    },
    "autoupdate": {
        "url": "https://github.com/nzbfast/nzbfast/releases/download/v\$version/nzbfast-\$version-windows-x64.zip",
        "hash": {
            "url": "https://github.com/nzbfast/nzbfast/releases/download/v\$version/SHA256SUMS.txt"
        }
    }
}
EOF

echo "winget manifests: $WG"
echo "scoop manifest:   $ROOT/packaging/scoop/nzbfast.json"
echo
echo "Nothing has been published. Next steps:"
echo "  winget: copy $WG into a winget-pkgs fork as"
echo "          manifests/n/nzbfast/nzbfast/$VER/ and open a PR (anon account)."
echo "  scoop:  push packaging/scoop/nzbfast.json to the bucket repo (anon account)."
