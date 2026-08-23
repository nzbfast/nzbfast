#!/bin/zsh
# upload-release-assets.sh - the ONLY sanctioned way to put assets on a
# GitHub Release. TODO 63f: nothing uploads while unscanned.
#
#   packaging/upload-release-assets.sh vX.Y.Z <asset>...
#
# Refuses to upload any file that does not carry a scan stamp matching
# its CURRENT sha256. Stamps are written by scan-release-assets.sh into
# .scan-stamps next to each asset, only for assets it judged clean - a
# CANNOT INSPECT refusal writes nothing, and a rebuild changes the hash,
# so "scanned some earlier version of this file" does not count either.
#
# Why a separate gate instead of trusting the operator to run the scan
# first: cutting v1.0.13 the installer tripped CANNOT INSPECT and was
# uploaded anyway, with the refusal resolved only after publication. It
# happened to be clean. The order of operations must be structural, not
# a step in a checklist.
#
# The release must already exist (create it with --draft and NO asset
# arguments; publish after this succeeds). Uploads run under the anon
# account and refuse any other login.
set -euo pipefail
export LC_ALL=C

REPO=nzbfast/nzbfast
GH_CONFIG_DIR="${GH_CONFIG_DIR:-$HOME/.config/gh-nzbfast}"
export GH_CONFIG_DIR

if [ $# -lt 2 ]; then
  echo "usage: $0 vX.Y.Z <asset>..." >&2
  exit 1
fi
TAG=$1; shift
case "$TAG" in
  v[0-9]*) ;;
  *) echo "first argument must be the tag (vX.Y.Z), got: $TAG" >&2; exit 1 ;;
esac

LOGIN=$(gh api user --jq .login 2>/dev/null || true)
if [ "$LOGIN" != "nzbfast" ]; then
  echo "✗ REFUSING: gh login under $GH_CONFIG_DIR is '${LOGIN:-none}', not 'nzbfast'." >&2
  echo "    Public releases are cut by the release account only." >&2
  exit 1
fi

fail=0
for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "✗ no such file: $f" >&2; fail=1; continue
  fi
  dir=$(dirname "$f"); base=$(basename "$f")
  sum=$( { shasum -a 256 "$f" 2>/dev/null || sha256sum "$f"; } | awk '{print $1; exit}' )
  if [ ! -f "$dir/.scan-stamps" ] || ! grep -q "^$sum  $base\$" "$dir/.scan-stamps"; then
    echo "✗ UNSCANNED: $base has no scan stamp for its current contents." >&2
    echo "    Run: packaging/scan-release-assets.sh $f" >&2
    fail=1
  fi
done
if [ $fail -ne 0 ]; then
  echo "REFUSING to upload. Scan every asset first - and if the scan says" >&2
  echo "CANNOT INSPECT, fix the extractor, never upload around it." >&2
  exit 1
fi

# No macOS resource-fork metadata in any archive we ship.
#
# bsdtar - the tar on the build Mac - stores an AppleDouble `._name` member
# beside every file carrying an extended attribute, and macOS 15+ stamps
# `com.apple.provenance` on files it built. `zip` has the same failure with
# a `__MACOSX/` prefix. Neither is cosmetic:
#
#   - `tar tzvf` ON A MAC DOES NOT SHOW THEM. bsdtar consumes AppleDouble
#     members on read, so every previous inspection came back clean while
#     the bytes were there. GNU tar on Linux shows and extracts them. That
#     asymmetry is why v1.1.2 shipped both linux tarballs with five junk
#     members each and nobody noticed - hence python's tarfile below, which
#     reads what is actually stored.
#   - `._name` at the TOP LEVEL is a second top-level entry, and every
#     unpacker that collapses a single wrapper directory keys on there being
#     exactly one. community-scripts' `_deploy_unpacked_archive` is one, so
#     the Proxmox LXC install put the binary a level down from where its
#     systemd unit looked and the service could not start.
#
# The fix at the source is `COPYFILE_DISABLE=1` (or bsdtar
# `--no-mac-metadata`) on the packaging tar; this is the gate that makes
# forgetting it impossible. Deliberately over EVERY archive asset rather
# than the linux tarballs alone - measured 15 Aug, the .spk and both zips
# are clean today, and this is what keeps the next asset type honest.
#
# .qpkg IS covered, since 23 Aug 2026 - it was the documented hole here
# until then. It is a self-extracting shell script rather than an archive,
# so it cannot just be opened: packaging/qnap/unpack-qpkg.sh splits it
# first, the way packaging/scan-release-assets.sh has always split it, and
# the two inner archives are what get scanned.
#
# The splitter is asked for the PARTS (--parts) rather than for an
# unpacked tree, and that is the whole trick. bsdtar consumes AppleDouble
# members on extract exactly as it does on read, so a gate that unpacked
# the package on this Mac and walked the tree would report every
# junk-carrying .qpkg clean - the same asymmetry as `tar tzvf` above, one
# layer further in. python's tarfile over the raw parts reads what the
# member headers actually store.
#
# A .qpkg is built by qbuild in a container rather than by the Mac's tar,
# so it is barely exposed to this. It is scanned anyway: "not exposed
# today" is what the .spk and both zips were too, and the 1.1.3 .qpkg
# still shipped its builder's uid through both of these gates because
# neither one looked at it.
junk_in_archive() {   # $1 = an archive; prints junk member names, or UNREADABLE:
  python3 - "$1" <<'PY'
import os, sys, tarfile, zipfile

path = sys.argv[1]
bad = []


def flag(pairs):
    """(name, where) - the VERDICT is on the name, the report on the where.

    Judging the labelled string instead was a real hole until 23 Aug 2026:
    a nested member was tested as "package.tgz!._nzbfast", whose basename
    is the whole string, so junk at the TOP level of an inner archive -
    the second-top-level-entry case this gate exists for - never matched.
    Only a nested member sitting in a subdirectory was ever caught.
    """
    for n, where in pairs:
        base = os.path.basename(n.rstrip("/"))
        if base.startswith("._") or n.startswith("__MACOSX/") or "/__MACOSX/" in n:
            bad.append(where)


seen = 0
try:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            seen = len(z.namelist())
            flag([(n, n) for n in z.namelist()])
    else:
        # A .spk is a tar of a tar, and a .qpkg embeds one too; the junk can
        # be in either layer, so recurse one level into nested archives.
        with tarfile.open(path) as t:
            seen = len(t.getmembers())
            flag([(m.name, m.name) for m in t.getmembers()])
            for m in t.getmembers():
                if not m.isfile() or not m.name.endswith((".tar.gz", ".tgz", ".tar")):
                    continue
                fh = t.extractfile(m)
                if fh is None:
                    continue
                with tarfile.open(fileobj=fh) as inner:
                    flag([(i.name, m.name + "!" + i.name)
                          for i in inner.getmembers()])
except Exception as e:  # noqa: BLE001 - an unreadable archive must fail loudly
    print(f"UNREADABLE: {e}")
    sys.exit(0)

# "It opened" is not "we looked inside it". A truncated stream can hand
# tarfile a valid-looking header and nothing else, and an archive with no
# members trivially carries no junk - which is a CLEAN verdict reached by
# having seen nothing. No release asset is legitimately empty.
if not seen:
    print("UNREADABLE: opened, but the archive holds no members")
    sys.exit(0)

print("\n".join(bad))
PY
}

for f in "$@"; do
  qparts=""
  case "$(basename "$f")" in
    *.tar.gz|*.tgz|*.zip|*.spk) scan_these=("$f") ;;
    *.qpkg)
      qparts=$(mktemp -d)
      if ! "$(dirname "$0")/qnap/unpack-qpkg.sh" --parts "$f" "$qparts" >/dev/null 2>&1; then
        echo "✗ $(basename "$f"): CANNOT INSPECT - unpack-qpkg.sh could not" >&2
        echo "      split it into its script, control and data parts. If QDK" >&2
        echo "      changed its self-extractor, that script has to change with" >&2
        echo "      it - see packaging/qnap/qdk-pin.txt." >&2
        rm -rf "$qparts"
        fail=1
        continue
      fi
      scan_these=("$qparts/control.tar" "$qparts/data.tar.gz")
      ;;
    *) continue ;;
  esac
  for a in "${scan_these[@]}"; do
    # A .qpkg's refusal has to name WHICH of its two inner archives is
    # dirty; the file name on its own would send the reader to a shell
    # script and nothing in it.
    label=$(basename "$f")
    if [ -n "$qparts" ]; then label="$label!$(basename "$a")"; fi
    junk=$(junk_in_archive "$a")
    if [ -n "$junk" ]; then
      case "$junk" in
        UNREADABLE:*)
          # Same posture as the linkage gate below: assert the positive. An
          # archive we cannot open has not been shown to be clean, so it
          # does not get to pass by failing to match.
          echo "✗ $label: CANNOT INSPECT - refusing to upload." >&2
          echo "$junk" | sed 's/^/      /' >&2
          fail=1
          continue
          ;;
      esac
      echo "✗ $label: macOS metadata inside the archive:" >&2
      echo "$junk" | head -5 | sed 's/^/      /' >&2
      echo "    Rebuild with COPYFILE_DISABLE=1 in front of the tar/zip (bsdtar" >&2
      echo "    also takes --no-mac-metadata, zip takes -X). Do NOT verify the" >&2
      echo "    rebuild with 'tar tzvf' on a Mac - it hides these. Re-run this" >&2
      echo "    script, or python3 -c 'import tarfile,sys;[print(m.name) for m" >&2
      echo "    in tarfile.open(sys.argv[1]).getmembers()]'." >&2
      fail=1
    fi
  done
  if [ -n "$qparts" ]; then rm -rf "$qparts"; fi
done
if [ $fail -ne 0 ]; then
  echo "REFUSING to upload: an asset carries macOS resource-fork metadata," >&2
  echo "or could not be opened to prove that it does not." >&2
  exit 1
fi

# Owner metadata. tar writes the BUILDING ACCOUNT's uid/gid and user/group
# names into every member header unless the builder passes the flags that
# stop it, and this project is anonymous in public - so a tarball built
# without them ships the build account name to everyone who downloads it,
# in a field no unpacker displays and `tar tzvf` on the release Mac makes
# no fuss about. build-linux-tarballs.sh passes the flags; this is the
# check on the bytes, which is the only one that sees a builder that
# stopped passing them.
#
# .qpkg is excluded here, and unlike the junk gate above it is NOT just a
# splitting problem: this loop demands EMPTY name strings, and root:root
# is the CORRECT installed ownership for a package format, so a .qpkg run
# through it would be refused every release. Its owner headers are checked
# by check-archive-identity.py below, under the ROOT-OK policy that says
# so. Zips are excluded because the format has no uid/gid/uname/gname
# fields to leak.
owner_fail=0
for f in "$@"; do
  case "$(basename "$f")" in *.tar.gz|*.tgz|*.spk) ;; *) continue ;; esac
  owners=$(python3 - "$f" <<'PY'
import sys, tarfile

path = sys.argv[1]
bad = []
try:
    with tarfile.open(path) as t:
        for m in t.getmembers():
            if m.uid or m.gid or m.uname or m.gname:
                bad.append(f"{m.name}: uid={m.uid} gid={m.gid} "
                           f"uname={m.uname!r} gname={m.gname!r}")
except Exception as e:  # noqa: BLE001 - an unreadable archive must fail loudly
    print(f"UNREADABLE: {e}")
    sys.exit(0)
print("\n".join(bad))
PY
)
  [ -n "$owners" ] || continue
  echo "✗ $(basename "$f"): builder identity in the archive headers:" >&2
  echo "$owners" | head -5 | sed 's/^/      /' >&2
  echo "    Rebuild with the owner flags: bsdtar takes" >&2
  echo "    --uid 0 --gid 0 --uname \"\" --gname \"\", GNU tar takes" >&2
  echo "    --owner=0 --group=0 --numeric-owner. packaging/build-linux-tarballs.sh" >&2
  echo "    picks the right pair; --print-tar-owner-flags shows which." >&2
  owner_fail=1
done
if [ $owner_fail -ne 0 ]; then
  echo "REFUSING to upload: an asset names the account that built it." >&2
  exit 1
fi

# The two gates above cover .tar.gz/.tgz/.zip/.spk, and since 23 Aug 2026
# the junk one reaches inside a .qpkg as well. What is still not theirs is
# the .qpkg's OWNER headers - root:root is right for a package format and
# wrong for a tarball, so it cannot share the strict loop - and .deb/.rpm,
# which are not archive types either gate opens. Cutting 1.1.3 the .qpkg
# went out with `uid=1001 gid=1001 uname='runner' gname='runner'` on every
# member of BOTH its inner tars, through both gates, because neither
# looked at it at all.
#
# check-archive-identity.py is the splitter that closes it: it takes a
# .qpkg apart the way packaging/qnap/unpack-qpkg.sh documents and reads
# the tar headers WITHOUT extracting (extraction as a non-root user drops
# the very uid/gid at issue), parses a .deb's `ar` members, and reads
# FILEUSERNAME/FILEGROUPNAME straight out of an .rpm header. It is also
# what the release.yml jobs run on their own output, so a CI-built asset
# meets the same rule where it is produced and again here.
#
# Additive on purpose: it re-checks the tar and zip assets the gates above
# already judged rather than replacing either. A third opinion that can
# only ever refuse is the right shape for the last mile.
python3 "$(dirname "$0")/check-archive-identity.py" "$@" || {
  echo "REFUSING to upload: an asset names the account that built it." >&2
  exit 1
}

# Linux release binaries must be STATICALLY linked (musl). Cutting 1.1.2 the
# linux tarballs were built for *-unknown-linux-gnu and published dynamically
# linked before anyone noticed. The names are the trap: the release carries
# BOTH `nzbfast-X.Y.Z-linux-x64.tar.gz` (human download, static musl, built
# here) and `nzbfast-x86_64-unknown-linux-gnu.tar.gz` (CI provenance build,
# glibc), and reading the triple off the wrong family picks a build that
# cannot start where it has to. Measured 28 Jul: the glibc aarch64 binary
# dies with `GLIBC_2.39 not found` on debian:bookworm; it would not run on
# Alpine at all, and DSM's older glibc takes the .spk down with it.
#
# Only the versioned human tarballs are checked. The `<triple>.tar.gz`
# provenance assets are SUPPOSED to be glibc - they are attested CI output,
# not the download we point people at - so matching them here would refuse
# every release.
for f in "$@"; do
  case "$(basename "$f")" in
    nzbfast-[0-9]*-linux-*.tar.gz) ;;
    *) continue ;;
  esac
  bin=$(tar tzf "$f" | grep -E '/nzbfast$' | head -1)
  if [ -z "$bin" ]; then
    echo "✗ $(basename "$f"): no nzbfast binary inside - cannot verify linkage." >&2
    fail=1; continue
  fi
  tmp=$(mktemp -d)
  tar xzf "$f" -C "$tmp" "$bin"
  # `file` says "statically linked" for musl, "dynamically linked" plus an
  # interpreter for glibc. Assert the positive - an unreadable file must
  # fail, never pass by not matching the negative.
  if file "$tmp/$bin" | grep -q "statically linked"; then
    echo "  ✓ $(basename "$f"): statically linked"
  else
    echo "✗ $(basename "$f"): NOT statically linked - $(file -b "$tmp/$bin")" >&2
    echo "    Release linux tarballs are static musl. Rebuild with:" >&2
    echo "    cargo zigbuild --release --target x86_64-unknown-linux-musl \\" >&2
    echo "                            --target aarch64-unknown-linux-musl -p nzbfast" >&2
    fail=1
  fi
  rm -rf "$tmp"
done
if [ $fail -ne 0 ]; then
  echo "REFUSING to upload: a linux asset would not start where it has to." >&2
  exit 1
fi

echo "all $# asset(s) carry a current scan stamp - uploading to $TAG"
gh release upload "$TAG" --repo "$REPO" --clobber "$@"
echo "✓ uploaded $# asset(s) to $TAG"
