# The QNAP package (.qpkg) - BETA

QNAP is the second-largest NAS vendor and, until this, the one platform
whose owners had no path to nzbfast except Container Station. This is a
native App Center package: install it, open the dashboard, done.

**Nobody on this team owns a QNAP, so nothing here has run on real
hardware.** That is the honest state of it, and it is why the artifact is
named `nzbfast-<ver>-qnap-beta.qpkg` and why it is deliberately absent
from the signed update manifest. See "Promoting it out of beta" below for
what a tester's confirmation would unlock.

## What it does on the NAS

| | |
| --- | --- |
| Installed at | `/share/<volume>/.qpkg/nzbfast/` - binary, service script, `nzbfast.env` |
| Data folder | the `nzbfast` folder in your **Download** shared folder, falling back to **Public** |
| Inside it | `config/` (settings, API key, index), `downloads/`, `watch/` |
| Service | `/etc/init.d/nzbfast.sh {start\|stop\|restart\|status}` |
| Port | 6789, registered as the package's Web_Port so App Center's Open button works |

The data folder is deliberately **outside** the package directory. QDK's
generated uninstall script does `rsync -a --delete` and then `rm -rf` over
the whole package directory, so anything kept in there is destroyed by one
click in App Center, with no undo and no warning that mentions downloads.
The layout is the container's exactly (`config`, `downloads`, `watch`
under one folder), which is what the compose file maps, so anyone moving
off Container Station has their existing folder picked up as it stands.

The one exception, and it is the case to keep in mind when reading the
uninstall text: if no shared folder is usable at install time, setup
falls back to `$QPKG_DIR/data`, which IS inside the package directory
and therefore IS destroyed by an uninstall. The install log says so when
it happens, and `PKG_PRE_REMOVE` checks the recorded path and warns
rather than repeating the "untouched" line, but the durable fix is for
the user to point Settings > Folders at a real shared folder.

## Upgrades never touch settings

Three things make that true, and all three are load-bearing:

1. **The data lives outside the package directory**, so QDK's file
   accounting never looks at it.
2. **The package ships no config file at all.** QDK deletes, on upgrade,
   every file the previous package shipped that the new one does not - so
   a settings file shipped once and dropped later would be deleted out
   from under the user.
3. **`QPKG_CONFIG` is not set**, and must never be. It reads like the
   field that protects a user's settings and it is the opposite:
   `qinstall.sh` compares each listed file against the copy *shipped in
   the package*, and for a file that is in no package it renames the
   user's live one to `settings.json.qdkorig` on the first upgrade.

`packaging/tests/qnap-install.sh` pins all three, plus the rule that an
`nzbfast.env` already on disk is the source of truth and is never
rewritten - including when it names a folder the chooser would not have
picked.

## Building it

```sh
packaging/qnap/make-qpkg.sh 1.1.2 dist
```

The payload is the release's own static musl linux binaries, downloaded
and checked against its `SHA256SUMS.txt` - the same trick `make-spk.sh`
uses, so the package ships the exact released bits and needs no
cross-compiler.

The build itself runs QDK, QNAP's own kit, pinned by commit in
`qdk-pin.txt`. **QDK cannot run on macOS**: `qbuild` finishes by rewriting
the generated self-extractor with `sed -i "s/SCRIPT_LEN/.../"`, and BSD
sed reads the next argument as a backup suffix, so the length patch never
lands. `make-qpkg.sh` therefore runs it natively when `qbuild` is on
`PATH`, and in a container on a Linux host without it. If neither is
available it refuses rather than assembling the format by hand.

**On macOS it refuses before it does anything at all**, and the command
above is not the one to run there - dispatch the workflow instead. The
container is not the way round it either, even though `qbuild` itself is
happy inside one: `make-qpkg.sh` stages into `mktemp -d`, macOS `mktemp`
given no template ignores `$TMPDIR` and always answers under
`/var/folders`, and colima shares `$HOME` and `/tmp/colima` but not
`/var/folders` - so the bind mount hands `qbuild` an empty `/work` and it
says `qpkg.cfg: No such file` about a file that is sitting in the staging
tree on the host. Re-running with `TMPDIR` set does not move it. That
cost an hour on 4 Sep 2026 cutting v1.4.0, which is why the refusal is
now the first thing the script does.

Every release gets one, and it is built AFTER the release rather than
during it. The **qnap-qpkg** workflow is the one that ships it: dispatch
it with the tag once the release page is up, then scan and upload the
artifact by hand, exactly as the Synology `.spk` is done. Step 4c of the
publish-release skill is the checklist. The same workflow runs by itself
on any pull request touching this directory, since `qbuild` does not run
on a maintainer's Mac and nothing else would exercise a `qpkg.cfg` edit
before a release.

Until 16 Aug 2026 the release run built it instead, in a `qnap-beta` job
that fed `make-qpkg.sh` the musl binaries the `packages` job already
cross-compiled for the .deb and .rpm - which is what let the package be
built while the release page was still empty. The cost was a package
whose payload nothing published a checksum for. Measured on 1.1.3: the
packaged binaries were `72cad10c` (x86_64) and `71d12ee9` (aarch64),
while the binaries in `nzbfast-1.1.3-linux-x64.tar.gz` and
`-arm64.tar.gz` were `9cc8c994` and `a11ce1ac`. Same source, same
version, different builder. `SHA256SUMS.txt` covers the `.qpkg` as a
file, not the binaries inside it, so a QNAP owner had no way to check
that what they were installing was the release. Waiting for the release
page costs one dispatch and answers that.

**Adding an architecture** is three places: a binary in `shared/bin/`
named `nzbfast-<uname -m>`, the `case` in `nzbfast-setup.sh` that links
it, and the refusal in `package_routines` that runs before anything is
unpacked. Nothing in `qpkg.cfg` changes, because the package is
architecture-less. QDK's own table maps QNAP's model families to
`uname -m`: `arm-x31` and `arm-x41` are both `armv7l`, so one armv7
binary would cover both; `arm-x19` and `arm-x09` are `armv5tel` and
`armv5tejl`. armv7 is not in this package yet, but the reason has
changed: TODO 178 settled the correctness question and a static-musl
`armv7-unknown-linux-musleabihf` build now ships as a beta tarball
beside x64/arm64. What is left is the packaging decision above - one
architecture-less package for every model - so adding it is the
three-place change described here, not a build problem. `armv5` stays
refused; there is no build for it.

One package covers both architectures. The reasoning is in `qpkg.cfg`;
the short version is that App Center's Install Manually dialog does no
filtering, so per-architecture files would make "which of these two is my
NAS" a question the downloader has to get right before anything works.
32-bit ARM models are refused with an explanation, before anything is
written to disk.

## Promoting it out of beta

When a QNAP owner confirms it installs, starts, serves the dashboard and
survives a package upgrade with their settings intact:

1. Drop `-beta` from the artifact name in `make-qpkg.sh`.
2. In `packaging/release-notes-header.md`, drop "**beta - still in
   testing**" from the QNAP row and delete the paragraph below the table
   that says nobody has run it. Both are generated into every release's
   notes, so this is the whole user-facing change.
3. Consider a QNAP Club listing, which is where QNAP owners actually
   browse for third-party packages. It is a repository XML feed, so a
   package that installs by hand is the prerequisite, not the other way
   round.

**Not** the update manifest. `latest.json` carries updater *payloads* for
the six platforms the notify-only updater knows about, and NAS packages
have never been among them - the Synology `.spk` is not there either.
Updates are notify-only: the dashboard says a new version exists and links
to the download page. Nothing in the manifest needs to change for QNAP,
now or later.
