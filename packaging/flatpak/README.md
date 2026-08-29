# Flatpak package - BETA

Flatpak is the one Linux format that reaches every desktop distribution
without us maintaining packaging for each of them. Until now the only
Linux downloads were tarballs and the .deb / .rpm pair.

**It is beta.** The program inside is the shipped release; what is new is
the packaging - the sandbox, the launcher, the folder permissions - and
that is what wants testing.

Like the .deb and .rpm, it is deliberately **not** in the signed update
manifest (`packaging/make-latest-json.sh`). Flatpak owns the files it
installed and has its own update channel, and our updater must not fight
it. The daemon detects the sandbox and the dashboard's update chip shows
`flatpak update` instead of the download page.

## Install

```sh
flatpak install --user ./nzbfast-1.2.4-x86_64.flatpak
flatpak run io.github.nzbfast.nzbfast
```

Or click the nzbfast icon in your application menu. That starts the
daemon and opens the dashboard in your browser. Clicking it again while
it is running just opens the dashboard.

## How it presents

nzbfast is a daemon with a web dashboard, not a windowed program, so
there is no nzbfast window - the browser is the interface. The package
follows SABnzbd's Flathub shape rather than inventing one: a desktop
entry that runs the daemon in the foreground and opens the dashboard
once the port is listening.

Closing the browser tab leaves the daemon running. It stops when you log
out, or with:

```sh
flatpak kill io.github.nzbfast.nzbfast
```

There is no autostart-on-boot. A Flatpak is a desktop-session package;
if you want nzbfast running whether or not anyone is logged in, the .deb
/ .rpm with its systemd unit is the right package (`packaging/linux/`).

## Where things go

| Path (on the host) | What it is |
|---|---|
| `~/.var/app/io.github.nzbfast.nzbfast/config/nzbfast/` | config, settings, API key, queue spool, index |
| `~/Downloads/nzbfast/` | completed downloads, until you change it |
| `~/Downloads/nzbfast/watch/` | drop .nzb files here |

The data directory needs no permission at all: inside the sandbox
`XDG_CONFIG_HOME` already points at the app's own private directory. It
is also why a Flatpak install and a tarball install on the same machine
do not collide.

## Folder permissions - read this one

A Flatpak reaches only the folders it was granted, and a folder it was
not granted fails with a plain permission error on a path that looks
perfectly writable from a terminal. Granted out of the box:

| Permission | Why |
|---|---|
| `--filesystem=home` | the download folder can be anywhere in the home directory, and the user picks it after install |
| `--filesystem=/mnt`, `/media`, `/run/media` | secondary and removable drives, across every distribution's mount convention |
| `--filesystem=/srv` | where a home server keeps its data |
| `--filesystem=xdg-run/gvfs` | network shares mounted by the desktop rather than fstab |
| `--share=network` | Usenet, and the dashboard's own listener |

Downloading somewhere outside all of that - a second internal disk at
`/data`, say - needs one command:

```sh
flatpak override --user --filesystem=/data io.github.nzbfast.nzbfast
```

[Flatseal](https://flathub.org/apps/com.github.tchx84.Flatseal) does the
same with checkboxes. Restart nzbfast afterwards.

To go the other way and tighten it:

```sh
flatpak override --user --nofilesystem=home io.github.nzbfast.nzbfast
flatpak override --user --filesystem=xdg-download io.github.nzbfast.nzbfast
```

The manifest explains each permission where it is granted, including the
two we deliberately do not ask for (`--filesystem=host`, and any display
socket - nzbfast draws nothing, and reaches your browser through the
OpenURI portal).

**One caveat for a Flathub submission.** `--filesystem=home` is a
flatpak-builder-lint error and needs a Flathub exception. So does
`--filesystem=host`; only SABnzbd's narrower set lints clean. All three
variants were measured on 15 Aug 2026:

| finish-args | flatpak-builder-lint |
|---|---|
| `home` + mount points (ours) | `finish-args-home-filesystem-access` |
| `host` (qBittorrent, Transmission, Fragments) | `finish-args-host-filesystem-access` |
| `xdg-download` + mount points (SABnzbd) | clean |

The three peers with `host` each hold an exception, so this is a
submission-time conversation rather than a blocker - and it does not
apply to the bundle at all. Trading it for a clean lint is one line:
`--filesystem=home` becomes `--filesystem=xdg-download`.

## Build it

Needs a Linux machine with `flatpak-builder`, the freedesktop 25.08
runtime and SDK, and the Rust SDK extension:

```sh
flatpak install -y flathub org.freedesktop.Platform//25.08 \
    org.freedesktop.Sdk//25.08 org.freedesktop.Sdk.Extension.rust-stable//25.08
```

Then:

```sh
./generate-cargo-sources.sh      # only after a Cargo.lock change
./make-flatpak.sh                # from the tagged release
./make-flatpak.sh --local        # from the current working tree
```

Both produce `nzbfast-<version>-<arch>.flatpak`, a single file that
installs on any distribution. A bundle is architecture-specific: build it
on the architecture you want. x86_64 and aarch64 come from the same
manifest with no arch conditionals, and nothing in it restricts
`only-arches`.

`cargo-sources.json` is generated, not written by hand: a Flathub build
has no network, so every crate has to be listed with a URL and a
checksum up front. Regenerate it whenever `Cargo.lock` changes or the
build stops offline at the first crate that moved.

## What has been tested, and what has not

Built and exercised on x86_64 in a container (Ubuntu host, the
`flathub-infra/flatpak-github-actions:freedesktop-25.08` image), 15 Aug
2026:

- builds from source against freedesktop 25.08 with the rust-stable SDK
  extension, fully offline from `cargo-sources.json` (657 entries)
- the bundle installs, and exports the binary, launcher, desktop entry,
  metainfo, icon and licence
- the metainfo passes `appstreamcli validate`, the desktop entry passes
  `desktop-file-validate`
- the daemon starts inside the sandbox and serves the API
- it reports `flatpak: true` / `container: false`, so the dashboard shows
  the `flatpak update` recipe and not the compose-file one
- the data directory lands in the sandbox-private config directory
- a second launch opens the dashboard instead of trying to bind the port,
  including when the port was changed away from 6789: the launcher reads
  the live port out of `runtime.json` (verified with a daemon on 7100 -
  the second launch was a no-op and nothing ever bound 6789)
- **the permissions do what they say**: `/mnt`, `/media`, `/run/media`
  and `/srv` are all writable from inside and a host file under `/mnt` is
  readable, while an ungranted path (`/opt`) is refused. Writes to `/etc`
  inside the sandbox land on the runtime's own `/etc` and never reach the
  host's.

Not tested, and the reason it matters:

- **aarch64.** The manifest carries no arch conditionals and nothing
  restricts `only-arches`, but no ARM build has been run.
- **A real desktop session.** Everything above is headless. The one path
  that cannot be checked that way is the click-the-icon path: whether the
  OpenURI portal actually lands the dashboard in the user's browser. That
  is the single thing a first tester should confirm.

## Flathub

Not submitted. Flathub's requirements page carries a generative-AI policy
that this project has to be read against before anything is filed:

> Applications containing AI-generated or AI-assisted code,
> documentation, or any other content are not allowed.

with "Exceptions may be granted for mature, well-maintained projects".
The same section forbids AI tools or agents opening the submission PR.
That is a decision for the maintainer, not something to route around, so
this directory ships the manifest and the bundle and stops there.

Nothing here is wasted if the answer is no: the bundle is the same thing
NZBGet ships (`com.nzbget.nzbget.<ver>.<arch>.flatpak` on their release
page), and NZBGet is not on Flathub either. SABnzbd is, as
`org.sabnzbd.sabnzbd`, and its manifest is what this one was modelled on.

If it is submitted, the manifest goes to `flathub/flathub` on the
`new-pr` base branch, and needs first:

- the source tarball pointed at a release that contains the Flatpak
  support (1.1.3 or later - 1.1.2 predates the sandbox detection, so its
  update chip would send Flatpak users to the download page). DONE 22
  Aug: the manifest is on v1.2.1, and `cargo-sources.json` was checked
  against that tag's own `Cargo.lock` rather than the working tree's -
  328 registry crates, an exact match, so no regeneration was owed.
- `flatpak run --command=flatpak-builder-lint org.flatpak.Builder manifest io.github.nzbfast.nzbfast.yaml`
- the app ID verified by putting the Flathub token at
  `https://nzbfast.github.io/.well-known/org.flathub.VerifiedApps.txt`
