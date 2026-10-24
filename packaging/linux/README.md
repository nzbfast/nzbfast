# Linux distribution packages (.deb / .rpm) - BETA

Until now the only Linux download was a tarball, so every Linux user
wrote their own systemd unit. These packages do that part for them:
binary, service unit, service account, data directory, one config file.

**They are beta.** The program inside is the shipped release; what is new
is the packaging - the unit, the account, the upgrade path - and that is
what wants testing. They are deliberately NOT listed in the signed update
manifest (`packaging/make-latest-json.sh`), so no existing install can be
auto-updated onto one.

| | |
|---|---|
| `nzbfast_<ver>-0beta<n>_amd64.deb` | Debian, Ubuntu, Raspberry Pi OS, Mint |
| `nzbfast_<ver>-0beta<n>_arm64.deb` | the same, on 64-bit ARM |
| `nzbfast-<ver>-0.beta<n>.x86_64.rpm` | Fedora, RHEL and rebuilds, openSUSE |
| `nzbfast-<ver>-0.beta<n>.aarch64.rpm` | the same, on 64-bit ARM |

The binary is a static musl build, so a package pulls in no libraries and
does not care how old the distribution's glibc is.

## Install

```sh
sudo dpkg -i nzbfast_1.1.2-0beta1_amd64.deb     # Debian / Ubuntu
sudo rpm -i nzbfast-1.1.2-0.beta1.x86_64.rpm    # Fedora / RHEL
```

Installing **enables** the service for the next boot but does **not**
start it, because a fresh install has no Usenet provider configured yet.
Set one up, then start it:

```sh
sudo nzbfast setup --config /var/lib/nzbfast/config.json
sudo systemctl start nzbfast
journalctl -u nzbfast          # the first start prints the API key
```

Then open `http://<host>:6789`.

## What goes where

| Path | What it is |
|---|---|
| `/usr/bin/nzbfast` | the program |
| `/usr/lib/systemd/system/nzbfast.service` | the service unit |
| `/etc/nzbfast/nzbfast.env` | port and folder settings - the only file the package owns under `/etc` |
| `/usr/share/nzbfast/` | the example config and the install-time setup script |
| `/var/lib/nzbfast/` | **your install**: config, settings, API key, queue spool, index, downloads |

Running as: a system account named `nzbfast`, created on first install.

## Upgrading keeps your settings

Install the new package over the old one (`dpkg -i`, `rpm -U`, or your
package manager). What happens:

- Everything in `/var/lib/nzbfast` is left exactly as it is. The package
  does not own a single path inside that directory - not `config.json`,
  not `settings.json`, not the API key, not the spool - so neither dpkg
  nor rpm can replace or delete any of it. `setup-data-dir.sh` runs on
  every install and only ever creates what is *missing*.
- `/etc/nzbfast/nzbfast.env` is a conffile (dpkg) / `%config(noreplace)`
  (rpm). Your edits survive; a changed default arrives beside it as
  `.dpkg-dist` or `.rpmnew`.
- The daemon is restarted only if it was already running.

Removing (`dpkg -r`, `rpm -e`) stops and disables the service and leaves
`/var/lib/nzbfast` alone. Purging (`dpkg -P`) additionally removes
`/etc/nzbfast` - and still leaves `/var/lib/nzbfast`, because that is
where the downloads are. Delete it by hand if you want it gone.

## Downloading somewhere other than /var/lib/nzbfast

The unit runs with `ProtectSystem=strict`, so anything outside
`/var/lib/nzbfast` is read-only to the daemon until you say otherwise -
including a folder that looks perfectly writable from a root shell, and
including one chosen in the dashboard rather than in the env file. Name
it:

```sh
sudo systemctl edit nzbfast
```

```ini
[Service]
ReadWritePaths=/mnt/media
```

`/etc/nzbfast/nzbfast.env` says the same thing where you will be standing
when you need it.

## Building them

```sh
cargo zigbuild --release -p nzbfast \
  --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl
packaging/linux/make-packages.sh
```

`make-packages.sh` runs on Linux only (it needs `dpkg-deb`, `rpmbuild`
and `file`); a release builds these in
`.github/workflows/provenance-release.yml`, job `linux-packages`, around
the binaries inside that run's attested linux tarballs (`--bin-amd64`,
`--bin-arm64`). It refuses to package a binary that is dynamically linked or
built for the other architecture, and it builds the service unit out of
`packaging/systemd/nzbfast.service` rather than keeping a second copy -
asserting every substitution, so an edit to the unit that this script
does not know about stops the build instead of shipping a unit pointing
at the wrong paths.

`packaging/tests/linux-packages.sh` exercises the maintainer scripts and
the generated unit off-box, without installing anything.
