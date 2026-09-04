## Which file do I download?

| Your system | Download this |
| --- | --- |
| macOS (Apple silicon or Intel) | `nzbfast-@VERSION@-macos.dmg` |
| Windows, almost everyone | `nzbfast-@VERSION@-windows-x64-setup.exe` (installer) |
| Windows, portable / no install | `nzbfast-@VERSION@-windows-x64.zip` |
| Windows on ARM (Snapdragon X), **beta - still in testing** | `nzbfast-@VERSION@-windows-arm64-beta-setup.exe`, or the `-beta.zip` |
| Linux x86-64 | `nzbfast-@VERSION@-linux-x64.tar.gz` |
| Linux ARM64 (Raspberry Pi, ARM NAS) | `nzbfast-@VERSION@-linux-arm64.tar.gz` |
| Debian, Ubuntu, Fedora and friends, **beta - still in testing** | `nzbfast_@VERSION@-0beta1_amd64.deb` or `_arm64.deb`; `nzbfast-@VERSION@-0.beta1.x86_64.rpm` or `.aarch64.rpm` |
| Linux 32-bit ARM (Pi 2/3/Zero 2 W on 32-bit Raspberry Pi OS) - **beta** | `nzbfast-@VERSION@-linux-armv7-beta.tar.gz` |
| Synology | `nzbfast-@VERSION@-noarch.spk`, or the Docker image |
| Unraid | **Community Applications**: search `nzbfast` in the Apps tab and click Install |
| QNAP, **beta - still in testing** | `nzbfast-@VERSION@-qnap-beta.qpkg`, or the Docker image |
| TrueNAS SCALE | the Docker image, or the Linux `tar.gz` for your CPU |
| FreeBSD (x86-64), **beta - still in testing** | `nzbfast-@VERSION@-freebsd-x64-beta.tar.gz` |
| Android (phone or tablet, ARM64), **beta - still in testing** | `nzbfast-@VERSION@-android-arm64.apk` |
| Docker | `docker pull nzbfast/nzbfast:@VERSION@`, or [`docker-compose.yml`](https://github.com/nzbfast/nzbfast/blob/main/docker-compose.yml) from the repo (`docker compose up -d`) |

On Unraid there is nothing on this page to download. The Community Applications template fills in port 6789, the three paths and the Unraid user IDs, so there is nothing to write by hand.

Already running the Docker image, on Unraid or anywhere else? Also nothing to download: the tag `latest` now points at @VERSION@, so update the container the way you normally do (on Unraid that is the Docker tab, Check for Updates, Apply Update).

The Windows on ARM build is a beta: it is still in testing, and it is not as stable or as proven as everything else on this page - it ships with each release so that people on these machines can try it and tell us what breaks. It is a native ARM64 build rather than x64 under emulation, so it should be quicker and easier on the battery, but if anything at all misbehaves the `windows-x64` installer runs on these machines too and is the proven one. Like every Windows download here it is not yet code-signed, so expect SmartScreen's "Windows protected your PC" and an elevation prompt naming an unknown publisher, and expect Defender to be more suspicious of it than of the x64 build - that combination has not been exercised on ARM64 either. It is also outside the update check: the in-app updater will not offer it a new version, so watch this page instead.

The Linux `.deb` and `.rpm` packages are also a beta. They install the daemon as a system service with its own user and a data directory under `/var/lib/nzbfast`, and they enable it without starting it, because there is nothing to download until you have added a provider. Both were installed and upgraded on Debian and Fedora before shipping, but they are new, they are not in any distro's own repository, and the version says so: `0beta1` and `0.beta1` both sort BELOW the eventual release revision, so upgrading to the finished package works normally when it lands. If you would rather not be the one to find the rough edges, the `linux-x64` and `linux-arm64` tarballs are the same program and have shipped for months.

The QNAP `.qpkg` is a beta of a different kind: **it has never been run on a QNAP.** Nobody on the project owns one. It is built with QNAP's own QDK, its install decisions are tested against simulated NAS layouts and the built package is taken apart and checked before release, but none of that is a real NAS booting it - so it is offered in the hope that somebody will try it and tell us. Install it through App Center, the gear icon, Install Manually; one file covers both Intel and 64-bit ARM models. Your settings and downloads are normally kept outside the app's own folder, so removing the package leaves them where they are; the exception is a NAS where no shared folder was usable at install time, in which case setup says so on screen and puts them inside the app folder, where an uninstall does take them with it. An issue saying what happened either way is the most useful thing a QNAP owner can send us. The Docker image on Container Station remains the proven path.

Run `uname -m` if you are not sure which Raspberry Pi download you need: `aarch64` means the 64-bit OS, so take the ARM64 file. Only `armv7l` (or `armv6l`) wants the beta 32-bit build - and that one is beta because it has not yet been through a release on real Pi hardware, so it is not offered by auto-update. Update it by downloading the next one by hand.

The FreeBSD build is the newest beta here and the least proven: **nobody has run it on a real FreeBSD machine.** It is built inside a FreeBSD virtual machine on every release, and that same binary downloads a synthetic release over loopback before the file is packaged, so it is not shipped untried. But a virtual machine is not a NAS: no real disks, no ZFS pool, no jail. It is x86-64 only, it needs FreeBSD 14.3 or newer, and it does not reach TrueNAS CORE, which is FreeBSD 13 and now out of support. Unpack it, read the README inside, and there is an rc.d service script in there so `sysrc nzbfast_enable=YES` works the way you would expect. Like the other betas it is outside the update check. If you run FreeBSD, an issue telling us what happened - working or not - is worth more to this build than anything else we could do to it.

The Android build is the newest thing on this page: **this is the first release it has ever appeared in**, and it is a beta in the fullest sense. It is the download engine with a phone front end, ARM64 only, and it is not on Google Play - you install the `.apk` yourself, which means Android will warn you about installing from an unknown source and you have to allow it for your browser or file manager. It is signed with our own key rather than a store one, so that warning is expected; what matters is that the same key signs every future build, so updates install over the top instead of asking you to uninstall first. Unlike the other betas it does tell you when a new version is out: the app asks its own engine once a day, when you open it, and puts a card at the top of the screen with a link to the releases page. It will never install anything - Android does not let an app replace itself without a permission we do not ask for - so the new `.apk` is still a download you start. If you try it, an issue telling us what your phone did is worth more than anything else you could send us.

Everything named `nzbfast-updater-*`, plus `latest.json`, `latest.json.sig` and `SHA256SUMS`, is machine-only. You do not need to download those.
