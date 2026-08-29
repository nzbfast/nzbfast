# nzbfast on Android - adb test kit

> **The RELEASE artifact is `build-release-apk.sh` in this directory**
> (TODO 281 AN5, 27 Aug 2026). It cross-builds the slim engine, stages
> it, assembles, signs with the project's release keystore and verifies with
> apksigner, producing `out/nzbfast-<ver>-android-arm64.apk`. Neither
> `build-apk.sh` nor `run-on-device.sh` below is a release path: the
> first signs with a throwaway debug key and the second pushes a bare
> binary to /data/local/tmp. `.claude/skills/release-bundle` has the
> keystore location, the certificate fingerprint to compare an upload
> against, and why a second key would be a second app.
>
> The native Jetpack Compose app now lives in `compose-app/` (screens,
> ExoPlayer test preview, remote mode - see its README and
> CONTRACT.md). The WebView APK below stays as the fallback shell; its
> on-device engine owns port 6789, while the compose app's takes an
> OS-chosen port and publishes it in `runtime.json`, so the two can
> never collide however many are installed.

Proof-of-life kit for the Android port: build the slim engine for
aarch64, push it to a phone or emulator with adb, run the daemon on
127.0.0.1, drive it from the device's own browser.

This is the Phase 0 shape from `research/PLAN-ANDROID.md`: no app yet,
just the engine binary under adb. The slim build (`--no-default-features`)
compiles out the indexer stack (index, Spotnet, oracle ledger,
enrichment) and with it sqlite; the download pipeline - NNTP, yEnc
decode, PAR2 verify/repair, extraction - is all there.

THE DASHBOARD IS NO LONGER PART OF THE SLIM BUILD (TODO 281 IO3b,
28 Aug 2026): it is a `dashboard` cargo feature, on in `default` and
dropped by `--no-default-features`, so the iOS store binary and the
release APK's engine carry no web UI at all. THIS kit is the one place
in this directory that still needs it - a WebView shell whose entire UI
is that page - so every command below asks for it back with
`--features dashboard`. Do not copy that flag into `compose-app/`: the
release APK is the Compose app, its UI is native, and it correctly
ships without the pages.

## Build

Requires the Android NDK and cargo-ndk, plus the rust targets:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
```

From the repo root (ANDROID_NDK_HOME must point at an installed NDK):

```sh
cargo ndk -t arm64-v8a -p 26 build --release -p nzbfast \
  --no-default-features --features dashboard
cp target/aarch64-linux-android/release/nzbfast packaging/android/nzbfast-android-arm64
```

For the x86_64 emulator image swap `-t x86_64` and the target dir
accordingly. `-p 26` = API 26 / Android 8, the plan's floor.

## Run

Connect a device (USB debugging on) or start an emulator, then:

```sh
cd packaging/android
./run-on-device.sh
```

The script pushes the binary to `/data/local/tmp/nzbfast`, starts
`nzbfast serve --bind 127.0.0.1 --port 6789` with a throwaway API key,
and opens the dashboard in the device browser. Add a test NZB either
through the dashboard or by pushing it into the watch folder:

```sh
adb push test.nzb /data/local/tmp/nzbfast/watch/
```

Servers are configured in the dashboard (Settings - Servers) exactly as
on any other platform.

## Notes

- `NZBFAST_NO_ENRICH=1` is set by the script; the slim build has no
  enrichment workers to begin with, the variable is belt and braces.
- Everything stays under `/data/local/tmp/nzbfast`; remove with
  `adb shell rm -rf /data/local/tmp/nzbfast`.
- The daemon binds 127.0.0.1 only - nothing off-device can reach it.
- This kit is for local testing; nothing here is a release artifact.
