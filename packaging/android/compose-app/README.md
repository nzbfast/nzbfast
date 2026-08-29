# nzbfast for Android (Jetpack Compose)

The native Android app: Material 3, dark-first, DOWNLOADER-first. One
UI, two sources - "this device" runs the bundled slim engine on the
phone (exec'd from nativeLibraryDir, same mechanism as the test APK in
`../app`); "my server" points the same screens at an nzbfast daemon
you already run. The player is Media3 ExoPlayer on the daemon's
/stream endpoint, so Matroska plays with hardware decode and range
seeks.

Screens: Connect (mode picker + first-run news-server form), Home (the
queue: aggregate speed and progress, per-job progress, ETA and phase,
pause/resume/cancel buttons, then history with the daemon's own failure
reasons; Play appears on any row the contract says is readable), Add
(document picker, nzblnk paste, and share-target for .nzb files and
nzblnk links), Settings (export folder, hold-on-mobile-data, and a
readout of the phone-shaped defaults below).

## TODO 281 AN1-AN4, 26 Aug 2026

**AN1, downloader-first Home.** The queue is the headline and Play is a
row affordance. Delete moved off the swipe and onto a button with a
confirmation - a left swipe deleting a download irreversibly is a
gesture a pocket can perform - and that confirmation asks the question
that matters on a phone: whether the bytes go too, defaulting ON for a
queue row (partials are worth nothing) and OFF for a finished one.

**AN2, `EngineService` is a real dataSync foreground service.** It polls
the daemon itself at 5 s, because the notification is the only surface a
user who has left the app can see and the poll behind it therefore
cannot live in an activity; it shows aggregate progress weighted by
BYTES (averaging per-job percentages says a 40 GB job at 10% beside a
200 MB job at 90% is halfway done); it holds a PARTIAL_WAKE_LOCK while
the queue has work, because a foreground service is exempt from being
killed and NOT from the device suspending; and it stops when the queue
drains and the app is off screen. The stop signal is the daemon's own
`queue_idle` (contract addition - see CONTRACT.md), never an empty queue
list: a job in its tail is in neither list. Pause-on-metered is a
setting, driven by a ConnectivityManager callback, and it undoes only
the pause it applied - which takes two halves, not one. Until 28 Aug
2026 only the second half was there: the latch said which pauses to give
back and nothing said which it was allowed to TAKE, so a queue the USER
had paused was adopted by the next step onto cellular and resumed by the
next step off it, or by turning the setting off while still on cellular,
which is a user-paused download running over metered data. Both edges
now go through one rule in `MeteredPolicy.kt`, tested there.

**AN3, storage.** Downloads land in app-private storage and are
EXPORTED, rather than written straight into a SAF tree: a document URI
has no `pwrite` and no preallocation, so aiming the one-pass writer at
one would cost preallocation, range writes and the resume journal in a
single move. Pick a folder with `ACTION_OPEN_DOCUMENT_TREE` and finished
jobs are copied there by the service (so it works with the app closed),
or per job from a history row. Free space is on the Add screen, and the
picked NZB's own declared size is checked against it before the add.

**AN4, phone-shaped defaults** (`DeviceProfile`): `--mem-limit` from
total RAM / 16 clamped 192-512 MB rather than the engine's desktop
RAM/4; `NZBFAST_CPU_WORKERS` from the count of cores in the fastest
frequency tier, read out of `cpuinfo_max_freq`, because
`available_parallelism` counts little cores as big ones and these pools
share one thermal envelope; and the news server's connection count
derived from `linkDownstreamBandwidthKbps` rather than a desktop's
fixed number. All three are shown back on the Settings screen, read
from the same functions that produced them.

The endpoints the app uses are inventoried in `CONTRACT.md`. The API
client is hand-rolled (HttpURLConnection + the platform org.json);
its parsers are exercised by JVM snapshot tests against responses
recorded from a real daemon (`app/src/test/resources/snapshots/`).

## Build

Requires the Android SDK (a platforms/android-36 install), JDK 17+,
and the slim engine binary:

```sh
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
cargo ndk -t arm64-v8a --platform 26 build --release -p nzbfast --no-default-features

cd packaging/android/compose-app
./fetch-engine.sh        # stages the engine as a jniLib (gitignored)
ANDROID_HOME=... ./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Tests: `./gradlew :app:testDebugUnitTest` - 32 JUnit tests, ~25 s, no
device and no engine binary. They are the only thing holding this app
to the frozen contract in `CONTRACT.md`: each parses a response
snapshot recorded from a real daemon, so a daemon-side shape drift
lands here as a red test.

Both this and `:app:lintDebug` run in CI on every push that touches
`packaging/android/compose-app/**`, as two separate steps of the one
job in `.github/workflows/android-lint.yml` (tests wired 27 Aug 2026;
that file's header argues the step-not-task-not-job shape and the
`if:` that stops a red test hiding a red lint).

### Toolchain from nothing (macOS)

A stock Mac has neither a JDK nor an Android SDK, and `java -version`
answers "Unable to locate a Java Runtime". Everything below installs
into the Homebrew prefix, so none of it needs a password:

```sh
brew install openjdk@17                       # keg-only, NOT on PATH
brew install --cask android-commandlinetools

export JAVA_HOME=/opt/homebrew/opt/openjdk@17
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export PATH="$JAVA_HOME/bin:$PATH"

yes | sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-36" "build-tools;35.0.0"
```

`openjdk@17` is keg-only: `JAVA_HOME` has to be set explicitly or
Gradle will not find a JVM. `compileSdk = 36` is what pins the
platform package; `build-tools` and `platform-tools` bring aapt2/d8
and adb. Roughly 3 GB on disk, a few minutes on a fast line.

**The Kotlin builds without the engine and without the NDK.** The
`jniLibs.srcDir("engine")` above is an ABSENT directory until
`fetch-engine.sh` runs, and gradle is happy with that: `assembleDebug`
and `testDebugUnitTest` both go green on a checkout that has never
seen cargo-ndk. So typechecking a Kotlin change costs the SDK install
and nothing else. You only need the cargo-ndk chain to produce an APK
whose on-device engine actually runs.

`:app:lintDebug` is NOT part of `assembleDebug`, so it has to be asked
for by name:

```sh
./gradlew :app:lintDebug
```

It is green: 0 errors and 17 warnings as of 27 Aug 2026, read off the
CI runner's own `lint-results-debug.xml` rather than a local run - `8x
UseKtx`, `4x GradleDependency`, `2x NewerVersionAvailable`, `1x
AndroidGradlePluginVersion`, `1x OldTargetApi`, `1x
MissingApplicationIcon`. Two of those are worth knowing about: the
`OldTargetApi` hold is explained in the workflow header (targeting 35
caps dataSync foreground services, which `EngineService` would hit),
and `MissingApplicationIcon` is real - no `android:icon` and no `res/`
directory, so the launcher draws the generic default. It was
red from 6 Aug with 6 errors, all from `0324c3c3` (PiP and player),
and both fixes are worth knowing before you touch either file:

- `MissingSuperCall` at `MainActivity.onUserLeaveHint`. The override
  entered PiP and returned without chaining, which drops whatever the
  platform does on that callback for every screen that is NOT the
  player. Fixed by calling `super.onUserLeaveHint()` first.
- Five `UnsafeOptInUsageError` in `PlayerScreen`, all of them
  `PlayerView` calls inside the `AndroidView` factory and update
  lambdas: `setShowNextButton`, `setShowPreviousButton`,
  `setShowFastForwardButton`, `setShowRewindButton`, and the
  `DefaultTimeBar` lookup that gates scrubbing. media3 ships those
  outside its stable surface, so each one needs an explicit opt-in.
  Taken once for the whole composable, as
  `@androidx.annotation.OptIn(UnstableApi::class)` on `PlayerScreen` -
  fully qualified because the unqualified `OptIn` is Kotlin's own
  annotation and the two are not interchangeable. Note that lint flags
  the CALLS, not the types: `ExoPlayer.Builder` and the `PlayerView`
  constructor a few lines above drew nothing, so counting `@UnstableApi`
  classes will not tell you how many errors to expect.

`lintVitalRelease`, which `assembleRelease` does run, was clean
throughout - a red `lintDebug` was never a broken build. Lint needs no
NDK and no engine binary either, same as `assembleDebug` above.

Gradle is pinned by the wrapper (8.13, AGP 8.11.1, Kotlin 2.1.21) -
build through `./gradlew`, not a system gradle. The debug APK is
signed with the standard debug keystore; nothing here is a release
artifact.

The on-device engine binds 127.0.0.1 on a port the OS picks
(`--port 0`), and reports which one in `runtime.json` beside its config
in app-private storage; nothing in the app holds a port constant. It
used to bind a fixed 6791, and every app on a phone shares ONE loopback
namespace, so a predictable port is a port a sibling app can pre-bind
before the engine gets there (TODO 158 item 4). Identity is proved by
the `runtime.json` token, not by the port - see `EngineIdentity` - but
a port nobody can name in advance is one nobody can lie in wait on. The
service also sets `NZBFAST_PORT_LOCKED=1`, so a `port` saved from the
daemon's own embedded dashboard cannot pin the listener back to one
fixed number.

The consequence for debugging: `adb forward`/`adb reverse` need the
port of the moment, so read it rather than assuming one -
`adb shell run-as app.nzbfast.mobile cat files/config/runtime.json`.
