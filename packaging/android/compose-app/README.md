# nzbfast for Android (Jetpack Compose)

The native Android app: Material 3, dark-first, playback-first. One
UI, two sources - "this device" runs the bundled slim engine on the
phone (exec'd from nativeLibraryDir, same mechanism as the test APK in
`../app`); "my server" points the same screens at an nzbfast daemon
you already run. The player is Media3 ExoPlayer on the daemon's
/stream endpoint, so Matroska plays with hardware decode and range
seeks.

Screens: Connect (mode picker + first-run news-server form), Home
(active jobs with live progress, a "Play test preview" button the
moment the daemon says the file is readable, then history; swipe to
pause/resume/delete), Add (document picker, nzblnk paste, and
share-target for .nzb files and nzblnk links).

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

Tests: `./gradlew :app:testDebugUnitTest`.

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

It is green as of 23 Aug 2026 (0 errors, 14 warnings; the warnings are
dependency-freshness and manifest notes, not this app's code). It was
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
