# nzbfast iOS app

A native SwiftUI downloader. TWO SOURCES since TODO 281 IO1: the engine
runs on this phone (`crates/nzbfast-ffi` linked in as a staticlib,
serving 127.0.0.1 from a thread of the app's own process), or on an
nzbfast the user already runs elsewhere. Both are bring-your-own-server;
neither has an indexer, a search box or any content in it, which is the
posture `research/PLAN-MOBILE-DOWNLOADER-2026-08-24.md` rests on.
Simulator-only for now - building and running needs no Apple developer
identity.

The app is Downloads (the queue, and the headline), Add, History, one
Settings sheet and the player. NO WebView anywhere, deliberately: the
engine still compiles the web dashboard in, but nothing in this app
points at it. The A3 spike harness at the bottom of this file does, and
it is a throwaway.

## Requirements

- Xcode 16 or newer (project uses folder-synchronized groups), and an
  iOS Simulator RUNTIME. Xcode does not necessarily ship with one and
  an Xcode upgrade can leave you without: `xcrun simctl list runtimes`
  printing an empty list is what that looks like, and
  `xcodebuild -downloadPlatform iOS` fixes it (8.5 GB, no Apple ID).
  Without a runtime the project still BUILDS - the SDK is there - so
  the first sign is that no device can be booted.
- A Rust toolchain with the iOS targets: `rustup target add
  aarch64-apple-ios-sim aarch64-apple-ios`. The "Build nzbfast-ffi"
  build phase runs `packaging/ios/build-ffi.sh`, which maps
  Xcode's PLATFORM_NAME/ARCHS onto one of those and leaves
  `libnzbfast_ffi.a` where LIBRARY_SEARCH_PATHS expects it. The
  staticlib is built RELEASE whatever the app configuration is: a debug
  build of yEnc and PAR2 is unusably slow, and those are the product.
- Network access on first build: the VLCKit xcframework resolves via
  Swift Package Manager (tylerjonesio/vlckit-spm 3.6.0, checksum
  pinned in the package).

## Build and run (Simulator)

```sh
cd packaging/ios
xcodebuild -project NzbfastMobile.xcodeproj -scheme NzbfastMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

Or open `NzbfastMobile.xcodeproj` in Xcode and run on any iPhone
simulator. Install and launch from the command line:

```sh
xcrun simctl install booted <path-to>/NzbfastMobile.app
xcrun simctl launch booted com.nzbfast.mobile
```

## Where things live on the device

Two directories, and `nzbfast_start` takes them separately for this
reason:

- **Documents** - finished downloads, and nothing else. `Info.plist`
  declares `UIFileSharingEnabled`, so the Files app shows this folder
  and a finished job needs no export step. That is the opposite of the
  Android answer, where a SAF document tree has no `pwrite` and no
  preallocation so the payload is copied out afterwards.
- **Application Support/nzbfast** - `config.local.json`,
  `settings.json`, `runtime.json`, `passwords.txt`, `.spool`. Engine
  state, excluded from backup, and never in front of the user.

The engine is started with `--port 0` so the OS picks a free port, and
the app reads it back out of `runtime.json`. That file is DELETED before
the start, and its `pid` is checked against the app's own: the engine
runs inside this process, so a record that matches is one this run
wrote. A per-install API key is minted and required, because app
sandboxing does not extend to 127.0.0.1 - another app on the phone can
reach the listener.

## Test rig

Run a daemon on the Mac; the Simulator reaches the host's localhost
directly:

```sh
NZBFAST_NO_ENRICH=1 nzbfast serve --port 7789 --bind 127.0.0.1 \
  --apikey <key> --config <config-with-local-chaos-servers>
```

Connect the app to `http://127.0.0.1:7789` with that key. For a
playable job, post a real media file through a local mock NNTP server
(`nzbfast chaos-serve --profile clean`, then `nzbfast post file.mp4
--post-server 127.0.0.1:<port>`) and add the generated NZB to the
daemon.

## Headless QA

`simctl openurl` on a custom scheme raises an "Open in app?" dialog
nothing headless can tap, and it parks at SpringBoard level until a
restart. Use `-qaurl` launch arguments instead: they land in the
UserDefaults arguments domain, and `qaurl` / `qaurl2` / `qaurl3` /
`qaurl4` are run IN ORDER, awaited one at a time, so a sequence that
needs its steps to complete in turn works. DEBUG builds only.

```sh
C=$(xcrun simctl get_app_container <dev> com.nzbfast.mobile data)
cp job.nzb "$C/Documents/"
xcrun simctl launch --terminate-running-process <dev> com.nzbfast.mobile \
  -qaurl  "nzbfast://qa/device" \
  -qaurl2 "nzbfast://qa/server?host=127.0.0.1&port=1190&tls=0&user=u&pass=p&conns=8" \
  -qaurl3 "nzbfast://qa/addfile?path=$C/Documents/job.nzb"
```

`--terminate-running-process` is load-bearing: a plain `launch` on a
running app FOREGROUNDS it without restarting, so the arguments are
never re-read and the links silently do nothing.

Links: `/device`, `/server`, `/addfile`, `/connect`, `/addurl`, `/play`,
`/stopplay`, `/pause`, `/resume`, `/tab`, `/stopengine`, `/disconnect`.

Two more launch arguments drive the LIFECYCLE seam (DEBUG builds only,
added 27 Aug 2026 for TODO 281 IO2 finding C28 - see
`research/IOS-LIFECYCLE-QA-2026-08-27.md` for the runs they came from):

- `-qaActivityDelayMs <n>` stalls every ActivityKit call by n
  milliseconds.
- `-qaGraceSeconds <n>` forces the finish-in-flight grace budget to n
  seconds instead of asking `backgroundTimeRemaining`.

Both exist because the SIMULATOR CANNOT REACH THE CASE THE CODE IS FOR,
and that is worth knowing before reading any lifecycle result off it.
Measured 27 Aug 2026: a backgrounded Simulator app is NOT suspended - an
ActivityKit update stalled by 30 s was still delivered 30 s after the
background assertion had ended - and `backgroundTimeRemaining` never
answers a short budget there, so the wind-down's own quiet loop ran ~10 s
past the final update and the ordering came out right whether or not
anything waited for it. Forcing both is what puts them in the order a
phone with a second left on the clock puts them.

`LiveProgress` writes a timestamped journal of what it actually
published to `Documents/liveactivity-qa.log`, plus the two grace
boundaries, the audio-session ownership edges and the catch-up window's
own steps. It is the only witness available for any of them: an
`Activity` cannot be read from another process, the Simulator has no
lock screen a screenshot could catch, and nothing else says whether the
process hold was claimed. Read it with the app's data container:

```sh
C=$(xcrun simctl get_app_container <dev> com.nzbfast.mobile data)
cat "$C/Documents/liveactivity-qa.log"
```

The shape a healthy wind-down leaves, and the ONE thing to check - the
Held line must come before the two grace lines, and nothing may follow
it:

```
1787852003.683 delivered held=1 reason=Held while nzbfast is in the ...
1787852017.143 grace wind-down-returned
1787852017.144 grace assertion-ended
```

Three more traps, all measured 27 Aug 2026 and all of the shape where
the wrong answer LOOKS like a working one:

- The per-install API key is written through `UserDefaults`, which
  flushes to the preferences plist LAZILY - several seconds after the
  engine is already up and answering. A `plutil -extract` run straight
  after launch reports the key missing against an app that has one.
  Poll for it rather than reading once.
- THE PORT CHANGES ON EVERY RELAUNCH, because `--terminate-running-process`
  restarts the engine and the OS picks a new one. A read of
  `runtime.json` that lands DURING the restart returns the PREVIOUS
  run's port, and every later call then talks to a dead port and
  reports the app broken. Resolve it by checking `mode=version`
  actually answers on the port the record names, not by reading the
  record once.
- `xcrun simctl install` over an installed app can ROTATE THE DATA
  CONTAINER, taking the queue, the history and the minted key with it.
  Re-read `get_app_container` after every install rather than caching
  the path.

To BACKGROUND the app headlessly there is no simctl command and no
Home button to press: launch a different app (`xcrun simctl launch
<dev> com.apple.Preferences`) and ours goes to the background behind
it. A plain `xcrun simctl launch <dev> com.nzbfast.mobile` brings it
back - which is the same "foregrounds without re-reading arguments"
behaviour that makes `--terminate-running-process` load-bearing above,
used deliberately here.

To watch the on-device engine from the Mac, read its port out of the
container and use the key from the app's preferences. The dots in that
key path have to be escaped or `plutil -extract` reports "no value at
that key path" against a key that is plainly there:

```sh
PORT=$(python3 -c "import json;print(json.load(open('$C/Library/Application Support/nzbfast/runtime.json'))['port'])")
KEY=$(plutil -extract 'nzbfast\.device\.apikey' raw "$C/Library/Preferences/com.nzbfast.mobile.plist")
curl -s -H "X-Api-Key: $KEY" "http://127.0.0.1:$PORT/api?mode=playback&output=json"
```

## Notes

- The player is VLCKit because most real posts are Matroska and
  AVPlayer refuses the container.
- All playback copy stays under the "test preview" framing.
- Info.plist allows arbitrary HTTP loads for development (local
  daemons are plain http); tighten before any store build.
- Share-sheet registration for .nzb files is deferred to P2.
- Backgrounding, the Live Activity and the memory budget are TODO 281
  IO2 and IO2b - see "What happens when you switch away" below.
- THE ENGINE THIS APP LINKS HAS NO WEB UI, and that is deliberate
  (TODO 281 IO3b, 28 Aug 2026). `nzbfast-ffi` builds nzbfast with
  `default-features = false`, and the `dashboard` feature that carries
  the two shells, the i18n catalogues, the manuals, the stylesheet and
  the favicons is a DEFAULT one - so `/`, `/manual`, `/i18n/*.json`,
  `/site.webmanifest`, `/custom.css`, the favicons and `/wall` all
  answer 404 here while the API answers normally. Do not read that 404
  as a broken engine, and do not reach for the dashboard to debug this
  app: read the API with the curl recipe above. A desktop daemon still
  serves all of it, unchanged. If you ever need the pages inside the
  app for a one-off, build the staticlib with
  `--features nzbfast/dashboard` by hand - never by putting them back
  in the shipped configuration.

## What happens when you switch away

The honest matrix, and every one of these is implemented rather than
planned (TODO 281 IO2/IO2b):

1. **Watching keeps it downloading.** Playback and the engine are one
   process, so an app iOS keeps scheduled for playing real audio is an
   app whose NNTP sockets stay open. Start a file and the download runs
   at full speed with the screen off or the phone in a pocket.
   `Playback.swift` owns the session, the lock-screen transport, route
   changes and interruptions; `Lifecycle` reads `playbackHoldsProcess`
   and leaves the queue alone while it is true. THE SESSION IS ONLY EVER
   ACTIVE WHILE REAL MEDIA IS REALLY PLAYING - there is deliberately no
   entry point a caller with no audio could use, because a silent
   session held open to keep a download alive is the one move that gets
   an app removed.
2. **Keep-awake.** Plugged in on a shelf, a small always-on downloader.
   `ScreenAwake` arbitrates the idle timer between the setting and the
   player, so neither can turn the other off.
3. **Finish-in-flight grace.** `Lifecycle` takes a background assertion
   on the way out, pauses the queue GRACEFULLY (`mode=pause` with no
   arguments - "finish in-flight, keep the queue for resume", not the
   `value2=now` abort) and waits for the bytes to stop before letting go.
   What that buys is not more download time, it is a cheap STOP: a queue
   wound down to a quiet point resumes from its journal with nothing to
   redo.
4. **Opportunistic catch-up.** A `BGProcessingTask` asks for a window
   while charging and on wifi. Never guaranteed and NEVER PROMISED in
   the UI.
5. **Live Activity.** Lock screen and Dynamic Island, from the
   `NzbfastWidgets` extension. It FREEZES while the app is suspended,
   which is the truthful behaviour - and the grace pushes one final
   update saying the queue is held, so what the user finds frozen reads
   as "waiting for you" rather than as a bar that stopped for no reason.

PiP is NOT wired, and the reason is a library fact rather than a
decision: MobileVLCKit 3.6 has no picture-in-picture and no
sample-buffer output to feed an `AVPictureInPictureController` -
`drawable` takes a view or a layer, and a layer VLC renders into is not
one PiP can adopt. Grepping the shipped headers for
`PictureInPicture`/`SampleBuffer` returns nothing. The route is the A4
remux track (Matroska to fragmented MP4, pure Rust), which the plan
already names as the lane that upgrades VLCKit to AVPlayer and buys
AirPlay with it; PiP falls out of that for free. It is also not
verifiable here in any case -
`AVPictureInPictureController.isPictureInPictureSupported()` is false in
the Simulator.

## Memory, and what jetsam actually measures

The engine's own default budget is `MemBudget::auto` - a quarter of
physical RAM - which is a DESKTOP figure. Measured on the dev Mac it
comes out at the 16 GB ceiling. On a phone that is a budget for a
process the platform is willing to kill.

`nzbfast_start` therefore takes a fifth argument, `mem_limit_bytes`, and
`DeviceProfile.memLimitBytes()` fills it in: total RAM / 16, clamped to
192 MB .. 512 MB, the same rule the Android launcher passes as
`--mem-limit`. It is an ARGUMENT and not an environment variable
because it is a fact about the host platform like `out_dir` and `port`,
and one an embedder must not be able to forget silently; the reasoning
is at length in `nzbfast_start`'s doc comment. `NZBFAST_CPU_WORKERS` is
set alongside it from `hw.perflevel0.logicalcpu` - the performance
cluster - which is AN4's CPU half.

Two traps in reading a Simulator measurement:

- `physicalMemory` and `hw.perflevel0.logicalcpu` are the MAC'S. The
  memory clamp saves the budget half (a 512 GB box divides to 32 GB and
  clamps back to 512 MB, so the engine really is running a large phone's
  budget). The CPU half is not clamped, so the Simulator runs far more
  workers than a phone would - which makes its footprint an UPPER bound
  on the phone's rather than a matching figure.
- `os_proc_available_memory()` answers 0 in the Simulator, because a
  Simulator process has no jetsam limit to subtract from.
  `DeviceProfile.availableMemoryBytes()` reports that as nil, and nil
  means UNKNOWN and never "critical".

To read the engine's own figures, `mode=stats` carries
`host.rss_bytes` (phys_footprint - the number jetsam judges, not
resident size), `host.rss_peak_bytes` and `host.rss_budget`:

```sh
curl -s -H "X-Api-Key: $KEY" "http://127.0.0.1:$PORT/api?mode=stats&output=json" \
  | python3 -c "import json,sys;h=json.load(sys.stdin)['host'];print(h['rss_bytes'],h['rss_peak_bytes'],h['rss_budget'])"
```

`nzbkit::mem`'s `current_rss`, `dashboard_rss` and `trim` were
`cfg(target_os = "macos")` until IO2, so on iOS `dashboard_rss` fell all
the way through to `peak_rss` - the engine could not report its own
footprint on the one platform where a footprint gets you killed, and its
"current" reading was really a peak that never came down.

## A3 spike harness (in-process engine)

`HarnessApp.swift` + `build-harness.sh` are a THROWAWAY Simulator app
proving the engine runs in-process on iOS behind the C ABI in
`crates/nzbfast-ffi` (iOS forbids exec, so the Android child-process
shape does not transfer). Not a product app - the shell above is that;
it adopts the same staticlib for on-device mode.

```sh
packaging/ios/build-harness.sh
xcrun simctl install <device> packaging/ios/NZBFastHarness.app
xcrun simctl launch <device> com.nzbfast.spike-harness
```

The harness starts the engine on 127.0.0.1:8724 (the Simulator shares
the host's loopback - 6789 would collide with a dev Mac's live daemon)
and shows the dashboard it serves in a WKWebView. Details, sizes and
the aws-lc-rs verdict: `research/SPIKE-IOS-STATICLIB-2026-08-05.md`.
