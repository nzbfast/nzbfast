# parfast for macOS

The SwiftUI front end over the PAR2 engine, plan
`research/PLAN-PARFAST-GUI-2026-09-12.md` (TODO 342), chip B.

```sh
swift build && swift test     # 67 tests, no app bundle needed
./make-app.sh                 # universal build/parfast.app
ARCH=arm64 ./make-app.sh      # this Mac only, for a quick loop
./Tools/generate.py --check   # the shared tables are current
./Tools/shoot.sh out/         # the screenshot set, light and dark
```

No Xcode project files, the `macapp/` precedent: a `Package.swift`, a
`make-app.sh` that assembles and ad-hoc signs the bundle, and an iconset
generated at build time and never committed.

## Shape

| Target | What |
|---|---|
| `ParfastCore` | The FFI contract as Swift types (plan 4.5), the `CoreClient` protocol, `MockCore` and its scenarios, the create planner the mock answers previews with. No SwiftUI. |
| `ParfastApp` | Every view and view model. A library, so the tests can reach it. |
| `Parfast` | A three-line executable shim over `ParfastApp`. |
| `ParfastAppTests` | The contract, the planner, the mock and the view models. |

`apps/parfast/shared/` is the cross-platform half and this chip owns it:
`strings/en.json` is the copy table, `design/tokens.json` the palette,
`icon/make-icon-master.py` the app icon. `Tools/generate.py` turns the first
two into `Sources/ParfastApp/Generated/{Strings,Tokens}.swift` plus a string
catalogue; the generated files are COMMITTED so `swift build` needs no
python, and `--check` refuses a stale copy. The Windows lane (chip C) reads
the same two files and proposes additions by handoff, never by editing.

## Mock first

The app runs against `MockCore` until `apps/parfast/crates/parfast-ffi`
lands (plan 3.3; the crates sit in a detached workspace of their own so
nothing the GUI is made of reaches the public repo - plan 4.4, decision D2a). Every screen, state and error path in plan section 5 is reachable
from the scripted scenarios in `Sources/ParfastCore/MockScenarios.swift`, at
an adjustable speed, with no PAR2 file on disk. Switching to the real engine
is one line in `App.swift` plus an `FfiCore.swift`; nothing above
`CoreClient` knows which core it is talking to.

A mock build says so where it cannot be missed: Settings > Performance reads
`MockCore (no engine linked)` and the version is `1.5.0-mock`.

The `Demo` menu and the `parfast://demo?...` URL exist only while the core is
a `MockCore` - `DemoRoute` checks the concrete type, so a build against the
real engine has no such route at all.
