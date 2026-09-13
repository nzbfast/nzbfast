# The remembered window: the recover rule both apps must agree on

parfast remembers the size and the position of its one window between runs,
so a user who makes it bigger keeps it bigger. `1120x720`
(`size.window_default_*`) is the FIRST-RUN size and nothing else.

Persisting a frame is easy. Handing a saved frame back safely is not, and the
part that will be got wrong is the same on both platforms, so it is written
down once here and ported twice:

- `apps/parfast/mac/Sources/ParfastApp/WindowFrame.swift` (`WindowFrameRule`),
  pinned by `Tests/ParfastAppTests/WindowFrameRuleTests.swift`
- `apps/parfast/windows/Parfast.ViewModels/WindowFrameRule.cs`, pinned by
  `Parfast.Tests/WindowFrameRuleTests.cs`

Both are PURE functions over (saved rect, maximised flag, the list of screen
work areas, a minimum size). No window server is needed to test them, which is
the whole point: a monitor cannot be unplugged in CI.

## The rule

Input: the saved outer frame, whether it was maximised (mac: zoomed), the work
areas of the screens attached RIGHT NOW with the primary first, and the
window's minimum size. All in one coordinate space and one unit: device pixels
on Windows, points on mac.

1. **Pick the target screen by geometry**, not by a stored display id. The
   target is the attached work area with the largest overlap with the saved
   frame, counting only an overlap big enough to grab: at least 120 x 32, or
   the saved frame's own size where that is smaller. A display id is not
   stable across an unplug, a dock, or a driver update; a rectangle is. A
   saved frame that still overlaps the display it was saved on therefore comes
   back to that display, and one that does not falls through to step 2.
2. **No overlapping screen means the ORIGIN is discarded, never the size.**
   The monitor was unplugged or the resolution changed. Keep the size the user
   chose, target the primary screen, and let the OS place the window
   (`center()` on mac, a plain resize with no move on Windows). Throwing the
   size away here is the bug this rule exists to prevent: the user loses a
   deliberate choice because of a cable.
3. **Clamp the size to the target work area**, then floor it at the minimum
   size. A restored frame is not allowed to defeat the work-area clamp that
   landed in `16f8a622c1`: a window saved on a 4K panel and reopened on a 13in
   laptop has to fit the laptop. The floor wins over the clamp when the two
   disagree, because a window below its own minimum is a layout neither app
   has a design for.
4. **Clamp the origin so the whole window is inside the target work area.**
   A window dragged half off the right edge comes back fully on screen. That
   costs a little fidelity and buys the invariant that matters: whatever comes
   back is wholly on a screen, and therefore reachable.
   STATED COST: a window deliberately left straddling two displays is pulled
   onto the one it is mostly on. Keeping the straddle would mean clamping
   against a union of rectangles rather than one, and a window spanning a seam
   is a rarity next to the invariant.
5. **Maximised is a state, not a size.** When the saved frame was maximised,
   the recovered frame is the target work area exactly and the maximised flag
   survives; the caller re-maximises after moving. Saving the restored bounds
   of a maximised window and reopening it un-maximised is a regression from
   the user's point of view.

With no screens in the list at all (which cannot happen on a running desktop),
the saved frame is returned untouched. A rule that cannot see its subject must
not invent an answer.

## What each app stores, and where

**mac.** `NSWindow.setFrameAutosaveName` does the frame half, which is why it
is used rather than a hand-rolled `UserDefaults` frame: it saves on every move
and resize, so a force quit loses nothing, and it already understands screens.
The NSWindow is reached from the SwiftUI `Window` scene through an
`NSViewRepresentable` in the root view's background. The recover rule runs
immediately AFTER the autosave restore, over whatever AppKit handed back, so
nothing here depends on AppKit's own screen remapping being right.

The zoomed flag is the one thing autosave does not carry, so it goes in
`UserDefaults` beside it.

STATED LIMIT: a window quit while zoomed comes back zoomed, and un-zooming it
then gives AppKit's standard frame rather than the size the user had before
zooming. Autosave writes the zoomed frame and there is no hook to make it
write the other one. The Windows port does keep the pre-maximise size, because
`AppWindow.Changed` hands it over for free.

A window quit in native full screen comes back as a large ordinary window
rather than full screen: step 3 clamps the full-screen frame down to the work
area, which is what stops it opening bigger than the display.

**Windows.** A JSON file, `%LOCALAPPDATA%\parfast\window.json`, beside the
queue store the app already keeps in that directory.

NOT `ApplicationData.Current.LocalSettings`, which is the shape a WinUI app
reaches for first. This app is `WindowsPackageType=None` - unpackaged and
self-contained - so it has no package identity, and `ApplicationData.Current`
is documented to need one. The probe that would settle it empirically wants a
Windows box, and choosing the file makes the question moot rather than
load-bearing: the directory is already created and written by
`MainWindow.QueueStorePath`, it works with or without identity, and it can be
deleted by hand to test the first-run path.

The saved bounds are the RESTORED (un-maximised) bounds, tracked from
`AppWindow.Changed` whenever the presenter reports `Restored`, so un-maximising
a restored window gives back the size the user actually had. They are written
on close and on a two-second debounce after any move or resize, so a kill does
not lose the frame either.

## What must not persist

The screenshot and demo routes set their own geometry so that a round of
pictures stays comparable with the round before it, and a shoot must not leave
its geometry behind as the user's window.

- mac: `DemoRoute` suspends persistence (it detaches the autosave name and the
  observers) the moment a `parfast://demo` URL is handled, and persistence is
  never attached at all under `PARFAST_SCREENSHOT=1`.
- Windows: `--shot` (`CommandLineOptions.IsScreenshot`) neither loads nor
  saves.
