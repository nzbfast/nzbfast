import AppKit
import SwiftUI

/// The one rule that decides what a SAVED window frame turns into on the
/// screens attached right now. A pure function, deliberately.
///
/// The rule is written down in `apps/parfast/shared/design/window-frame.md`
/// and this is its reference implementation; the C# port is
/// `apps/parfast/windows/Parfast.ViewModels/WindowFrameRule.cs`. Do not
/// re-derive it in either place - change the shared document and both ports.
///
/// WHY IT IS PURE: every interesting case is a case no test box can produce.
/// A monitor cannot be unplugged in CI, a display cannot change resolution
/// between two launches of a unit test, and a window server is not running on
/// the machine this suite runs on at all. So the part that will actually be
/// got wrong - what happens to a frame whose screen has gone - is a function
/// over rectangles, and `WindowFrameRuleTests` is where it is pinned.
enum WindowFrameRule {

    /// What the caller should do with the window.
    struct Outcome: Equatable {
        /// The frame to apply. When `placeByOS` is set, only its SIZE is
        /// meaningful and its origin is zero.
        var frame: CGRect
        /// The saved origin named no attached screen, so the OS places it.
        var placeByOS: Bool
        /// The window was zoomed when it was saved and should be zoomed again.
        var zoomed: Bool
    }

    /// The smallest slice of a window that counts as "on this screen". A frame
    /// that overlaps a work area by less than this is not reachable in any
    /// useful sense - there is nothing to grab - so it is treated as off
    /// screen and recovered rather than honoured.
    static let grabSize = CGSize(width: 120, height: 32)

    /// - Parameters:
    ///   - saved: the saved outer frame.
    ///   - zoomed: whether the window was zoomed when it was saved.
    ///   - workAreas: `visibleFrame` of every attached screen, PRIMARY FIRST.
    ///   - minSize: the window's minimum size.
    static func recover(saved: CGRect, zoomed: Bool,
                        workAreas: [CGRect], minSize: CGSize) -> Outcome {
        // A rule that cannot see its subject must not invent an answer.
        guard let primary = workAreas.first else {
            return Outcome(frame: saved, placeByOS: false, zoomed: zoomed)
        }

        let hit = targetScreen(for: saved, in: workAreas)
        let target = hit ?? primary
        let lost = hit == nil

        // Zoomed is a STATE, not a size: the frame that comes back is the
        // target screen's work area, whatever was saved, and the caller zooms.
        if zoomed {
            return Outcome(frame: target, placeByOS: false, zoomed: true)
        }

        // Clamp to the work area, then floor at the minimum. The floor wins,
        // and can exceed the work area on a very small display: a window below
        // its own minimum is a layout this app has no design for.
        let maxW = max(minSize.width, target.width)
        let maxH = max(minSize.height, target.height)
        let width = max(min(saved.width, maxW), minSize.width)
        let height = max(min(saved.height, maxH), minSize.height)

        // The origin is the ONLY thing an absent screen costs. Never the size:
        // losing a deliberate choice because of a cable is the defect this
        // whole function exists to prevent.
        if lost {
            return Outcome(frame: CGRect(x: 0, y: 0, width: width, height: height),
                           placeByOS: true, zoomed: false)
        }

        let x = max(target.minX, min(saved.minX, target.maxX - width))
        let y = max(target.minY, min(saved.minY, target.maxY - height))
        return Outcome(frame: CGRect(x: x, y: y, width: width, height: height),
                       placeByOS: false, zoomed: false)
    }

    /// The attached work area the saved frame overlaps most, by geometry
    /// rather than by a stored display id - an id is not stable across an
    /// unplug, a dock or a driver update, and a rectangle is.
    private static func targetScreen(for saved: CGRect, in workAreas: [CGRect]) -> CGRect? {
        let needW = min(grabSize.width, saved.width)
        let needH = min(grabSize.height, saved.height)
        var best: CGRect?
        var bestArea: CGFloat = 0
        for area in workAreas {
            let hit = area.intersection(saved)
            guard !hit.isNull, hit.width >= needW, hit.height >= needH else { continue }
            let score = hit.width * hit.height
            if score > bestArea {
                bestArea = score
                best = area
            }
        }
        return best
    }
}

/// Persistence for the ONE window: it attaches the frame autosave, applies
/// `WindowFrameRule` over whatever came back, and carries the zoomed flag that
/// autosave does not.
///
/// `setFrameAutosaveName` rather than a hand-rolled `UserDefaults` frame,
/// deliberately: it writes on every move and resize, so a force quit or
/// "close windows when quitting an app" loses nothing, and it is the piece
/// macOS's implicit restoration was standing in for. Implicit restoration is
/// what this app had until 12 Sep 2026, and it looked like it worked, which is
/// worse than plainly not working - it stops in exactly the cases nobody
/// tests.
@MainActor
enum MainWindowFrame {
    /// Namespaced so it cannot collide with a SwiftUI scene's own restoration
    /// key. Changing it silently forgets everybody's window once.
    static let autosaveName = "parfast.main.window"
    private static let zoomedKey = "parfast.main.window.zoomed"

    private static var observers: [NSObjectProtocol] = []
    private static var suspended = false

    /// Attaches persistence to the main window, restoring the saved frame.
    ///
    /// Called from `WindowFrameAccessor`, which is the supported way to reach
    /// the NSWindow behind a SwiftUI `Window` scene. Idempotent: the accessor
    /// can be asked more than once as the view is rebuilt.
    static func attach(to window: NSWindow) {
        // A screenshot run must never leave its geometry behind as somebody's
        // window (shared/design/window-frame.md, "What must not persist").
        guard !suspended, !DemoRoute.screenshotModeAllowed else { return }
        guard window.frameAutosaveName != autosaveName else { return }

        let wantZoom = UserDefaults.standard.bool(forKey: zoomedKey)
        // Restores the saved frame if there is one, and does nothing on a
        // first run - where the window already carries `.defaultSize`.
        _ = window.setFrameAutosaveName(autosaveName)
        apply(to: window, zoomed: wantZoom)
        observe(window)
    }

    /// Stops this process persisting anything further, and detaches the
    /// autosave so the geometry a shoot sets is not written.
    static func suspend() {
        suspended = true
        for token in observers { NotificationCenter.default.removeObserver(token) }
        observers = []
        for window in NSApp.windows where window.frameAutosaveName == autosaveName {
            window.setFrameAutosaveName("")
        }
    }

    /// Runs the recover rule over the frame AppKit handed back.
    ///
    /// Always, not only when a frame was restored: the rule is also the
    /// guard that a restored frame cannot defeat the work-area clamp from
    /// `16f8a622c1`, and running it on a first-run window is a no-op because
    /// `defaultWindowSize` already fits.
    private static func apply(to window: NSWindow, zoomed: Bool) {
        let areas = workAreas()
        let out = WindowFrameRule.recover(
            saved: window.frame, zoomed: zoomed, workAreas: areas,
            minSize: CGSize(width: T.sizeWindowMinWidth, height: T.sizeWindowMinHeight))

        if out.placeByOS {
            window.setFrame(CGRect(origin: window.frame.origin, size: out.frame.size),
                            display: false)
            window.center()
        } else {
            window.setFrame(out.frame, display: false)
        }

        // The frame is already the target screen's work area, so the window
        // reads as zoomed and there is normally nothing to toggle. The call is
        // for the case where AppKit disagrees about what "zoomed" means on
        // this screen.
        if out.zoomed, !window.isZoomed {
            window.zoom(nil)
        }
    }

    /// `visibleFrame` of every screen, PRIMARY FIRST, which is the order
    /// `WindowFrameRule` documents. `NSScreen.screens[0]` IS the primary - the
    /// screen whose frame has its origin at zero, the one the menu bar is on -
    /// so the AppKit order is already the order the rule wants.
    ///
    /// `visibleFrame` and not `frame`: it already excludes the menu bar and the
    /// Dock, wherever the user keeps the Dock, which is what makes it the
    /// "work area" the rule is written against.
    private static func workAreas() -> [CGRect] {
        NSScreen.screens.map(\.visibleFrame)
    }

    /// The zoomed flag, written on every geometry change rather than at quit,
    /// so a force quit keeps it - the same property autosave gives the frame.
    private static func observe(_ window: NSWindow) {
        let centre = NotificationCenter.default
        for name in [NSWindow.didResizeNotification, NSWindow.didMoveNotification,
                     NSWindow.didEndLiveResizeNotification] {
            let token = centre.addObserver(forName: name, object: window, queue: .main) { note in
                guard let win = note.object as? NSWindow else { return }
                MainActor.assumeIsolated {
                    guard !suspended else { return }
                    // Full screen is a third state and is not persisted: its
                    // frame would be the whole display, which step 3 of the
                    // rule then clamps back down to the work area anyway.
                    guard !win.styleMask.contains(.fullScreen) else { return }
                    UserDefaults.standard.set(win.isZoomed, forKey: zoomedKey)
                }
            }
            observers.append(token)
        }
    }
}

/// The bridge from the SwiftUI `Window` scene to its NSWindow.
///
/// A `Window` scene hands out no window reference, so the documented routes are
/// an `NSViewRepresentable` that reads `view.window` or the AppDelegate. The
/// representable is used because it fires when the view is IN a window, which
/// the delegate's launch callbacks do not guarantee for a SwiftUI scene.
///
/// The `DispatchQueue.main.async` is load-bearing: inside `makeNSView` the view
/// has no window yet, so reading it there returns nil every time.
struct WindowFrameAccessor: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        DispatchQueue.main.async {
            if let window = view.window { MainWindowFrame.attach(to: window) }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}
