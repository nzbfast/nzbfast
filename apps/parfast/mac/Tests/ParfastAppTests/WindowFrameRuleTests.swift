import XCTest
@testable import ParfastApp

/// The recover rule for a saved window frame, pinned over the screen layouts
/// that break it.
///
/// EVERY CASE HERE IS ONE NO TEST BOX CAN PRODUCE: a monitor unplugged between
/// two launches, a display whose resolution changed under a saved frame, a
/// window left on a screen that is now to the left of the primary instead of
/// the right. That is exactly why the rule is a function over rectangles - the
/// alternative is a feature whose interesting half is only ever exercised by a
/// user with two monitors and a complaint.
///
/// The rule is `apps/parfast/shared/design/window-frame.md`; the C# port is
/// pinned by the matching `Parfast.Tests/WindowFrameRuleTests.cs`.
final class WindowFrameRuleTests: XCTestCase {

    /// A 1920x1080 primary with the menu bar and Dock taken out, mac
    /// coordinates (y up, origin bottom-left).
    private let primary = CGRect(x: 0, y: 25, width: 1920, height: 1030)
    /// A 2560x1440 second display to the right of it.
    private let right = CGRect(x: 1920, y: 25, width: 2560, height: 1415)
    private let minSize = CGSize(width: 1000, height: 660)

    private func recover(_ saved: CGRect, zoomed: Bool = false,
                         screens: [CGRect]? = nil) -> WindowFrameRule.Outcome {
        WindowFrameRule.recover(saved: saved, zoomed: zoomed,
                                workAreas: screens ?? [primary], minSize: minSize)
    }

    // MARK: - the ordinary case

    /// A frame that still fits where it was saved comes back untouched. If this
    /// ever stops holding, the feature is not doing the one thing it is for.
    func testAFrameThatStillFitsIsReturnedUnchanged() {
        let saved = CGRect(x: 200, y: 120, width: 1400, height: 900)
        let out = recover(saved)
        XCTAssertEqual(out.frame, saved)
        XCTAssertFalse(out.placeByOS)
        XCTAssertFalse(out.zoomed)
    }

    // MARK: - the off-screen rule

    /// THE CASE THE WHOLE RULE EXISTS FOR: saved on a second monitor that is
    /// now unplugged. The SIZE is the user's deliberate choice and survives;
    /// only the origin is discarded.
    func testAnUnpluggedMonitorCostsTheOriginAndNotTheSize() {
        let saved = CGRect(x: 2400, y: 300, width: 1600, height: 1000)
        let out = recover(saved, screens: [primary])
        XCTAssertTrue(out.placeByOS)
        XCTAssertEqual(out.frame.size, CGSize(width: 1600, height: 1000))
        XCTAssertEqual(out.frame.origin, .zero, "placeByOS means the origin is not meaningful")
    }

    /// A frame that merely touches a screen by a sliver is NOT on it: there is
    /// no title bar to grab, so it recovers like an absent screen.
    func testASliverOfOverlapDoesNotCountAsOnScreen() {
        // 40 points of width inside the primary, well under the 120x32 grab.
        let saved = CGRect(x: 1880, y: 300, width: 1200, height: 800)
        let out = recover(saved, screens: [primary])
        XCTAssertTrue(out.placeByOS)
        XCTAssertEqual(out.frame.size, CGSize(width: 1200, height: 800))
    }

    /// And a grabbable slice IS on it, which is the other side of the same
    /// threshold. 200 points of width and the full height overlap here.
    func testAGrabbableSliceCountsAsOnScreen() {
        let saved = CGRect(x: 1720, y: 300, width: 1200, height: 700)
        let out = recover(saved, screens: [primary])
        XCTAssertFalse(out.placeByOS)
        // Pulled fully back on: the origin is clamped so the window fits.
        XCTAssertEqual(out.frame, CGRect(x: 720, y: 300, width: 1200, height: 700))
    }

    // MARK: - the work-area clamp

    /// A frame saved on a 4K panel, reopened on a 13in laptop. A restored
    /// frame does not get to defeat the clamp that landed in 16f8a622c1.
    func testASavedFrameIsClampedToTheScreenItOpensOn() {
        let laptop = CGRect(x: 0, y: 25, width: 1440, height: 875)
        let saved = CGRect(x: 0, y: 25, width: 2400, height: 1500)
        let out = recover(saved, screens: [laptop])
        XCTAssertEqual(out.frame, laptop, "clamped to the work area exactly")
        XCTAssertFalse(out.placeByOS)
    }

    /// The minimum size wins over the work area, deliberately: a window below
    /// its own minimum is a layout this app has no design for, so on a tiny
    /// display it is right to overflow.
    func testTheMinimumSizeWinsOverATinyWorkArea() {
        let tiny = CGRect(x: 0, y: 0, width: 800, height: 600)
        let out = recover(CGRect(x: 0, y: 0, width: 700, height: 500), screens: [tiny])
        XCTAssertEqual(out.frame.size, minSize)
    }

    /// Clamping the size must not then leave the window hanging off the right
    /// or the bottom.
    func testTheOriginIsPulledBackSoTheWholeWindowFits() {
        let saved = CGRect(x: 1500, y: 700, width: 1400, height: 900)
        let out = recover(saved)
        XCTAssertEqual(out.frame, CGRect(x: 520, y: 155, width: 1400, height: 900))
        XCTAssertLessThanOrEqual(out.frame.maxX, primary.maxX)
        XCTAssertLessThanOrEqual(out.frame.maxY, primary.maxY)
    }

    // MARK: - multi monitor

    /// The display the frame was saved on is preferred while it is attached,
    /// and it is chosen by GEOMETRY - no display id is stored, because an id
    /// is not stable across an unplug or a dock and a rectangle is.
    func testTheDisplayTheFrameWasSavedOnIsPreferred() {
        let saved = CGRect(x: 2200, y: 300, width: 1800, height: 1100)
        let out = recover(saved, screens: [primary, right])
        XCTAssertEqual(out.frame, saved)
        XCTAssertFalse(out.placeByOS)
    }

    /// A frame straddling two screens is pulled onto the one it is MOSTLY on,
    /// which is the stated cost of rule 4. Deliberate: keeping the straddle
    /// would mean clamping against a union of rectangles, and a window that
    /// spans a seam is a rarity next to the invariant rule 4 buys, which is
    /// that whatever comes back is wholly on a screen.
    func testAStraddlingFrameIsPulledOntoTheScreenItIsMostlyOn() {
        // 1400 wide starting 1700 into the primary: 220 points of it on the
        // primary, 1180 on the right-hand display.
        let saved = CGRect(x: 1700, y: 300, width: 1400, height: 900)
        let out = recover(saved, screens: [primary, right])
        XCTAssertEqual(out.frame, CGRect(x: 1920, y: 300, width: 1400, height: 900))
        XCTAssertFalse(out.placeByOS)
    }

    /// With the second display gone, that same frame falls back to the primary
    /// and keeps its size.
    func testWithTheSecondDisplayGoneItComesBackOntoThePrimary() {
        let saved = CGRect(x: 2200, y: 400, width: 1800, height: 1100)
        let out = recover(saved, screens: [primary])
        XCTAssertTrue(out.placeByOS)
        // Clamped to the primary's work area on the way, because it is bigger
        // than that screen.
        XCTAssertEqual(out.frame.size, CGSize(width: 1800, height: 1030))
    }

    // MARK: - zoomed

    /// Zoomed is a STATE, not a size: a window quit maximised reopens
    /// maximised, filling the work area of whichever screen it lands on.
    func testAZoomedWindowComesBackZoomedOnItsScreen() {
        let out = recover(right, zoomed: true, screens: [primary, right])
        XCTAssertTrue(out.zoomed)
        XCTAssertEqual(out.frame, right)
        XCTAssertFalse(out.placeByOS)
    }

    /// Zoomed on a display that has gone: still zoomed, now on the primary.
    /// The saved geometry is irrelevant here by construction, which is the
    /// point of treating it as a state.
    func testAZoomedWindowWhoseScreenIsGoneZoomsOnThePrimary() {
        let out = recover(right, zoomed: true, screens: [primary])
        XCTAssertTrue(out.zoomed)
        XCTAssertEqual(out.frame, primary)
    }

    // MARK: - degenerate

    /// No screens at all cannot happen on a running desktop, and a rule that
    /// cannot see its subject must not invent an answer.
    func testNoScreensReturnsTheSavedFrameUntouched() {
        let saved = CGRect(x: 10, y: 20, width: 300, height: 400)
        let out = recover(saved, screens: [])
        XCTAssertEqual(out.frame, saved)
        XCTAssertFalse(out.placeByOS)
    }
}
