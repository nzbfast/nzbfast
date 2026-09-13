using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The recover rule for a saved window frame, pinned over the display layouts
/// that break it.
/// </summary>
/// <remarks>
/// EVERY CASE HERE IS ONE NO TEST BOX CAN PRODUCE: a monitor unplugged between
/// two launches, a display whose resolution changed under a saved frame, a
/// window left on a display that is no longer attached. That is exactly why the
/// rule is a function over rectangles - the alternative is a feature whose
/// interesting half is only ever exercised by a user with two monitors and a
/// complaint.
/// <para>
/// Case for case with the Swift reference,
/// <c>apps/parfast/mac/Tests/ParfastAppTests/WindowFrameRuleTests.swift</c>, so
/// a divergence between the two ports shows up as a failing test on one side
/// rather than as two apps that behave differently on a dock. Coordinates are
/// WINDOWS-SHAPED here (y grows downward, the primary at the origin) and mac
/// shaped there, which is why the numbers differ while the cases do not.
/// </para>
/// </remarks>
public sealed class WindowFrameRuleTests
{
    /// <summary>A 1920x1080 primary with a 40px taskbar along the bottom.</summary>
    private static readonly WindowRect Primary = new(0, 0, 1920, 1040);

    /// <summary>A 2560x1440 second display to the right of it.</summary>
    private static readonly WindowRect Right = new(1920, 0, 2560, 1400);

    private const int MinW = 1000;
    private const int MinH = 660;

    private static WindowFrameOutcome Recover(
        WindowRect saved, bool maximised = false, params WindowRect[] screens) =>
        WindowFrameRule.Recover(saved, maximised,
            screens.Length == 0 ? [Primary] : screens, MinW, MinH);

    // ---- the ordinary case ----

    /// <summary>
    /// A frame that still fits where it was saved comes back untouched. If this
    /// ever stops holding, the feature is not doing the one thing it is for.
    /// </summary>
    [Fact]
    public void AFrameThatStillFitsIsReturnedUnchanged()
    {
        var saved = new WindowRect(200, 120, 1400, 900);
        var got = Recover(saved);
        Assert.Equal(saved, got.Bounds);
        Assert.False(got.PlaceByOS);
        Assert.False(got.Maximised);
    }

    // ---- the off-screen rule ----

    /// <summary>
    /// THE CASE THE WHOLE RULE EXISTS FOR: saved on a second monitor that is now
    /// unplugged. The SIZE is the user's deliberate choice and survives; only
    /// the origin is discarded.
    /// </summary>
    [Fact]
    public void AnUnpluggedMonitorCostsTheOriginAndNotTheSize()
    {
        var got = Recover(new WindowRect(2400, 300, 1600, 1000), false, Primary);
        Assert.True(got.PlaceByOS);
        Assert.Equal(1600, got.Bounds.Width);
        Assert.Equal(1000, got.Bounds.Height);
        Assert.Equal(0, got.Bounds.X);
        Assert.Equal(0, got.Bounds.Y);
    }

    /// <summary>
    /// A frame that merely touches a display by a sliver is NOT on it: there is
    /// no title bar to grab, so it recovers like an absent display.
    /// </summary>
    [Fact]
    public void ASliverOfOverlapDoesNotCountAsOnScreen()
    {
        // 40px of width inside the primary, well under the 120x32 grab.
        var got = Recover(new WindowRect(1880, 300, 1200, 700), false, Primary);
        Assert.True(got.PlaceByOS);
        Assert.Equal(1200, got.Bounds.Width);
        Assert.Equal(700, got.Bounds.Height);
    }

    /// <summary>And a grabbable slice IS on it, the other side of the threshold.</summary>
    [Fact]
    public void AGrabbableSliceCountsAsOnScreen()
    {
        var got = Recover(new WindowRect(1720, 300, 1200, 700), false, Primary);
        Assert.False(got.PlaceByOS);
        Assert.Equal(new WindowRect(720, 300, 1200, 700), got.Bounds);
    }

    // ---- the work-area clamp ----

    /// <summary>
    /// A frame saved on a 4K panel, reopened on a 13in laptop. A restored frame
    /// does not get to defeat the clamp that landed in 16f8a622c1.
    /// </summary>
    [Fact]
    public void ASavedFrameIsClampedToTheDisplayItOpensOn()
    {
        var laptop = new WindowRect(0, 0, 1440, 860);
        var got = Recover(new WindowRect(0, 0, 2400, 1500), false, laptop);
        Assert.Equal(laptop, got.Bounds);
        Assert.False(got.PlaceByOS);
    }

    /// <summary>
    /// The minimum size wins over the work area, deliberately: a window below
    /// its own minimum is a layout this app has no design for, so on a tiny
    /// display it is right to overflow.
    /// </summary>
    [Fact]
    public void TheMinimumSizeWinsOverATinyWorkArea()
    {
        var tiny = new WindowRect(0, 0, 800, 600);
        var got = Recover(new WindowRect(0, 0, 700, 500), false, tiny);
        Assert.Equal(MinW, got.Bounds.Width);
        Assert.Equal(MinH, got.Bounds.Height);
    }

    /// <summary>
    /// Clamping the size must not then leave the window hanging off the right
    /// or the bottom.
    /// </summary>
    [Fact]
    public void TheOriginIsPulledBackSoTheWholeWindowFits()
    {
        var got = Recover(new WindowRect(1500, 700, 1400, 900));
        Assert.Equal(new WindowRect(520, 140, 1400, 900), got.Bounds);
        Assert.True(got.Bounds.Right <= Primary.Right);
        Assert.True(got.Bounds.Bottom <= Primary.Bottom);
    }

    // ---- multi monitor ----

    /// <summary>
    /// The display the frame was saved on is preferred while it is attached, and
    /// it is chosen by GEOMETRY - no display id is stored, because an id is not
    /// stable across an unplug or a dock and a rectangle is.
    /// </summary>
    [Fact]
    public void TheDisplayTheFrameWasSavedOnIsPreferred()
    {
        var saved = new WindowRect(2200, 200, 1800, 1100);
        var got = Recover(saved, false, Primary, Right);
        Assert.Equal(saved, got.Bounds);
        Assert.False(got.PlaceByOS);
    }

    /// <summary>
    /// A frame straddling two displays is pulled onto the one it is MOSTLY on,
    /// which is the stated cost of rule 4. Deliberate: keeping the straddle
    /// would mean clamping against a union of rectangles, and a window that
    /// spans a seam is a rarity next to the invariant rule 4 buys, which is that
    /// whatever comes back is wholly on a display.
    /// </summary>
    [Fact]
    public void AStraddlingFrameIsPulledOntoTheDisplayItIsMostlyOn()
    {
        // 1400 wide starting 1700 into the primary: 220px of it on the primary,
        // 1180 on the right-hand display.
        var got = Recover(new WindowRect(1700, 300, 1400, 900), false, Primary, Right);
        Assert.Equal(new WindowRect(1920, 300, 1400, 900), got.Bounds);
        Assert.False(got.PlaceByOS);
    }

    /// <summary>
    /// With the second display gone, that same frame falls back to the primary
    /// and keeps its size.
    /// </summary>
    [Fact]
    public void WithTheSecondDisplayGoneItComesBackOntoThePrimary()
    {
        var got = Recover(new WindowRect(2200, 200, 1800, 1100), false, Primary);
        Assert.True(got.PlaceByOS);
        Assert.Equal(1800, got.Bounds.Width);
        // Clamped to the primary's work area on the way, being taller than it.
        Assert.Equal(1040, got.Bounds.Height);
    }

    // ---- maximised ----

    /// <summary>
    /// Maximised is a STATE, not a size: a window quit maximised reopens
    /// maximised, filling the work area of whichever display it lands on.
    /// </summary>
    [Fact]
    public void AMaximisedWindowComesBackMaximisedOnItsDisplay()
    {
        var got = Recover(Right, true, Primary, Right);
        Assert.True(got.Maximised);
        Assert.Equal(Right, got.Bounds);
        Assert.False(got.PlaceByOS);
    }

    /// <summary>
    /// Maximised on a display that has gone: still maximised, now on the
    /// primary. The saved geometry is irrelevant here by construction, which is
    /// the point of treating it as a state.
    /// </summary>
    [Fact]
    public void AMaximisedWindowWhoseDisplayIsGoneMaximisesOnThePrimary()
    {
        var got = Recover(Right, true, Primary);
        Assert.True(got.Maximised);
        Assert.Equal(Primary, got.Bounds);
    }

    // ---- degenerate ----

    /// <summary>
    /// No displays at all cannot happen on a running desktop, and a rule that
    /// cannot see its subject must not invent an answer.
    /// </summary>
    [Fact]
    public void NoDisplaysReturnsTheSavedFrameUntouched()
    {
        var saved = new WindowRect(10, 20, 300, 400);
        var got = WindowFrameRule.Recover(saved, false, [], MinW, MinH);
        Assert.Equal(saved, got.Bounds);
        Assert.False(got.PlaceByOS);
    }
}
