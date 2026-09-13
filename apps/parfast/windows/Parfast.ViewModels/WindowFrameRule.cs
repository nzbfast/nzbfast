namespace Parfast.ViewModels;

/// <summary>A rectangle in one coordinate space: device pixels on Windows.</summary>
public readonly record struct WindowRect(int X, int Y, int Width, int Height)
{
    public int Right => X + Width;

    public int Bottom => Y + Height;

    /// <summary>The overlap with another rectangle, or a zero-sized one.</summary>
    public WindowRect Intersect(WindowRect other)
    {
        var x = Math.Max(X, other.X);
        var y = Math.Max(Y, other.Y);
        var w = Math.Min(Right, other.Right) - x;
        var h = Math.Min(Bottom, other.Bottom) - y;
        return w <= 0 || h <= 0 ? new WindowRect(0, 0, 0, 0) : new WindowRect(x, y, w, h);
    }

    public long Area => (long)Math.Max(0, Width) * Math.Max(0, Height);
}

/// <summary>What the caller should do with the window.</summary>
/// <param name="Bounds">
/// The bounds to apply. When <paramref name="PlaceByOS"/> is set only the SIZE
/// is meaningful and the origin is zero.
/// </param>
/// <param name="Maximised">The window was maximised and should be maximised again.</param>
/// <param name="PlaceByOS">The saved origin named no attached display, so the OS places it.</param>
public readonly record struct WindowFrameOutcome(WindowRect Bounds, bool Maximised, bool PlaceByOS);

/// <summary>
/// What a SAVED window frame turns into on the displays attached right now.
/// A PORT, not a design.
/// </summary>
/// <remarks>
/// The rule is written down in <c>apps/parfast/shared/design/window-frame.md</c>
/// and the reference implementation is
/// <c>apps/parfast/mac/Sources/ParfastApp/WindowFrame.swift</c>. This file is
/// that implementation in C#, function for function, so a window saved on one
/// of these apps and a window saved on the other come back by the same rule.
/// Do not re-derive it here; change the shared document and both ports together.
/// <para>
/// WHY IT IS PURE, and why it lives in Parfast.ViewModels rather than beside the
/// window: every interesting case is a case no test box can produce. A monitor
/// cannot be unplugged between two launches of a unit test, a display cannot
/// change resolution mid-suite, and the suite runs on the dev Mac where there is
/// no <c>AppWindow</c> at all. The part that will actually be got wrong - what
/// happens to a frame whose display has gone - is therefore a function over
/// rectangles, pinned by <c>Parfast.Tests/WindowFrameRuleTests.cs</c>.
/// </para>
/// </remarks>
public static class WindowFrameRule
{
    /// <summary>
    /// The smallest slice of a window that counts as "on this display". A frame
    /// overlapping a work area by less than this is not reachable in any useful
    /// sense - there is nothing to grab - so it is recovered rather than
    /// honoured. In the same unit as everything else here: device pixels, so
    /// these are 100%-scaling figures and a 200% display gets a physically
    /// smaller slice, which is the right direction (the pixels are smaller too).
    /// </summary>
    public const int GrabWidth = 120;

    /// <summary>The height half of <see cref="GrabWidth"/>.</summary>
    public const int GrabHeight = 32;

    /// <param name="saved">The saved outer bounds.</param>
    /// <param name="maximised">Whether the window was maximised when it was saved.</param>
    /// <param name="workAreas">The work area of every attached display, PRIMARY FIRST.</param>
    /// <param name="minWidth">The window's minimum width, in the same unit.</param>
    /// <param name="minHeight">The window's minimum height, in the same unit.</param>
    public static WindowFrameOutcome Recover(
        WindowRect saved, bool maximised, IReadOnlyList<WindowRect> workAreas,
        int minWidth, int minHeight)
    {
        // A rule that cannot see its subject must not invent an answer.
        if (workAreas.Count == 0)
        {
            return new WindowFrameOutcome(saved, maximised, false);
        }

        var hit = TargetArea(saved, workAreas);
        var target = hit ?? workAreas[0];
        var lost = hit is null;

        // Maximised is a STATE, not a size: what comes back is the target
        // display's work area, whatever was saved, and the caller maximises.
        if (maximised)
        {
            return new WindowFrameOutcome(target, true, false);
        }

        // Clamp to the work area, then floor at the minimum. The floor wins, and
        // can exceed the work area on a very small display: a window below its
        // own minimum is a layout this app has no design for.
        var maxW = Math.Max(minWidth, target.Width);
        var maxH = Math.Max(minHeight, target.Height);
        var width = Math.Max(Math.Min(saved.Width, maxW), minWidth);
        var height = Math.Max(Math.Min(saved.Height, maxH), minHeight);

        // The origin is the ONLY thing an absent display costs. Never the size:
        // losing a deliberate choice because of a cable is the defect this whole
        // function exists to prevent.
        if (lost)
        {
            return new WindowFrameOutcome(new WindowRect(0, 0, width, height), false, true);
        }

        var x = Math.Max(target.X, Math.Min(saved.X, target.Right - width));
        var y = Math.Max(target.Y, Math.Min(saved.Y, target.Bottom - height));
        return new WindowFrameOutcome(new WindowRect(x, y, width, height), false, false);
    }

    /// <summary>
    /// The attached work area the saved frame overlaps most, by GEOMETRY rather
    /// than by a stored display id - an id is not stable across an unplug, a
    /// dock or a driver update, and a rectangle is.
    /// </summary>
    private static WindowRect? TargetArea(WindowRect saved, IReadOnlyList<WindowRect> workAreas)
    {
        var needW = Math.Min(GrabWidth, saved.Width);
        var needH = Math.Min(GrabHeight, saved.Height);
        WindowRect? best = null;
        long bestArea = 0;
        foreach (var area in workAreas)
        {
            var hit = area.Intersect(saved);
            if (hit.Width < needW || hit.Height < needH)
            {
                continue;
            }

            if (hit.Area > bestArea)
            {
                bestArea = hit.Area;
                best = area;
            }
        }

        return best;
    }
}
