using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Parfast.Core.Contracts;
using Parfast.ViewModels;
using Windows.UI;

namespace Parfast.App.Controls;

/// <summary>
/// One file table row's own block strip: the same picture as the map above it, cut
/// to this member's blocks.
/// </summary>
/// <remarks>
/// Section 4 of the 12 September 2026 prettiness review, chart (c). The table said
/// <c>29 / 32</c> and the strip above said where the damage was, and nothing joined
/// the two, so a reader had to take on trust that the three bad blocks in the strip
/// were the three the row was counting. This is that join, and it is drawn from the
/// SAME decoded states through the SAME <see cref="BlockMapRule"/>, so it cannot
/// disagree - see <see cref="FileStripModel"/> for how the slice is derived and for
/// the reconciliation that makes it refuse rather than guess.
/// <para>
/// A GROUND PLUS A BAD TICK, exactly as the big map draws: the majority state
/// carries the proportion and a tick along the bottom carries the presence, floored
/// at <see cref="BlockMapRule.MinimumMarkWidth"/> so a lone damaged block in a
/// hundred is drawn rather than antialiased into nothing. Both of the obvious
/// one-rule alternatives fail silently in opposite directions and the measurement
/// that chose this one is in that class's header; this control re-derives none of
/// it.
/// </para>
/// <para>
/// THIS ONE DOES NOT NEED A Refresh(), AND IT IS THE ONLY CONTROL HERE THAT DOES
/// NOT. Every other model in these two screens is one object mutated in place, which
/// is why <see cref="BlockMap"/>, <see cref="Legend"/> and <see cref="CostBar"/> all
/// grew an explicit repaint - assigning a dependency property the value it already
/// holds raises nothing. A row strip lives inside a <c>DataTemplate</c>, where there
/// is no field to call a method on, so the model is REPLACED on every snapshot
/// instead and this property's own change callback does the work.
/// <see cref="FileStripModel.Build"/> hands the previous instance back when the
/// picture has not moved, so a settled table of a hundred rows is not repainting ten
/// times a second either.
/// </para>
/// <para>
/// THE COST IS BOUNDED BY THE COLUMN, not by the set. The model cuts at most
/// <see cref="FileStripModel.TargetCells"/> cells and this merges adjacent cells of
/// one ground into a single rectangle first, so a clean member is ONE rectangle and
/// the worst case is a handful - the same bound the big map is built to.
/// </para>
/// </remarks>
public sealed partial class MiniBlockStrip : ContentControl
{
    public static readonly DependencyProperty ModelProperty = DependencyProperty.Register(
        nameof(Model), typeof(FileStripModel), typeof(MiniBlockStrip),
        new PropertyMetadata(null, (d, _) => ((MiniBlockStrip)d).Redraw()));

    /// <summary>
    /// How tall the strip is: a sixth of the signature map's height.
    /// </summary>
    /// <remarks>
    /// A row strip is a supplement to the figure beside it, not a second signature
    /// visual, and a table of twenty of them at the map's own 24 points would compete
    /// with the thing it is a detail of. Four points is the same weight as the
    /// hashing row's progress bar two columns to the left.
    /// </remarks>
    private const double StripHeight = 4;

    /// <summary>How tall the bad tick is, as a fraction of a strip this thin.</summary>
    private const double TickHeight = 2;

    private readonly Canvas _canvas = new();
    private readonly ToolTip _tip = new();

    public MiniBlockStrip()
    {
        Height = StripHeight;
        IsTabStop = false;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
        Content = _canvas;
        ToolTipService.SetToolTip(this, _tip);
        SizeChanged += (_, _) => Redraw();
        ActualThemeChanged += (_, _) => Redraw();
        Loaded += (_, _) => Redraw();
    }

    public FileStripModel? Model
    {
        get => (FileStripModel?)GetValue(ModelProperty);
        set => SetValue(ModelProperty, value);
    }

    private void Redraw()
    {
        _canvas.Children.Clear();

        var width = ActualWidth;
        var model = Model;
        if (model is null || model.Cells.Count == 0)
        {
            // No strip rather than an empty one. A row with no blocks (an extra file)
            // and a set whose block totals did not reconcile both land here, and in
            // both cases the honest thing is to draw nothing and leave the row's own
            // figures to speak.
            Visibility = Visibility.Collapsed;
            _tip.Content = null;
            return;
        }

        Visibility = Visibility.Visible;
        var summary = model.AccessibleSummary();
        _tip.Content = summary;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(this, summary);

        if (width <= 1)
        {
            return;
        }

        var dark = ActualTheme == ElementTheme.Dark;
        var cells = model.Cells;

        // Ground first, then ticks, and the order is the rule rather than a
        // convenience: a tick drawn under the next cell's ground would be covered by
        // it once the mark is widened to its floor.
        var start = 0;
        while (start < cells.Count)
        {
            var ground = cells[start].Ground;
            var end = start + 1;
            while (end < cells.Count && cells[end].Ground == ground)
            {
                end++;
            }

            var x0 = (double)start / cells.Count * width;
            var x1 = (double)end / cells.Count * width;
            _canvas.Children.Add(Bar(x0, 0, Math.Max(x1 - x0, 1), StripHeight,
                BlockPalette.Ground(ground, dark)));
            start = end;
        }

        for (var c = 0; c < cells.Count; c++)
        {
            if (cells[c].BadMark is not { } bad)
            {
                continue;
            }

            var x0 = (double)c / cells.Count * width;
            var w = Math.Max((double)(c + 1) / cells.Count * width - x0, BlockMapRule.MinimumMarkWidth);
            x0 = Math.Min(x0, width - w);
            _canvas.Children.Add(Bar(x0, StripHeight - TickHeight, w, TickHeight,
                BlockPalette.For(bad, dark)));
        }
    }

    private static Rectangle Bar(double x, double y, double w, double h, TokenColor color)
    {
        var rect = new Rectangle
        {
            Width = Math.Max(0, w),
            Height = h,
            Fill = new SolidColorBrush(Color.FromArgb(color.A, color.R, color.G, color.B)),
        };
        Canvas.SetLeft(rect, x);
        Canvas.SetTop(rect, y);
        return rect;
    }
}
