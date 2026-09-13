using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Parfast.Core.Contracts;
using Parfast.ViewModels;
using Windows.Foundation;
using Windows.UI;

namespace Parfast.App.Controls;

/// <summary>
/// The block availability strip of plan section 5.2: one cell per source block,
/// coloured by state, with a recovery band under it and hover detail.
/// </summary>
/// <remarks>
/// CUSTOM DRAWN, AND NOT AN ITEMS CONTROL. Ten thousand cells as ten thousand
/// Rectangles in a WrapPanel is ten thousand layout objects to measure and
/// arrange on every 10 Hz snapshot, which is where a UI like this dies. Instead
/// <see cref="BlockMapModel"/> reduces the run-length encoded states to at most
/// one cell per available pixel, and this control draws those as a handful of
/// Rectangles, merging ADJACENT CELLS OF THE SAME GROUND into one rectangle
/// first. A clean thousand-block set is then a single rectangle, and the worst
/// case is bounded by the pixel width rather than by the set.
/// <para>
/// WHAT IT DRAWS is the shared rule of <c>apps/parfast/shared/design/blockmap.md</c>,
/// ported in <see cref="BlockMapRule"/>: a GROUND of the majority state, which
/// carries the proportion, plus a TICK along the bottom wherever the cell holds a
/// damaged or missing block, which carries the presence. Chip B measured the two
/// obvious one-rule alternatives and both fail silently in opposite directions;
/// the numbers are in that file and in BlockMapRule's own header.
/// </para>
/// <para>
/// WHY Rectangles RATHER THAN A CanvasControl. Win2D would be the natural tool
/// and is a second NuGet package with its own native dependency, on a build box
/// that has never restored a .NET package. Rectangles in a Canvas need nothing
/// beyond WinUI itself and, reduced to colour runs, are fast enough: the strip is
/// tens of shapes, not thousands.
/// </para>
/// </remarks>
public sealed partial class BlockMap : ContentControl
{
    /// <remarks>
    /// THE CHANGE CALLBACK IS NOT ENOUGH ON ITS OWN, and believing it was is what
    /// made this control wrong for its whole life until 12 Sep 2026. The view
    /// model owns ONE <see cref="BlockMapModel"/> for the life of the page and
    /// MUTATES it in place on every snapshot, so the page's per-refresh
    /// `Map.Model = Vm.Map` assigns a dependency property the value it already
    /// holds - and WinUI raises no change for that, so Redraw never ran from a
    /// snapshot. Call <see cref="Refresh"/> after setting these, which
    /// VerifyPage now does.
    /// </remarks>
    public static readonly DependencyProperty ModelProperty = DependencyProperty.Register(
        nameof(Model), typeof(BlockMapModel), typeof(BlockMap),
        new PropertyMetadata(null, (d, _) => ((BlockMap)d).Redraw()));

    public static readonly DependencyProperty RecoveryAvailableProperty = DependencyProperty.Register(
        nameof(RecoveryAvailable), typeof(int), typeof(BlockMap),
        new PropertyMetadata(0, (d, _) => ((BlockMap)d).Redraw()));

    public static readonly DependencyProperty RecoveryNeededProperty = DependencyProperty.Register(
        nameof(RecoveryNeeded), typeof(int), typeof(BlockMap),
        new PropertyMetadata(0, (d, _) => ((BlockMap)d).Redraw()));

    // From the SHARED tokens file, so both apps draw the same strip.
    private static readonly double StripHeight = Tokens.Size.BlockMapHeight;
    private static readonly double BandHeight = Tokens.Size.RecoveryBandHeight;
    private const double BandGap = 8;

    /// <summary>How tall the bad tick along the bottom of a cell is.</summary>
    private const double TickHeight = 6;

    private readonly Canvas _canvas = new();
    private readonly Border _strip;
    private readonly ToolTip _tip = new();

    /// <summary>The strip's corner radius. The mac app's is 6; they match on purpose.</summary>
    private const double StripRadius = 6;

    public BlockMap()
    {
        IsTabStop = true;
        UseSystemFocusVisuals = true;
        Height = StripHeight + BandGap + BandHeight;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
        // The strip is CLIPPED to a rounded rectangle and carries a hairline
        // border, which is what the mac app has always done and Windows did not:
        // the runs are square-ended rectangles on a Canvas, so without the clip
        // the strip's own corners are square inside a card whose radius is 12,
        // and the whole thing reads as a progress bar somebody forgot to style.
        // The border is what separates a nearly-empty strip from the card behind
        // it; the fill alone cannot, now that a present run is a wash.
        _strip = new Border
        {
            Child = _canvas,
            CornerRadius = new CornerRadius(StripRadius),
            BorderThickness = new Thickness(1),
        };
        Content = _strip;
        ToolTipService.SetToolTip(this, _tip);
        SizeChanged += (_, _) => Redraw();
        PointerMoved += OnPointerMoved;
        PointerExited += (_, _) => _tip.IsOpen = false;
        ActualThemeChanged += (_, _) => Redraw();
        Loaded += (_, _) => Redraw();
    }

    public BlockMapModel? Model
    {
        get => (BlockMapModel?)GetValue(ModelProperty);
        set => SetValue(ModelProperty, value);
    }

    public int RecoveryAvailable
    {
        get => (int)GetValue(RecoveryAvailableProperty);
        set => SetValue(RecoveryAvailableProperty, value);
    }

    public int RecoveryNeeded
    {
        get => (int)GetValue(RecoveryNeededProperty);
        set => SetValue(RecoveryNeededProperty, value);
    }

    /// <summary>
    /// Raised with the number of cells the control has room for, so the shell can
    /// tell the model how finely to divide the set. The control never computes
    /// more cells than pixels.
    /// </summary>
    public event Action<int>? WidthInCellsChanged;

    private void OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        var model = Model;
        if (model is null || model.Cells.Count == 0 || ActualWidth <= 0)
        {
            return;
        }

        var x = e.GetCurrentPoint(this).Position.X;
        var index = (int)Math.Clamp(x / ActualWidth * model.Cells.Count, 0, model.Cells.Count - 1);
        _tip.Content = model.Describe(model.Cells[index]);
        _tip.IsOpen = true;
    }

    /// <summary>
    /// Repaint from the model as it stands now.
    /// </summary>
    /// <remarks>
    /// PUBLIC BECAUSE THE MODEL IS MUTATED IN PLACE. The block map is the one
    /// thing on the verify screen that is redrawn rather than re-bound, and
    /// until this existed it was also the one thing that did not update: the
    /// header figures, the status pill, the census line and the file table are
    /// all plain assignments on every refresh and were all correct, while the
    /// picture beside them stayed at whatever the last SizeChanged, theme change
    /// or Loaded had drawn.
    ///
    /// WHAT THAT LOOKED LIKE, since a frozen picture does not announce itself:
    /// the `clean` scenario - a settled, undamaged set - drew SIX PER CENT of
    /// the strip green and the remaining ninety-four per cent in the pending
    /// grey, directly beside a green "Complete - no repair needed" pill, a
    /// census reading "2,001 present ... of 2,001 blocks" and five file rows all
    /// saying Complete. Four things agreed and the signature visual contradicted
    /// all four. It was worse on the quiet scenarios than the loud ones, because
    /// a set whose RecoveryNeeded changes mid-verify got an accidental redraw
    /// out of THAT property's change callback and so happened to look right -
    /// which is why the damaged scenarios were fine and the clean one was not.
    ///
    /// Plan 5.2 asks for the opposite of frozen: "Redraws live as verify walks
    /// the files".
    /// </remarks>
    public void Refresh() => Redraw();

    private void Redraw()
    {
        _canvas.Children.Clear();

        var width = ActualWidth;
        if (width <= 1)
        {
            return;
        }

        var dark = ActualTheme == ElementTheme.Dark;
        var model = Model;
        _strip.BorderBrush = new SolidColorBrush(ToColor(Tokens.Surface.CardBorder(dark)));

        if (model is null || model.Cells.Count == 0)
        {
            // An empty map is a flat pending strip rather than nothing: a blank
            // where the signature visual goes reads as a broken screen, and a
            // grey strip reads as "no answer yet", which is the truth.
            _canvas.Children.Add(Bar(0, 0, width, StripHeight, BlockPalette.For(BlockState.Pending, dark)));
            WidthInCellsChanged?.Invoke((int)width);
            return;
        }

        // TWO PASSES, GROUND THEN TICKS, and the order is the rule rather than a
        // drawing convenience: a tick drawn under the next cell's ground would be
        // covered by it when the mark is widened to its floor. See BlockMapRule
        // for why the map is a ground plus a tick at all.
        var cells = model.Cells;

        // Ground. Adjacent cells sharing a colour merge into one rectangle, so a
        // clean thousand-block set is a single shape rather than a thousand.
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
                GroundColour(ground, dark)));
            start = end;
        }

        // The bad ticks, along the bottom of the strip. Each is floored at
        // BlockMapRule.MinimumMarkWidth: a sub-pixel rectangle antialiases to
        // nearly nothing, which is the same defect as not drawing it.
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

        DrawRecoveryBand(width, dark);
        WidthInCellsChanged?.Invoke((int)width);
        AutomationName();
    }

    /// <summary>
    /// The recovery band: available recovery blocks drawn against the number
    /// needed, with the needed count marked (plan section 5.2).
    /// </summary>
    private void DrawRecoveryBand(double width, bool dark)
    {
        var available = Math.Max(0, RecoveryAvailable);
        var needed = Math.Max(0, RecoveryNeeded);
        var y = StripHeight + BandGap;

        if (available == 0 && needed == 0)
        {
            return;
        }

        // The band's scale is the LARGER of the two, so when more is needed than
        // exists the shortfall is visible as the marker sitting past the end of
        // the filled bar. Scaling to `available` alone would put the marker off
        // the edge, which is the one case the band exists to show.
        var scale = Math.Max(available, needed);
        var filled = scale == 0 ? 0 : (double)available / scale * width;

        // THE TRACK IS recovery.spare, NOT THE PENDING GREY. A meter's unfilled
        // track is a lighter step of its own ramp, so the whole bar reads as one
        // quantity partly filled; the pending grey belongs to the map above and
        // borrowing it made the band read as a second, unrelated progress bar.
        // The mac app has drawn it on the spare token since it was written - this
        // is Windows catching up rather than a new idea, and `recovery.spare` was
        // already in the shared tokens and unused here.
        _canvas.Children.Add(Rounded(0, y, width, BandHeight, BlockPalette.RecoverySpare(dark)));
        if (filled > 0)
        {
            _canvas.Children.Add(Rounded(0, y, Math.Max(filled, 2), BandHeight, BlockPalette.Recovery(dark)));
        }

        if (needed <= 0)
        {
            return;
        }

        var at = scale == 0 ? 0 : (double)needed / scale * width;
        var marker = new Rectangle
        {
            Width = 2,
            Height = BandHeight + 6,
            Fill = new SolidColorBrush(ToColor(BlockPalette.NeededMarker(dark))),
        };
        Canvas.SetLeft(marker, Math.Clamp(at - 1, 0, width - 2));
        Canvas.SetTop(marker, y - 3);
        _canvas.Children.Add(marker);
    }

    /// <summary>
    /// The colour a RUN is grounded in, which is not always the colour that names its
    /// state.
    /// </summary>
    /// <remarks>
    /// The rule, the measurement that chose it and why saturation is reserved for the
    /// small marks are all in <see cref="BlockPalette.Ground"/>, which is where it
    /// lives now that the key and the file table's per-row strips draw it too. It was
    /// written out here first and a third caller would have been a third copy.
    /// </remarks>
    private static TokenColor GroundColour(BlockState ground, bool dark) =>
        BlockPalette.Ground(ground, dark);

    private void AutomationName()
    {
        // Plan 5.7, accessibility: the block map exposes a text summary. The
        // picture is unreadable to a screen reader by construction, so the
        // automation name IS the answer, not a label saying "block map".
        var summary = Model?.AccessibleSummary();
        if (!string.IsNullOrEmpty(summary))
        {
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(this, summary);
        }
    }

    /// <summary>
    /// A bar with its ends rounded, for the recovery meter.
    /// </summary>
    /// <remarks>
    /// The radius is half the height, so the track and its fill are capsules and
    /// the fill's right end is a cap rather than a cut. Square ends on a short bar
    /// read as a fragment of something longer.
    /// </remarks>
    private static Rectangle Rounded(double x, double y, double w, double h, TokenColor color)
    {
        var rect = Bar(x, y, w, h, color);
        rect.RadiusX = h / 2;
        rect.RadiusY = h / 2;
        return rect;
    }

    private static Rectangle Bar(double x, double y, double w, double h, TokenColor color)
    {
        var rect = new Rectangle
        {
            Width = w,
            Height = h,
            Fill = new SolidColorBrush(ToColor(color)),
        };
        Canvas.SetLeft(rect, x);
        Canvas.SetTop(rect, y);
        return rect;
    }

    private static Color ToColor(TokenColor c) => Color.FromArgb(c.A, c.R, c.G, c.B);
}
