using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Parfast.ViewModels;
using Windows.UI;

namespace Parfast.App.Controls;

/// <summary>
/// What this set will cost on disk: a two-segment proportion bar over the create
/// preview, with a legend that carries the figures.
/// </summary>
/// <remarks>
/// Section 4 of the 12 September 2026 prettiness review, chart (a). The numbers
/// were already on the wire - <see cref="CostBarModel"/> reads them straight off
/// the <c>PlanPreview</c> the screen recomputes on every edit - and were spent on
/// three separate figures that needed arithmetic to answer "what is this going to
/// cost me". The bar answers it at a glance and moves as the recovery slider moves.
/// <para>
/// WHY Rectangles ON A Canvas. The same reason <see cref="BlockMap"/> gives: Win2D
/// would be the natural tool for a drawn control and is a second NuGet package with
/// a native dependency, on a build box that has never restored a .NET package. This
/// bar is four shapes.
/// </para>
/// <para>
/// THE CHANGE CALLBACK IS NOT ENOUGH ON ITS OWN. The create view model owns ONE
/// <see cref="CostBarModel"/> for the life of the page and mutates it in place on
/// every recompute, so the page's <c>Cost.Model = Vm.Cost</c> assigns a dependency
/// property the value it already holds and WinUI raises no change for that. Call
/// <see cref="Refresh"/> after setting it, which CreatePage does. A chart that
/// silently never repaints looks exactly like one that is working, on the first
/// frame - it cost the block map its whole life until 12 Sep 2026.
/// </para>
/// <para>
/// THE PALETTE IS EMPHASIS, NOT CATEGORICAL, and it was chosen by the house
/// validator rather than by eye. The source span is the de-emphasis grey
/// (<c>block.pending</c>) and the PAR2 span is <c>recovery.available</c>, the
/// colour this app already means "recovery" with in the verify screen's band, so
/// the two pictures agree. Measured: dE 28.2 to full colour vision and 22.2 under
/// deuteranopia in light, 39.2 and 29.5 in dark, against a floor of 15 and 8. The
/// grey trips the validator's chroma floor and lightness band by construction,
/// which is the point of a de-emphasis slot and outside the scope of checks written
/// for categorical identity; its sub-3:1 contrast against the card is answered by
/// the hairline border and by the legend carrying every figure in words, which is
/// the relief that check asks for.
/// </para>
/// </remarks>
public sealed partial class CostBar : ContentControl
{
    /// <remarks>See the class remarks: setting this is not enough, call Refresh.</remarks>
    public static readonly DependencyProperty ModelProperty = DependencyProperty.Register(
        nameof(Model), typeof(CostBarModel), typeof(CostBar),
        new PropertyMetadata(null, (d, _) => ((CostBar)d).Redraw()));

    /// <summary>
    /// How tall the bar is.
    /// </summary>
    /// <remarks>
    /// Thin, per the house mark spec (a bar caps at 24 and never fills its slot).
    /// Heavier than the verify screen's 8 point recovery band because this one
    /// carries two segments and the gap between them, and at 8 the gap eats a
    /// quarter of the bar's visual weight.
    /// </remarks>
    private const double BarHeight = 12;

    /// <summary>
    /// The gap between touching segments, in the surface colour.
    /// </summary>
    /// <remarks>
    /// The house rule, and it is negative space rather than ink: nothing is drawn
    /// there, so the card shows through. Never a border around a segment - a stroke
    /// adds weight that is not data.
    /// </remarks>
    private const double SegmentGap = 2;

    private const double BarRadius = 6;

    private readonly Canvas _canvas = new();
    private readonly Border _track;
    private readonly TextBlock _header = new() { FontSize = 12, Opacity = 0.9 };
    private readonly TextBlock _footprint = new()
    {
        FontSize = 12,
        Opacity = 0.9,
        HorizontalAlignment = HorizontalAlignment.Right,
    };

    private readonly StackPanel _legend = new()
    {
        Orientation = Orientation.Horizontal,
        Spacing = 16,
    };

    private readonly TextBlock _padding = new()
    {
        FontSize = 11,
        Opacity = 0.7,
        TextWrapping = TextWrapping.Wrap,
    };

    private readonly ToolTip _tip = new();

    public CostBar()
    {
        IsTabStop = true;
        UseSystemFocusVisuals = true;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;

        _track = new Border
        {
            Child = _canvas,
            Height = BarHeight,
            CornerRadius = new CornerRadius(BarRadius),
            BorderThickness = new Thickness(1),
        };

        var rows = new Grid { RowSpacing = 8 };
        rows.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rows.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rows.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rows.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var head = new Grid();
        head.Children.Add(_header);
        head.Children.Add(_footprint);
        Grid.SetRow(head, 0);
        Grid.SetRow(_track, 1);
        Grid.SetRow(_legend, 2);
        Grid.SetRow(_padding, 3);
        rows.Children.Add(head);
        rows.Children.Add(_track);
        rows.Children.Add(_legend);
        rows.Children.Add(_padding);
        Content = rows;

        ToolTipService.SetToolTip(this, _tip);
        SizeChanged += (_, _) => Redraw();
        PointerMoved += OnPointerMoved;
        PointerExited += (_, _) => _tip.IsOpen = false;
        ActualThemeChanged += (_, _) => Redraw();
        Loaded += (_, _) => Redraw();
    }

    public CostBarModel? Model
    {
        get => (CostBarModel?)GetValue(ModelProperty);
        set => SetValue(ModelProperty, value);
    }

    /// <summary>Repaint from the model as it stands now. See the class remarks.</summary>
    public void Refresh() => Redraw();

    private void OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        var model = Model;
        if (model is null || !model.HasPlan || _track.ActualWidth <= 0)
        {
            return;
        }

        // The segment under the pointer, by walking the shares. The LAST segment
        // catches everything past the end, so the rounded cap and the hairline
        // border are inside a hit target rather than a dead strip.
        var share = e.GetCurrentPoint(_track).Position.X / _track.ActualWidth;
        var hit = model.Segments[^1];
        var walked = 0.0;
        foreach (var segment in model.Segments)
        {
            walked += segment.Share;
            if (share <= walked)
            {
                hit = segment;
                break;
            }
        }

        _tip.Content = $"{hit.Label}: {model.Describe(hit)}";
        _tip.IsOpen = true;
    }

    private void Redraw()
    {
        _canvas.Children.Clear();
        _legend.Children.Clear();

        var dark = ActualTheme == ElementTheme.Dark;
        var width = _track.ActualWidth;
        _track.BorderBrush = new SolidColorBrush(ToColor(Tokens.Surface.CardBorder(dark)));

        var model = Model;
        _header.Text = Strings.CreateCostHeader;
        _footprint.Text = model?.FootprintText ?? string.Empty;
        _padding.Text = model?.PaddingText ?? string.Empty;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            this, model?.AccessibleSummary() ?? Strings.CreateCostNoPlan);

        if (model is null || !model.HasPlan)
        {
            // An empty bar is a flat well rather than nothing: a blank where a figure
            // goes reads as a broken card, and an unfilled track reads as "no plan
            // yet", which is the truth while the pane is being filled in.
            Visibility = Visibility.Collapsed;
            return;
        }

        Visibility = Visibility.Visible;
        if (width <= 1)
        {
            // Laid out but not measured yet. The legend is still built, so the figures
            // are on screen for the frame before SizeChanged brings the picture.
            BuildLegend(model, width, dark);
            return;
        }

        // ONE PASS, LEFT TO RIGHT, each segment at its own share of the width. A
        // segment narrower than the model's floor IS NOT DRAWN AND IS NOT WIDENED:
        // in a part-to-whole bar the width is the value, so flooring a sliver to a
        // visible two pixels overstates it - which is the opposite of the block map,
        // where a floored bad tick carries presence and the ground beside it carries
        // the proportion. The legend says so in words for the segment that was
        // dropped, so nobody hunts the picture for a colour that is not in it.
        var x = 0.0;
        var first = true;
        foreach (var segment in model.Segments)
        {
            var full = segment.Share * width;
            if (!CostBarModel.IsDrawable(segment.Share, width))
            {
                x += full;
                continue;
            }

            var left = first ? x : x + SegmentGap;
            var drawn = Math.Max(full - (first ? 0 : SegmentGap), CostBarModel.MinimumSegmentWidth);
            _canvas.Children.Add(Bar(left, 0, Math.Min(drawn, Math.Max(0, width - left)), BarHeight,
                Colour(segment.Kind, dark)));
            x += full;
            first = false;
        }

        BuildLegend(model, width, dark);
    }

    private void BuildLegend(CostBarModel model, double width, bool dark)
    {
        foreach (var segment in model.Segments)
        {
            var item = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
            var colour = Colour(segment.Kind, dark);
            item.Children.Add(new Rectangle
            {
                Width = 10,
                Height = 10,
                RadiusX = 3,
                RadiusY = 3,
                VerticalAlignment = VerticalAlignment.Center,
                Fill = new SolidColorBrush(ToColor(colour)),
            });
            item.Children.Add(new TextBlock
            {
                Text = segment.Label,
                FontSize = 12,
                Opacity = 0.75,
                VerticalAlignment = VerticalAlignment.Center,
            });

            // The figures wear TEXT tokens and never the segment's colour: identity
            // comes from the swatch beside them. A pale fill is illegible as text.
            item.Children.Add(new TextBlock
            {
                Text = model.Describe(segment),
                FontSize = 12,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
            });

            var inside = model.DescribeInside(segment);
            if (!string.IsNullOrEmpty(inside))
            {
                item.Children.Add(new TextBlock
                {
                    Text = inside,
                    FontSize = 11,
                    Opacity = 0.65,
                    VerticalAlignment = VerticalAlignment.Center,
                });
            }

            if (width > 1 && !CostBarModel.IsDrawable(segment.Share, width))
            {
                item.Children.Add(new TextBlock
                {
                    Text = Strings.CreateCostTooSmall,
                    FontSize = 11,
                    Opacity = 0.65,
                    VerticalAlignment = VerticalAlignment.Center,
                });
            }

            _legend.Children.Add(item);
        }
    }

    /// <summary>
    /// The colour a segment is drawn in. Emphasis, not identity: see the class
    /// remarks for the measurement.
    /// </summary>
    private static TokenColor Colour(CostSegment kind, bool dark) => kind == CostSegment.Par2
        ? Tokens.Recovery.Available(dark)
        : Tokens.Block.Pending.For(dark);

    private static Rectangle Bar(double x, double y, double w, double h, TokenColor color)
    {
        var rect = new Rectangle
        {
            Width = Math.Max(0, w),
            Height = h,
            Fill = new SolidColorBrush(ToColor(color)),
        };
        Canvas.SetLeft(rect, x);
        Canvas.SetTop(rect, y);
        return rect;
    }

    private static Color ToColor(TokenColor c) => Color.FromArgb(c.A, c.R, c.G, c.B);
}
