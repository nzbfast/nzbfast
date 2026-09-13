using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Parfast.ViewModels;
using Windows.Foundation;
using Windows.UI;

namespace Parfast.App.Controls;

/// <summary>
/// The read rate over the last couple of minutes: a gradient-filled area with the
/// endpoint emphasised.
/// </summary>
/// <remarks>
/// Section 4 of the 12 September 2026 prettiness review, chart (b), and the
/// treatment nzbfast's own dashboard is known for. The sheet showed one
/// instantaneous rate and threw the previous value away;
/// <see cref="RateHistory"/> is the ring buffer that keeps them and is the only new
/// data in the whole change.
/// <para>
/// WHAT IS BORROWED FROM THE DASHBOARD'S <c>drawArea</c> AND WHAT IS NOT. Borrowed:
/// the gradient wash under a two point line, the endpoint marker, and the
/// VU-meter y-scale rule - scale UP instantly so a spike is never clipped, ease
/// DOWN when the window maximum falls, because a spiky series that re-scales on
/// every sample judders and the judder is read as information. That rule lives in
/// <see cref="RateHistory.DisplayMax"/> so it is testable without a window. NOT
/// borrowed: any of the code, which is canvas and JavaScript, and the per-frame
/// x-glide, which needs an animation loop this app does not have and does not want.
/// </para>
/// <para>
/// MOTION: THERE IS NONE, WHICH IS HOW THE REST OF THIS APP RESPECTS THE SETTING.
/// parfast runs no storyboards and no transitions anywhere - the block map, the
/// status pill and the progress bar all simply redraw - so a chart that animated
/// would be the first moving thing in the window rather than one more. The single
/// motion-shaped behaviour is the y-scale easing above, and it is switched off from
/// the system's animations setting (<c>UISettings.AnimationsEnabled</c>, Windows'
/// equivalent of <c>prefers-reduced-motion</c>), which leaves a chart that steps
/// rather than glides and is otherwise identical.
/// </para>
/// <para>
/// A single series, so there is NO LEGEND: the label above the figure names what is
/// plotted, and a box with one swatch would restate it. The endpoint is the only
/// direct label, which is the house rule - a value on every point goes unread.
/// </para>
/// </remarks>
public sealed partial class Sparkline : ContentControl
{
    /// <remarks>
    /// Like every model in this app the history is mutated in place, so assigning
    /// this is not a change WinUI can notice. Call <see cref="Refresh"/> after
    /// setting it, which ProgressSheet does.
    /// </remarks>
    public static readonly DependencyProperty ModelProperty = DependencyProperty.Register(
        nameof(Model), typeof(RateHistory), typeof(Sparkline),
        new PropertyMetadata(null, (d, _) => ((Sparkline)d).Redraw()));

    /// <summary>The series line's thickness, per the house mark spec.</summary>
    private const double LineThickness = 2;

    /// <summary>
    /// The endpoint marker's diameter, and the surface ring around it.
    /// </summary>
    /// <remarks>
    /// Eight points is the floor for a marker; the two point ring in the surface
    /// colour is what keeps it legible where it sits on the line it terminates.
    /// </remarks>
    private const double MarkerSize = 8;

    private const double MarkerRing = 2;

    /// <summary>How many pixels each sample gets at least, so a narrow strip draws a shorter window.</summary>
    private const double PixelsPerSample = 2;

    /// <summary>Air above the peak, so the highest sample is a line and not the ceiling.</summary>
    private const double TopPadding = 3;

    /// <summary>
    /// Air at the right, wide enough for the endpoint marker AND its ring.
    /// </summary>
    /// <remarks>
    /// Without it the plot runs to the control's own edge, the marker is clamped
    /// flush against it, and the surface ring - the thing that makes the marker read
    /// as a marker rather than as a blob on the end of the line - is cut in half by
    /// the edge. Seen on the first Windows frame of this control; the clamp was
    /// doing its job and the job was the wrong one.
    /// </remarks>
    private static readonly double RightPadding = (MarkerSize / 2) + MarkerRing;

    private readonly Canvas _canvas = new();
    private RateHistory? _motionAppliedTo;

    public Sparkline()
    {
        Content = _canvas;
        IsTabStop = false;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
        SizeChanged += (_, _) => Redraw();
        ActualThemeChanged += (_, _) => Redraw();
        Loaded += (_, _) => Redraw();
    }

    public RateHistory? Model
    {
        get => (RateHistory?)GetValue(ModelProperty);
        set => SetValue(ModelProperty, value);
    }

    /// <summary>Repaint from the history as it stands now.</summary>
    public void Refresh() => Redraw();

    /// <summary>
    /// Reads the system's animations setting onto the model, once.
    /// </summary>
    /// <remarks>
    /// Called from the redraw rather than from Loaded, and only when the model it has
    /// not yet answered for arrives: the sheet assigns the history AFTER the control
    /// loads, so a one-shot read in Loaded would have run against a null model and
    /// left the setting at its default for ever - a reduced-motion reader would have
    /// got the easing anyway, silently.
    /// <para>
    /// Wrapped, and defaulting to ON when it cannot be read. <c>UISettings</c> is a
    /// WinRT projection and a failure here must not take the chart with it. Easing a
    /// y scale is very mild motion, so the platform default is the right answer to an
    /// unknown, and nobody gets a thrown exception inside a redraw.
    /// </para>
    /// </remarks>
    private void ApplyMotionSetting(RateHistory model)
    {
        if (ReferenceEquals(_motionAppliedTo, model))
        {
            return;
        }

        _motionAppliedTo = model;
        try
        {
            model.SmoothScale = new Windows.UI.ViewManagement.UISettings().AnimationsEnabled;
        }
        catch (Exception)
        {
            model.SmoothScale = true;
        }
    }

    private void Redraw()
    {
        _canvas.Children.Clear();

        var w = ActualWidth;
        var h = ActualHeight;
        var model = Model;
        if (model is null)
        {
            return;
        }

        ApplyMotionSetting(model);
        if (!model.HasShape || w <= 2 || h <= 2)
        {
            return;
        }

        var dark = ActualTheme == ElementTheme.Dark;
        var accent = ToColor(Tokens.Accent.Primary(dark));
        var surface = ToColor(Tokens.Surface.Card(dark));

        var samples = model.Visible((int)Math.Max(2, w / PixelsPerSample));
        if (samples.Count < 2)
        {
            return;
        }

        var max = model.DisplayMax;
        var right = Math.Max(1, w - RightPadding);
        var step = right / (samples.Count - 1);
        var plot = Math.Max(1, h - TopPadding);

        // THE HISTORY IS STRETCHED ACROSS THE PLOT rather than laid out at a fixed
        // step anchored to the right, which is the one thing this does differently
        // from the dashboard's drawArea. That chart has a fixed window it scrolls
        // through, so a short history filling only the right quarter is right there.
        // Here a whole create can be twenty seconds, and a chart that spends three
        // quarters of itself on time that has not happened yet reads as broken. The
        // cost is that the x scale narrows as the buffer fills, which is ordinary
        // sparkline behaviour and is invisible without an axis - and there is no
        // axis, by design: this is a shape, and the figure above it is the value.
        var points = new PointCollection();
        for (var i = 0; i < samples.Count; i++)
        {
            var x = i * step;
            var y = h - (samples[i] / max * plot);
            points.Add(new Point(x, Math.Clamp(y, TopPadding, h)));
        }

        // THE AREA IS A WASH AND NOT A BLOCK: the accent at about a fifth at the top
        // falling to nothing at the baseline. A saturated fill under a two point line
        // is the "thick saturated block" the house guidance names, and it would make
        // the line - which is the data - the quietest thing in the card.
        var area = new PointCollection();
        foreach (var p in points)
        {
            area.Add(p);
        }

        area.Add(new Point(right, h));
        area.Add(new Point(0, h));
        // StartPoint and EndPoint rather than the angle constructor: the angle
        // overload's zero is left to right and a wash that runs sideways is not a
        // wash, it is a second, wrong encoding.
        var wash = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(0, 1),
        };
        wash.GradientStops.Add(new GradientStop { Color = WithAlpha(accent, 0x33), Offset = 0 });
        wash.GradientStops.Add(new GradientStop { Color = WithAlpha(accent, 0x05), Offset = 1 });
        _canvas.Children.Add(new Polygon { Points = area, Fill = wash });

        _canvas.Children.Add(new Polyline
        {
            Points = points,
            Stroke = new SolidColorBrush(accent),
            StrokeThickness = LineThickness,
            StrokeLineJoin = PenLineJoin.Round,
            StrokeStartLineCap = PenLineCap.Round,
            StrokeEndLineCap = PenLineCap.Round,
        });

        // The endpoint, which is "now" and the only point worth marking. The ring is
        // in the surface colour rather than a stroke of the accent, so the marker
        // separates from the line by negative space.
        var last = points[^1];
        var diameter = MarkerSize + (MarkerRing * 2);
        var marker = new Ellipse
        {
            Width = diameter,
            Height = diameter,
            Fill = new SolidColorBrush(accent),
            Stroke = new SolidColorBrush(surface),
            StrokeThickness = MarkerRing,
        };
        Canvas.SetLeft(marker, Math.Clamp(last.X - (diameter / 2), 0, Math.Max(0, w - diameter)));
        Canvas.SetTop(marker, Math.Clamp(last.Y - (diameter / 2), 0, Math.Max(0, h - diameter)));
        _canvas.Children.Add(marker);

        // The picture is unreadable to a screen reader by construction, so the
        // automation name IS the answer - the rate now and which way it is going -
        // rather than a label saying "chart" (plan 5.7, the same rule the block map
        // follows).
        var trend = model.TrendText;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            this,
            string.IsNullOrEmpty(trend)
                ? Fmt.Rate(model.Current)
                : $"{Fmt.Rate(model.Current)}. {trend}");
    }

    private static Color WithAlpha(Color c, byte alpha) => Color.FromArgb(alpha, c.R, c.G, c.B);

    private static Color ToColor(TokenColor c) => Color.FromArgb(c.A, c.R, c.G, c.B);
}
