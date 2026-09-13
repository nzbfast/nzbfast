using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Parfast.ViewModels;
using Windows.UI;

namespace Parfast.App.Controls;

/// <summary>
/// The verdict pill of plan section 5.2, and the queue's per-row state chip.
/// </summary>
/// <remarks>
/// One control for both, because they are the same statement in two sizes and the
/// alternative is two tone-to-colour switches that drift. The tones come from
/// <see cref="BlockPalette.Pill"/>, which is generated from the shared tokens
/// file, so a palette change reaches this and the mac lane's pill together.
/// </remarks>
public sealed class StatusPill : ContentControl
{
    public static readonly DependencyProperty ToneProperty = DependencyProperty.Register(
        nameof(Tone), typeof(PillTone), typeof(StatusPill),
        new PropertyMetadata(PillTone.Neutral, (d, _) => ((StatusPill)d).Restyle()));

    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(
        nameof(Text), typeof(string), typeof(StatusPill),
        new PropertyMetadata(string.Empty, (d, _) => ((StatusPill)d).Restyle()));

    public static readonly DependencyProperty IsBusyProperty = DependencyProperty.Register(
        nameof(IsBusy), typeof(bool), typeof(StatusPill),
        new PropertyMetadata(false, (d, _) => ((StatusPill)d).Restyle()));

    private readonly Border _shell = new();
    private readonly TextBlock _label = new();
    private readonly ProgressRing _ring = new();
    private readonly Microsoft.UI.Xaml.Shapes.Rectangle _dot = new();

    public StatusPill()
    {
        // A SOFT RADIUS, NOT A CAPSULE. At this size a 999 radius with a solid
        // fill is a highlighter stroke through the header, and it was competing
        // with the set name beside it for the card's attention. 8 is the shared
        // `radius.control` token's shape, so the verdict now belongs to the same
        // family as the buttons under it.
        _shell.CornerRadius = new CornerRadius(Tokens.Radius.Control);
        _shell.Padding = new Thickness(10, 4, 12, 4);
        _shell.BorderThickness = new Thickness(1);

        _dot.Width = 8;
        _dot.Height = 8;
        _dot.RadiusX = 4;
        _dot.RadiusY = 4;
        _dot.Margin = new Thickness(0, 0, 7, 0);
        _dot.VerticalAlignment = VerticalAlignment.Center;

        _ring.Width = 14;
        _ring.Height = 14;
        _ring.Margin = new Thickness(0, 0, 8, 0);
        _ring.IsActive = false;
        _ring.Visibility = Visibility.Collapsed;

        _label.FontSize = 13;
        _label.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold;
        _label.TextWrapping = TextWrapping.NoWrap;

        var row = new StackPanel { Orientation = Orientation.Horizontal };
        row.Children.Add(_ring);
        row.Children.Add(_dot);
        row.Children.Add(_label);
        _shell.Child = row;
        Content = _shell;

        ActualThemeChanged += (_, _) => Restyle();
        Loaded += (_, _) => Restyle();
    }

    public PillTone Tone
    {
        get => (PillTone)GetValue(ToneProperty);
        set => SetValue(ToneProperty, value);
    }

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    /// <summary>Shows the ring. Set while a job is running, cleared when it settles.</summary>
    public bool IsBusy
    {
        get => (bool)GetValue(IsBusyProperty);
        set => SetValue(IsBusyProperty, value);
    }

    /// <summary>
    /// How much of the tone's own colour the ground keeps. The rest is the card
    /// behind it, so one constant works on both themes.
    /// </summary>
    /// <remarks>
    /// A TINT AND A DOT RATHER THAN A SOLID FILL. The pill used to take the tone
    /// at full strength as its ground with a contrasting text colour on top, which
    /// at this size reads as a marker pen and, on the verify screen, shouted over
    /// the set name it sits beside. Tinted ground, the tone itself as ink, and a
    /// dot of the full-strength colour is the current idiom on both platforms.
    /// <para>
    /// The dot is not decoration. It is the same mark the legend puts beside each
    /// state, so the verdict and the key agree; and it is the secondary channel
    /// that keeps the verdict from being carried by colour alone, which the tint
    /// on its own would not do at 22% of a hue.
    /// </para>
    /// <para>
    /// DERIVED FROM THE TONE, NOT A SECOND TABLE. Five tones times two themes is
    /// ten more colours to keep in step with the five that already exist, and the
    /// tint is a function of the tone rather than an independent choice.
    /// </para>
    /// </remarks>
    private const byte TintAlpha = 38;

    private void Restyle()
    {
        var dark = ActualTheme == ElementTheme.Dark;
        var (_, tone) = BlockPalette.Pill(Tone, dark);
        var ink = Color.FromArgb(tone.A, tone.R, tone.G, tone.B);

        _shell.Background = new SolidColorBrush(Color.FromArgb(TintAlpha, tone.R, tone.G, tone.B));
        _shell.BorderBrush = new SolidColorBrush(Color.FromArgb(70, tone.R, tone.G, tone.B));
        var foreground = new SolidColorBrush(ink);
        _label.Foreground = foreground;
        _label.Text = Text;
        _ring.Foreground = foreground;
        _dot.Fill = foreground;
        _dot.Visibility = IsBusy ? Visibility.Collapsed : Visibility.Visible;

        // The ring is COLLAPSED rather than hidden when idle. A hidden ring still
        // occupies its width, so the pill would change size as a verdict settles
        // and the whole header card would shift by fourteen pixels.
        _ring.Visibility = IsBusy ? Visibility.Visible : Visibility.Collapsed;
        _ring.IsActive = IsBusy;

        Visibility = string.IsNullOrEmpty(Text) ? Visibility.Collapsed : Visibility.Visible;
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(this, Text);
    }
}
