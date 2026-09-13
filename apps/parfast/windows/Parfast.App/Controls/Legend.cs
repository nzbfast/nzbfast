using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Parfast.Core.Contracts;
using Parfast.ViewModels;
using Windows.UI;

namespace Parfast.App.Controls;

/// <summary>
/// The key under the block map: a swatch and a word per state.
/// </summary>
/// <remarks>
/// Built from <see cref="BlockPalette.Legend"/> rather than written out in XAML,
/// which is the difference between a key that always matches the strip and one
/// that matches it until somebody adds a state. Both the colour AND THE WORD come
/// from the shared tokens file, so a state chip B adds or renames appears here
/// with no edit on this side.
/// <para>
/// IT CARRIES THE COUNTS TOO, since 12 Sep 2026, and a state with none is dimmed
/// rather than dropped. Two reasons, and the second is the one that matters. The
/// obvious one: the census under the map used to restate all five numbers as a
/// grey sentence beside a key that had none, so the reader matched word to word
/// instead of colour to count. The real one: the strip tells six states apart by
/// COLOUR ALONE, and two of its pairs sit close enough that a colourblind reader
/// cannot separate them - a count beside each swatch is the secondary channel
/// that makes the key readable without colour at all. Dimming rather than hiding
/// keeps the key a fixed list, so its shape does not change as a verify walks and
/// states appear.
/// </para>
/// </remarks>
public sealed class Legend : ContentControl
{
    private readonly StackPanel _row = new() { Orientation = Orientation.Horizontal, Spacing = 16 };

    public Legend()
    {
        Content = _row;
        ActualThemeChanged += (_, _) => Build();
        Loaded += (_, _) => Build();
    }

    /// <summary>
    /// The map whose tallies the counts come from. Set it and call
    /// <see cref="Refresh"/>; like the strip's, this model is mutated in place, so
    /// assigning it is not a change anything can notice on its own.
    /// </summary>
    public BlockMapModel? Model { get; set; }

    public void Refresh() => Build();

    private void Build()
    {
        _row.Children.Clear();
        var dark = ActualTheme == ElementTheme.Dark;
        foreach (var token in BlockPalette.Legend)
        {
            var state = (BlockState)token.Code;
            // The swatch shows what the STRIP draws, which for a present run is the
            // washed ground and not the full-strength token. A key whose green is
            // twice the green of the thing it explains is the disagreement this
            // control exists to prevent - so the rule is CALLED and not restated.
            var color = BlockPalette.Ground(state, dark);
            var count = CountOf(state);
            var item = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
            item.Children.Add(new Rectangle
            {
                Width = 10,
                Height = 10,
                RadiusX = 3,
                RadiusY = 3,
                VerticalAlignment = VerticalAlignment.Center,
                Fill = new SolidColorBrush(Color.FromArgb(color.A, color.R, color.G, color.B)),
            });
            item.Children.Add(new TextBlock
            {
                Text = token.Label,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
                Opacity = 0.75,
            });
            if (count is { } n)
            {
                item.Children.Add(new TextBlock
                {
                    Text = Fmt.Count(n),
                    FontSize = 12,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    VerticalAlignment = VerticalAlignment.Center,
                    // Tabular digits: these sit in a row and change every snapshot,
                    // and proportional figures make the whole key twitch as they do.
                    FontFamily = new FontFamily("Segoe UI Variable Text"),
                });
                item.Opacity = n == 0 ? 0.4 : 1.0;
            }

            _row.Children.Add(item);
        }
    }

    private int? CountOf(BlockState state) => Model is not { } m ? null : state switch
    {
        BlockState.Present => m.Present,
        BlockState.Damaged => m.Damaged,
        BlockState.Missing => m.Missing,
        BlockState.Misnamed => m.Misnamed,
        BlockState.Hashing => m.Hashing,
        _ => null,
    };
}
