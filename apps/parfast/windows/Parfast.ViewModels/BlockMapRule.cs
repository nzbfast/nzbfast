using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>
/// How a merged block-map cell picks what it draws. A PORT, not a design.
/// </summary>
/// <remarks>
/// The rule is written down in <c>apps/parfast/shared/design/blockmap.md</c> and
/// the reference implementation is
/// <c>apps/parfast/mac/Sources/ParfastCore/BlockMapRule.swift</c>. This file is
/// that implementation in C#, function for function, so the two apps draw the
/// same picture of the same data. Do not re-derive it here; change the shared
/// document and both ports together.
/// <para>
/// THE MEASUREMENT THAT CHOSE IT, on the mock's ten-thousand-block set (188
/// damaged blocks, 1.88%, scattered, which is what dropped articles look like)
/// at 400 columns:
/// </para>
/// <list type="table">
/// <item><term>worst state wins</term><description>78 of 400 cells red, 19.5% of
/// the strip, for 1.88% damage</description></item>
/// <item><term>majority state only</term><description>0 cells red, the damage is
/// invisible</description></item>
/// <item><term>majority ground plus a bad tick</term><description>0 red, 78
/// ticked</description></item>
/// </list>
/// <para>
/// This lane argued for worst-wins on 12 Sep 2026, from the correct premise that
/// a merged cell must never hide a bad block. Chip B measured both and found the
/// premise right and the remedy wrong: worst-wins over-states damage by an order
/// of magnitude, so a repairable set looks a fifth destroyed on the screen the
/// user is deciding from. The TICK is what satisfies the premise without the
/// over-statement. Both failures are silent, which is why neither was going to be
/// caught by looking.
/// </para>
/// </remarks>
public static class BlockMapRule
{
    /// <summary>
    /// How much a state matters when two are tied, and the order the hover
    /// readout lists them in. Not a severity ranking of the DATA, a ranking of
    /// what the user needs to see first.
    /// </summary>
    public static int Rank(BlockState state) => state switch
    {
        BlockState.Present => 0,
        BlockState.Pending => 1,
        BlockState.Hashing => 2,
        BlockState.Misnamed => 3,
        BlockState.Damaged => 4,
        BlockState.Missing => 5,
        _ => 0,
    };

    /// <summary>
    /// A state is bad when it means data the set does not have where it expects
    /// it. MISNAMED IS NOT BAD: the data is on the disk under another name, it
    /// costs no recovery blocks, and painting it as damage makes a set two
    /// renames from perfect look nearly lost.
    /// </summary>
    public static bool IsBad(BlockState state) =>
        state is BlockState.Damaged or BlockState.Missing;

    /// <summary>The half-open block range a merged cell covers: [First, Last].</summary>
    public static (int First, int Last) Range(int column, int columns, int blocks)
    {
        var first = (int)((long)blocks * column / columns);
        var last = Math.Max(first, (int)((long)blocks * (column + 1) / columns) - 1);
        return (first, Math.Min(last, blocks - 1));
    }

    /// <summary>
    /// The cell's ground: the most common state in its range, ties going to the
    /// one that matters more.
    /// </summary>
    public static BlockState Ground(IReadOnlyList<BlockState> states, int first, int last)
    {
        if (first == last)
        {
            return states[first];
        }

        Span<int> counts = stackalloc int[8];
        for (var i = first; i <= last; i++)
        {
            var code = (int)states[i];
            if ((uint)code < (uint)counts.Length)
            {
                counts[code]++;
            }
        }

        var best = BlockState.Pending;
        var bestCount = -1;
        foreach (var state in All)
        {
            var n = counts[(int)state];
            if (n > bestCount || (n == bestCount && Rank(state) > Rank(best)))
            {
                best = state;
                bestCount = n;
            }
        }

        return best;
    }

    /// <summary>
    /// The tick along the bottom of the cell: the worst BAD state in the range,
    /// or null when it holds none. This is what stops the majority ground from
    /// hiding a single bad block in forty.
    /// </summary>
    public static BlockState? BadMark(IReadOnlyList<BlockState> states, int first, int last)
    {
        BlockState? worst = null;
        for (var i = first; i <= last; i++)
        {
            var s = states[i];
            if (!IsBad(s))
            {
                continue;
            }

            if (worst is null || Rank(s) > Rank(worst.Value))
            {
                worst = s;
            }
        }

        return worst;
    }

    /// <summary>
    /// Minimum width, in device-independent pixels, of any mark that says
    /// something is wrong here. This lane's finding, and it is the same defect as
    /// not drawing the mark at all: a sub-pixel rectangle antialiases to nearly
    /// nothing, so a lone damaged cell can be drawn and still be invisible.
    /// </summary>
    public const double MinimumMarkWidth = 2;

    internal static readonly BlockState[] All =
    [
        BlockState.Pending, BlockState.Present, BlockState.Damaged,
        BlockState.Missing, BlockState.Misnamed, BlockState.Hashing,
    ];
}
