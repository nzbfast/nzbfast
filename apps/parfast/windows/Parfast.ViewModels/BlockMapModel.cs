using Parfast.Core.Contracts;
using Parfast.Core.Mock;

namespace Parfast.ViewModels;

/// <summary>
/// One drawn cell of the block map: a span of source blocks and what is in it.
/// </summary>
/// <param name="FirstBlock">Zero based index of the first block in this cell.</param>
/// <param name="Count">How many blocks this cell covers. One, below the merge threshold.</param>
/// <param name="Ground">
/// The colour the cell is filled with: the MAJORITY state in its range, which is
/// what carries the proportion.
/// </param>
/// <param name="BadMark">
/// The worst damaged or missing state in the range, or null when it holds none.
/// Drawn as a tick along the bottom of the cell, and it is what carries the
/// presence. See <see cref="BlockMapRule"/> for the measurement that chose this
/// split.
/// </param>
public readonly record struct MapCell(
    int FirstBlock, int Count, BlockState Ground, BlockState? BadMark,
    int Damaged, int Missing, int Misnamed)
{
    public int LastBlock => FirstBlock + Count - 1;

    public bool HasBad => BadMark is not null;
}

/// <summary>
/// Turns the snapshot's run-length encoded block states into the cells the
/// block map control draws, and answers the hover question about a cell.
/// </summary>
/// <remarks>
/// The merge rule itself is <see cref="BlockMapRule"/>, which is a PORT of the
/// shared rule in <c>apps/parfast/shared/design/blockmap.md</c>: majority ground
/// for the proportion, a bad tick for the presence, and the exact census in the
/// line under the map. This class applies it and nothing more.
/// <para>
/// Everything here is pure. The control does the drawing; this class is what the
/// tests can assert on.
/// </para>
/// </remarks>
public sealed class BlockMapModel
{
    /// <summary>
    /// Above this many blocks the map stops drawing one cell per block and draws
    /// proportional segments. The number comes from the SHARED tokens file
    /// (<c>size.block_merge_threshold</c>) so both apps merge at the same point.
    /// </summary>
    public static int MergeThreshold => (int)Tokens.Size.BlockMergeThreshold;

    private BlockState[] _states = [];

    public int BlockCount => _states.Length;

    /// <summary>
    /// The decoded set-wide block states, in set order.
    /// </summary>
    /// <remarks>
    /// Exposed for <see cref="FileStripModel"/>, which cuts each file table row's
    /// own strip out of it. The point of sharing the array rather than letting the
    /// rows decode is that there is then ONE decode per snapshot and ONE reading of
    /// the wire runs, so a row strip cannot draw a different picture from the map
    /// above it - and a hundred-row table does not run
    /// <c>MockSurvey.Decode</c> a hundred times at ten hertz.
    /// </remarks>
    public IReadOnlyList<BlockState> States => _states;

    public IReadOnlyList<MapCell> Cells { get; private set; } = [];

    /// <summary>True when cells cover more than one block each.</summary>
    public bool Merged { get; private set; }

    public int Present { get; private set; }

    public int Damaged { get; private set; }

    public int Missing { get; private set; }

    public int Misnamed { get; private set; }

    public int Hashing { get; private set; }

    public int Pending { get; private set; }

    /// <summary>
    /// Rebuilds from a snapshot's survey. <paramref name="targetCells"/> is how
    /// many cells the control has room for, which is its pixel width: the map
    /// never computes more cells than it can draw.
    /// </summary>
    public void Update(Survey? survey, int targetCells)
    {
        _states = survey is null ? [] : MockSurvey.Decode(survey.BlockRuns);
        Tally();

        if (_states.Length == 0 || targetCells <= 0)
        {
            Cells = [];
            Merged = false;
            return;
        }

        // One cell per block while they fit, and the rule's own Range() even then,
        // so the single-block and merged paths cannot drift apart.
        var count = _states.Length <= MergeThreshold && _states.Length <= targetCells
            ? _states.Length
            : Math.Min(targetCells, _states.Length);
        Merged = count < _states.Length;

        var cells = new List<MapCell>(count);
        for (var c = 0; c < count; c++)
        {
            var (first, last) = BlockMapRule.Range(c, count, _states.Length);

            int damaged = 0, missing = 0, misnamed = 0;
            for (var i = first; i <= last; i++)
            {
                switch (_states[i])
                {
                    case BlockState.Damaged: damaged++; break;
                    case BlockState.Missing: missing++; break;
                    case BlockState.Misnamed: misnamed++; break;
                }
            }

            cells.Add(new MapCell(
                first,
                last - first + 1,
                BlockMapRule.Ground(_states, first, last),
                BlockMapRule.BadMark(_states, first, last),
                damaged,
                missing,
                misnamed));
        }

        Cells = cells;
    }

    /// <summary>
    /// How many blocks each cell covers, or null when that is not yet knowable.
    /// </summary>
    /// <remarks>
    /// NULL IS THE POINT, and it is chip B's finding ported: on the mac side the
    /// column count comes from a state variable that the first layout pass has not
    /// filled in, so the arithmetic divided by zero columns and printed the TOTAL
    /// as if it were the per-cell figure - "each one covers 10,000 blocks" beside a
    /// map of fourteen hundred cells. This lane's early return makes that
    /// unreachable rather than merely unlikely, and the null is kept anyway so the
    /// two ports answer the same shape.
    /// <para>
    /// The floor of two is theirs as well: a merged map by definition has more
    /// blocks than cells, so a per-cell count of ONE means the division rounded
    /// down, and "each one covers 1 blocks" is both wrong and ungrammatical.
    /// </para>
    /// </remarks>
    public int? BlocksPerCell =>
        BlockCount <= 0 || Cells.Count <= 0
            ? null
            : Math.Max(2, BlockCount / Cells.Count);

    /// <summary>The note under a merged map, or an empty string when it is exact.</summary>
    public string MergedNote => Merged && BlocksPerCell is { } per
        ? Strings.Fill(Strings.VerifyMapMergedNote, "per", Fmt.Count(per))
        : string.Empty;

    /// <summary>
    /// The hover text of plan section 5.2: "blocks 2,048 to 2,303: 4 damaged".
    /// </summary>
    public string Describe(MapCell cell)
    {
        var what = DescribeContents(cell);
        return cell.Count == 1
            ? Strings.Fill(Strings.VerifyMapHoverSingle,
                "index", Fmt.Count(cell.FirstBlock + 1), "state", what)
            : Strings.Fill(Strings.VerifyMapHoverRange,
                "first", Fmt.Count(cell.FirstBlock + 1),
                "last", Fmt.Count(cell.LastBlock + 1),
                "detail", what);
    }

    private static string DescribeContents(MapCell cell)
    {
        if (cell.Count == 1)
        {
            return BlockPalette.Label(cell.Ground).ToLowerInvariant();
        }

        var parts = new List<string>(3);
        if (cell.Missing > 0)
        {
            parts.Add($"{Fmt.Count(cell.Missing)} missing");
        }

        if (cell.Damaged > 0)
        {
            parts.Add($"{Fmt.Count(cell.Damaged)} damaged");
        }

        if (cell.Misnamed > 0)
        {
            parts.Add($"{Fmt.Count(cell.Misnamed)} found elsewhere");
        }

        if (parts.Count == 0)
        {
            return $"all {BlockPalette.Label(cell.Ground).ToLowerInvariant()}";
        }

        return string.Join(", ", parts);
    }

    /// <summary>
    /// The text a screen reader gets instead of the picture (plan section 5.7,
    /// accessibility: "the block map exposes a text summary").
    /// </summary>
    public string AccessibleSummary() =>
        _states.Length == 0
            ? "No block information yet."
            : Strings.Fill(Strings.VerifyMapSummary,
                "present", Fmt.Count(Present),
                "damaged", Fmt.Count(Damaged),
                "missing", Fmt.Count(Missing),
                "misnamed", Fmt.Count(Misnamed),
                "total", Fmt.Count(_states.Length));

    private void Tally()
    {
        Present = Damaged = Missing = Misnamed = Hashing = Pending = 0;
        foreach (var s in _states)
        {
            switch (s)
            {
                case BlockState.Present: Present++; break;
                case BlockState.Damaged: Damaged++; break;
                case BlockState.Missing: Missing++; break;
                case BlockState.Misnamed: Misnamed++; break;
                case BlockState.Hashing: Hashing++; break;
                default: Pending++; break;
            }
        }
    }
}
