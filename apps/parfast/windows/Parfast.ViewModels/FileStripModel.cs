using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>
/// One file table row's slice of the block map: the same blocks, the same rule, a
/// sixth of the height.
/// </summary>
/// <remarks>
/// WHAT IT IS FOR. The file table carries <c>29 / 32</c> as text and the big strip
/// above carries the whole set as one run, so nothing on the screen connected a
/// damaged run to the file it lives in: the reader could see that three blocks were
/// bad and which file was damaged, and had to take on trust that they were the same
/// three. A per-row strip is that connection, and it is free - it is literally the
/// file's own slice of the strip already drawn above it.
/// <para>
/// THE SLICE IS DERIVED, WHICH IS WHY IT CANNOT DISAGREE WITH THE BIG MAP.
/// <c>survey.block_runs</c> is one strip over the source blocks in SET order, and
/// the engine builds it by walking the members in <c>survey.files</c> order and
/// pushing each member's blocks in turn (<c>survey.rs</c>'s <c>push_blocks</c>
/// inside the loop over targets; the mock's <c>MockSurvey.Build</c> does the same
/// with an explicit running offset). So a member's blocks are the contiguous range
/// starting at the sum of the preceding members' <c>blocks_total</c>, and this
/// class does no decoding, no re-derivation and no second reading of the states -
/// it takes the array the block map already decoded and cuts it.
/// </para>
/// <para>
/// AND IT REFUSES RATHER THAN GUESSING. If the members' block totals do not add up
/// to the strip's length, the offsets are unreliable and a slice would attribute
/// one file's damage to another row - the worst thing this control could do, and
/// silent, because a plausible-looking strip beside the wrong name reads as
/// information. <see cref="Build"/> answers null for every row in that case and the
/// rows keep their <c>29 / 32</c> text, which is what they had before this existed.
/// A blank cell in a table is not a broken screen the way a blank signature visual
/// is.
/// </para>
/// <para>
/// A REPAIR'S PRE-FOLD SURVEY reports how many of a member's blocks are present
/// rather than which, so its present blocks are drawn first (API.md). The slice is
/// then honest about the COUNT and arbitrary about the POSITION, exactly as the big
/// map above it is, which is the property that matters: the two pictures are the
/// same picture.
/// </para>
/// </remarks>
public sealed class FileStripModel
{
    /// <summary>
    /// How many cells a row strip is cut into.
    /// </summary>
    /// <remarks>
    /// The Blocks column is a fixed width in the file table, so the budget is fixed
    /// too: 112 points of strip at two points a cell. The control stretches the
    /// cells it is given to whatever width it actually has, which is honest for a
    /// proportional strip, and floors a bad tick at
    /// <see cref="BlockMapRule.MinimumMarkWidth"/> the same way the big map does.
    /// <para>
    /// IT IS A CEILING AND NOT A TARGET: a member with eight blocks gets eight
    /// cells, not fifty-six, because <see cref="BlockMapRule.Range"/> is used for
    /// both paths and a cell is never smaller than a block.
    /// </para>
    /// </remarks>
    public const int TargetCells = 56;

    private FileStripModel(IReadOnlyList<MapCell> cells, int blocks, int ok, int bad)
    {
        Cells = cells;
        Blocks = blocks;
        Ok = ok;
        Bad = bad;
    }

    /// <summary>The cells to draw, left to right.</summary>
    public IReadOnlyList<MapCell> Cells { get; }

    /// <summary>How many source blocks this member owns.</summary>
    public int Blocks { get; }

    /// <summary>How many of them the set has, from the row's own census.</summary>
    public int Ok { get; }

    /// <summary>How many of them are damaged or missing, counted from the slice.</summary>
    public int Bad { get; }

    /// <summary>The hover text, and the text a screen reader gets instead of the strip.</summary>
    public string AccessibleSummary() =>
        Strings.Fill(Strings.VerifyFileStripSummary,
            "ok", Fmt.Count(Ok), "total", Fmt.Count(Blocks));

    /// <summary>
    /// Cuts one strip per member of <paramref name="files"/>, or all nulls when the
    /// members' block totals do not reconcile with <paramref name="setStates"/>.
    /// </summary>
    /// <param name="setStates">
    /// The decoded set-wide block states, which <see cref="BlockMapModel.States"/>
    /// already holds - decoded once per snapshot for the big map and shared here
    /// rather than decoded a second time per row.
    /// </param>
    /// <param name="files">The survey's files, IN SURVEY ORDER and unfiltered.</param>
    /// <param name="previous">
    /// The strips from the last snapshot, in the same order, or null. A row whose
    /// strip has not changed gets the SAME INSTANCE back, which is what stops a
    /// settled table repainting every row ten times a second: the control's
    /// dependency property sees no change and does not redraw.
    /// </param>
    public static IReadOnlyList<FileStripModel?> Build(
        IReadOnlyList<BlockState> setStates,
        IReadOnlyList<SurveyFile> files,
        IReadOnlyList<FileStripModel?>? previous = null)
    {
        var strips = new FileStripModel?[files.Count];
        if (files.Count == 0 || setStates.Count == 0)
        {
            return strips;
        }

        // THE RECONCILIATION, and it is the whole guard. The offsets are a running
        // sum of blocks_total, so they are only meaningful if that sum IS the strip.
        var owed = 0L;
        foreach (var file in files)
        {
            owed += Math.Max(0, file.BlocksTotal);
        }

        if (owed != setStates.Count)
        {
            return strips;
        }

        var offset = 0;
        for (var f = 0; f < files.Count; f++)
        {
            var blocks = Math.Max(0, files[f].BlocksTotal);
            if (blocks == 0)
            {
                // An extra file owns no source blocks and must still appear in the
                // table, so it gets no strip rather than an empty one.
                offset += blocks;
                continue;
            }

            var fresh = Cut(setStates, offset, blocks, Math.Max(0, files[f].BlocksOk));
            var before = previous is not null && f < previous.Count ? previous[f] : null;
            strips[f] = before is not null && before.Matches(fresh) ? before : fresh;
            offset += blocks;
        }

        return strips;
    }

    /// <summary>Whether two strips draw the same picture over the same census.</summary>
    private bool Matches(FileStripModel other)
    {
        if (Blocks != other.Blocks || Ok != other.Ok || Bad != other.Bad
            || Cells.Count != other.Cells.Count)
        {
            return false;
        }

        for (var i = 0; i < Cells.Count; i++)
        {
            if (!Cells[i].Equals(other.Cells[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static FileStripModel Cut(
        IReadOnlyList<BlockState> setStates, int offset, int blocks, int ok)
    {
        // A view over the slice, so the rule sees indices 0..blocks-1 and the cells
        // it produces are the FILE's block numbers rather than the set's. Nothing is
        // copied: the shared decoded array is read through the window.
        var slice = new Slice(setStates, offset);
        var count = Math.Min(TargetCells, blocks);
        var cells = new List<MapCell>(count);
        var bad = 0;

        for (var c = 0; c < count; c++)
        {
            var (first, last) = BlockMapRule.Range(c, count, blocks);
            int damaged = 0, missing = 0, misnamed = 0;
            for (var i = first; i <= last; i++)
            {
                switch (slice[i])
                {
                    case BlockState.Damaged: damaged++; break;
                    case BlockState.Missing: missing++; break;
                    case BlockState.Misnamed: misnamed++; break;
                }
            }

            bad += damaged + missing;
            cells.Add(new MapCell(
                first,
                last - first + 1,
                BlockMapRule.Ground(slice, first, last),
                BlockMapRule.BadMark(slice, first, last),
                damaged,
                missing,
                misnamed));
        }

        return new FileStripModel(cells, blocks, ok, bad);
    }

    /// <summary>
    /// A read-only window onto the set-wide states, so <see cref="BlockMapRule"/>
    /// can be called on a member's range with no copy and no second code path.
    /// </summary>
    private sealed class Slice(IReadOnlyList<BlockState> states, int offset) : IReadOnlyList<BlockState>
    {
        public int Count => states.Count - offset;

        public BlockState this[int index] => states[offset + index];

        public IEnumerator<BlockState> GetEnumerator()
        {
            for (var i = 0; i < Count; i++)
            {
                yield return this[i];
            }
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
            GetEnumerator();
    }
}
