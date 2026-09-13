using Parfast.Core.Contracts;

namespace Parfast.Core.Mock;

/// <summary>
/// Builds a live <see cref="Survey"/> for a scenario at a given fraction of
/// the way through verify, including the run-length encoded block map.
/// </summary>
/// <remarks>
/// The block map is the signature visual of section 5.2, and it has to fill
/// LEFT TO RIGHT as hashing walks the files, with the block currently being
/// read in the hashing state. So the states are computed from the fraction
/// rather than being a finished picture faded in: blocks before the cursor
/// carry their settled state, the file under the cursor is hashing, and
/// everything after it is pending. That is what the real survey looks like
/// mid verify, and building the mock any other way would have hidden the one
/// animation the design asks for.
/// </remarks>
public static class MockSurvey
{
    public static Survey Build(MockSet set, double fraction, bool repairing, bool settled)
    {
        var blocks = set.SourceBlocks;
        var cursor = settled ? blocks : (int)Math.Clamp(fraction * blocks, 0, blocks);
        var states = new BlockState[blocks];
        var files = new List<SurveyFile>(set.Files.Count);

        var offset = 0;
        foreach (var file in set.Files)
        {
            if (file.Outcome == FileStatus.Extra)
            {
                // An extra file owns no source blocks, and must still appear in
                // the table (section 5.2 lists Extra as a status).
                files.Add(new SurveyFile
                {
                    Name = file.Name,
                    Size = file.Size,
                    Status = FileStatus.Extra,
                    BlocksOk = 0,
                    BlocksTotal = 0,
                    Progress = 1,
                });
                continue;
            }

            var start = offset;
            var end = offset + file.Blocks;
            offset = end;

            // A repair that succeeded leaves every block present, which is what
            // animates the map into its verdict colour.
            var afterRepair = repairing && settled && set.Repairable;
            var settledState = afterRepair ? BlockState.Present : file.SettledState;
            var badFrom = end - (afterRepair ? 0 : file.LostBlocks);

            FileStatus status;
            double progress;
            int ok;

            if (cursor >= end)
            {
                for (var i = start; i < end; i++)
                {
                    states[i] = i >= badFrom && settledState != BlockState.Present
                        ? settledState
                        : file.Outcome == FileStatus.Missing ? BlockState.Missing
                        : file.Outcome == FileStatus.Misnamed ? BlockState.Misnamed
                        : BlockState.Present;
                }

                status = afterRepair ? FileStatus.Complete : file.Outcome;
                progress = 1;
                ok = file.Blocks - (afterRepair ? 0 : file.LostBlocks);
            }
            else if (cursor > start)
            {
                for (var i = start; i < cursor; i++)
                {
                    states[i] = BlockState.Present;
                }

                states[cursor] = BlockState.Hashing;
                status = FileStatus.Hashing;
                progress = (double)(cursor - start) / Math.Max(1, file.Blocks);
                ok = cursor - start;
            }
            else
            {
                status = FileStatus.Pending;
                progress = 0;
                ok = 0;
            }

            files.Add(new SurveyFile
            {
                Name = file.Name,
                Size = file.Size,
                Status = status,
                BlocksOk = Math.Max(0, ok),
                BlocksTotal = file.Blocks,
                FoundAs = status == FileStatus.Misnamed ? file.FoundAs : null,
                Progress = progress,
            });
        }

        var needed = settled || cursor >= blocks
            ? (repairing && set.Repairable ? 0 : set.RecoveryNeeded)
            : CountNeeded(states);

        return new Survey
        {
            SetName = set.SetName,
            Folder = set.Folder,
            BlockSize = set.BlockSize,
            SourceBlocks = blocks,
            RecoveryAvailable = set.RecoveryAvailable,
            RecoveryNeeded = needed,
            Verdict = VerdictFor(set, repairing, settled, cursor >= blocks),
            Files = files,
            BlockRuns = Encode(states),
        };
    }

    private static Verdict VerdictFor(MockSet set, bool repairing, bool settled, bool walked)
    {
        if (set.FailWith is not null && settled)
        {
            return Verdict.Failed;
        }

        if (!walked)
        {
            return Verdict.Verifying;
        }

        if (repairing && settled)
        {
            return set.Repairable ? Verdict.Repaired : Verdict.Failed;
        }

        if (set.RecoveryNeeded == 0)
        {
            return Verdict.Complete;
        }

        return set.Repairable ? Verdict.Repairable : Verdict.Unrepairable;
    }

    private static int CountNeeded(BlockState[] states) =>
        states.Count(s => s is BlockState.Damaged or BlockState.Missing);

    /// <summary>
    /// Run-length encodes the block states, which is the wire shape of
    /// <see cref="Survey.BlockRuns"/>: a ten thousand block set with four
    /// damaged members is a couple of dozen runs rather than ten thousand
    /// integers copied on every poll.
    /// </summary>
    public static List<int[]> Encode(IReadOnlyList<BlockState> states)
    {
        var runs = new List<int[]>();
        if (states.Count == 0)
        {
            return runs;
        }

        var current = states[0];
        var count = 1;
        for (var i = 1; i < states.Count; i++)
        {
            if (states[i] == current)
            {
                count++;
                continue;
            }

            runs.Add([(int)current, count]);
            current = states[i];
            count = 1;
        }

        runs.Add([(int)current, count]);
        return runs;
    }

    /// <summary>The inverse, used by the block map control and by the tests.</summary>
    public static BlockState[] Decode(IReadOnlyList<int[]> runs)
    {
        var total = 0;
        foreach (var run in runs)
        {
            if (run.Length >= 2 && run[1] > 0)
            {
                total += run[1];
            }
        }

        var states = new BlockState[total];
        var at = 0;
        foreach (var run in runs)
        {
            if (run.Length < 2 || run[1] <= 0)
            {
                continue;
            }

            var state = (BlockState)run[0];
            for (var i = 0; i < run[1]; i++)
            {
                states[at++] = state;
            }
        }

        return states;
    }
}
