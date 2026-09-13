using Parfast.Core.Contracts;

namespace Parfast.Core.Mock;

/// <summary>One file in a mock PAR2 set, and what verify will conclude about it.</summary>
public sealed record MockFile(
    string Name,
    long Size,
    int Blocks,
    FileStatus Outcome,
    int BadBlocks = 0,
    string? FoundAs = null)
{
    /// <summary>Blocks verify cannot recover from this file's own data.</summary>
    public int LostBlocks => Outcome switch
    {
        FileStatus.Missing => Blocks,
        FileStatus.Damaged => Math.Min(BadBlocks, Blocks),
        // A misnamed file is FOUND, under another name, so its data is
        // present and costs no recovery blocks. Getting this wrong is the
        // difference between "rename two files" and "burn 40 recovery
        // blocks", which is exactly the judgement the verdict pill reports.
        _ => 0,
    };

    /// <summary>The block state a finished verify leaves this file's blocks in.</summary>
    public BlockState SettledState => Outcome switch
    {
        FileStatus.Complete => BlockState.Present,
        FileStatus.Damaged => BlockState.Damaged,
        FileStatus.Missing => BlockState.Missing,
        FileStatus.Misnamed => BlockState.Misnamed,
        _ => BlockState.Present,
    };
}

/// <summary>
/// A scripted scenario: the set a mock verify walks, and how fast it walks
/// it. The catalogue in <see cref="MockScenarios"/> covers every state plan
/// section 3.3 names, which is the set of pictures the app is judged on.
/// </summary>
public sealed record MockSet
{
    public required string Key { get; init; }
    public required string Title { get; init; }
    public required string SetName { get; init; }
    public required string Folder { get; init; }
    public long BlockSize { get; init; } = 1048576;
    public int RecoveryAvailable { get; init; }
    public required IReadOnlyList<MockFile> Files { get; init; }

    /// <summary>How long a full verify of this set takes in the mock, in milliseconds.</summary>
    public int VerifyMs { get; init; } = 6000;

    /// <summary>How long a repair takes once the solver has run.</summary>
    public int RepairMs { get; init; } = 4000;

    /// <summary>Set when the scenario exists to demonstrate a failure the engine reports.</summary>
    public string? FailWith { get; init; }

    public int SourceBlocks => Files.Where(f => f.Outcome != FileStatus.Extra).Sum(f => f.Blocks);

    public long TotalBytes => Files.Where(f => f.Outcome != FileStatus.Extra).Sum(f => f.Size);

    public int RecoveryNeeded => Files.Sum(f => f.LostBlocks);

    public bool Repairable => RecoveryNeeded <= RecoveryAvailable;
}
