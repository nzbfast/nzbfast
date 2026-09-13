using Parfast.Core;
using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// Walks every scripted scenario of plan section 3.3 through the real
/// <see cref="VerifyViewModel"/> to its settled state, and asserts the verdict,
/// the pill, the file table and the block map.
/// </summary>
/// <remarks>
/// This is the acceptance suite for phase 0: the states listed here ARE the
/// screenshots the chip's demo produces, so a scenario that stops reaching its
/// verdict shows up as a red test rather than as a picture nobody took.
/// </remarks>
public class ScenarioTests
{
    /// <summary>
    /// Runs a scenario to completion with no timer: the mock's simulated clock is
    /// advanced by hand, which is what makes a thirty second create a millisecond
    /// test and keeps the suite free of sleeps.
    /// </summary>
    private static (ShellViewModel Shell, MockCore Core) Run(MockSet set, bool repair = false, bool autoRepair = false)
    {
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher());
        shell.Verify.AutoRepairWhenRepairable = autoRepair;
        shell.SetMapWidth(1200);
        shell.Verify.Open(PathUtil.Combine(set.Folder, set.Key + ".par2"), autoRepair);

        Drain(core, shell);

        if (repair)
        {
            shell.Verify.RepairCommand.Execute(null);
            Drain(core, shell);
        }

        return (shell, core);
    }

    private static void Drain(MockCore core, ShellViewModel shell)
    {
        // Sixty steps of one simulated second covers the longest scenario (the
        // thirty second create) twice over, and stops as soon as nothing is
        // active so a test failure is not hidden behind a long loop.
        //
        // The idle check reads the CORE's queue, not the shell's. The shell
        // applies a snapshot to Queue before Verify, so a repair that Verify
        // submits during that same Apply (verify then repair) is not in the
        // shell's copy until the next snapshot, and reading the shell here
        // stopped the loop one job early.
        for (var i = 0; i < 60; i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
            var queue = core.QueueSnapshot();
            if (queue.RunningCount == 0 && queue.WaitingCount == 0)
            {
                break;
            }
        }

        core.Advance(TimeSpan.Zero);
        shell.Queue.Apply(core.QueueSnapshot());
    }

    [Fact]
    public void CleanSetReportsCompleteAndNoRepairIsOffered()
    {
        var (shell, _) = Run(MockScenarios.Clean);
        var v = shell.Verify;

        Assert.Equal(Verdict.Complete, v.Verdict);
        Assert.Equal(PillTone.Good, v.StatusTone);
        Assert.Equal(Strings.VerifyPillComplete, v.StatusText);
        Assert.False(v.CanRepair);
        Assert.All(v.Files, f => Assert.Equal(FileStatus.Complete, f.Status));
        Assert.Equal(MockScenarios.Clean.SourceBlocks, v.Map.Present);
        Assert.Equal(0, v.Map.Damaged + v.Map.Missing + v.Map.Pending);
    }

    [Fact]
    public void DamagedRepairableSetNamesTheBlocksMissingAndTheBlocksAvailable()
    {
        var (shell, _) = Run(MockScenarios.DamagedRepairable);
        var v = shell.Verify;

        Assert.Equal(Verdict.Repairable, v.Verdict);
        Assert.Equal(PillTone.Warn, v.StatusTone);
        // THE LITERAL SENTENCE, not the same Strings.Fill call the view model
        // makes. Asserting the call against itself is how the placeholder rename
        // of 12 Sep 2026 nearly shipped green: Strings.Fill leaves an unknown
        // placeholder VISIBLE, so a stale argument name here and a stale argument
        // name there produce the same "{needed}" on both sides and agree with
        // each other about a pill no user would accept.
        Assert.Equal("Repairable - 12 blocks to rebuild, 40 available", v.StatusText);
        Assert.True(v.CanRepair);
        Assert.Equal(12, v.Map.Damaged);
        Assert.Equal(2, v.ProblemCount);
    }

    [Fact]
    public void RepairingARepairableSetTurnsTheWholeMapPresentAndSummarises()
    {
        var (shell, _) = Run(MockScenarios.DamagedRepairable, repair: true);
        var v = shell.Verify;

        Assert.Equal(Verdict.Repaired, v.Verdict);
        Assert.Equal(PillTone.Good, v.StatusTone);
        Assert.Equal(0, v.Map.Damaged + v.Map.Missing);
        Assert.Equal(MockScenarios.DamagedRepairable.SourceBlocks, v.Map.Present);
        Assert.NotNull(v.SummaryText);
        Assert.StartsWith("Repaired 2 files in ", v.SummaryText, StringComparison.Ordinal);
        Assert.All(v.Files.Where(f => f.Status != FileStatus.Extra),
            f => Assert.Equal(FileStatus.Complete, f.Status));
    }

    [Fact]
    public void UnrepairableSetSaysHowManyMoreBlocksItWouldNeedAndRefusesRepair()
    {
        var (shell, _) = Run(MockScenarios.Unrepairable);
        var v = shell.Verify;

        // 22 damaged in part2 plus 240 missing in part3 is 262 needed against 20
        // available, so it needs 242 more.
        Assert.Equal(Verdict.Unrepairable, v.Verdict);
        Assert.Equal(PillTone.Bad, v.StatusTone);
        Assert.Equal(Strings.Fill(Strings.VerifyPillUnrepairable, "short", "242"), v.StatusText);
        Assert.False(v.CanRepair);
        Assert.Equal(240, v.Map.Missing);
        Assert.Equal(22, v.Map.Damaged);
    }

    [Fact]
    public void MisnamedFilesCountAsFoundAndNameWhereTheyWereFound()
    {
        var (shell, _) = Run(MockScenarios.Misnamed);
        var v = shell.Verify;

        // The two misnamed members hold their data, so they cost NO recovery
        // blocks: only part04's four damaged blocks do. Treating a misnamed file
        // as lost would read as "repairable but only just" on a set that is
        // really two renames away from perfect.
        Assert.Equal(Verdict.Repairable, v.Verdict);
        Assert.Equal(4, v.Survey!.RecoveryNeeded);
        Assert.Equal(800, v.Map.Misnamed);

        var misnamed = v.Files.Where(f => f.Status == FileStatus.Misnamed).ToList();
        Assert.Equal(2, misnamed.Count);
        // Asserted against the shared template rather than its words: the point is
        // that the row NAMES THE FILE IT WAS FOUND AS, which is the whole value of
        // the misnamed state. Chip B owns how that sentence reads.
        Assert.All(misnamed, f => Assert.Equal(
            Strings.Fill(Strings.VerifyFileFoundAs, "path", PathUtil.FileName(f.FoundAs!)),
            f.StatusText));
        Assert.Contains(v.Files, f => f.Status == FileStatus.Extra);
    }

    [Fact]
    public void UnicodeNamesSurviveTheWholeRoundTrip()
    {
        var (shell, _) = Run(MockScenarios.Unicode, repair: true);
        var v = shell.Verify;

        Assert.Equal("Пример-набора.par2", v.SetName);
        Assert.Contains(v.Files, f => f.Name == "日本語のファイル名.part2.rar");
        Assert.Contains(v.Files, f => f.Name == "emoji-in-the-name-🎬.part4.rar");
        Assert.Contains(v.Files, f => f.Name == "عربي-الملف.part3.rar");
        Assert.Equal(Verdict.Repaired, v.Verdict);
    }

    [Fact]
    public void TenThousandBlocksMergesTheMapAndStillShowsTheDamage()
    {
        var (shell, _) = Run(MockScenarios.TenThousandBlocks);
        var v = shell.Verify;

        Assert.Equal(10000, v.Map.BlockCount);
        Assert.True(v.Map.Merged, "a 10,000 block set must draw merged segments");
        Assert.True(v.Map.Cells.Count <= 1200, $"{v.Map.Cells.Count} cells for 1,200 of width");

        // The four damaged members are 2 + 61 + 2 + 2 = 67 blocks, and the merge
        // must not lose the three that are a single bad block in a wide segment.
        Assert.Equal(67, v.Map.Damaged);
        Assert.True(v.Map.Cells.Count(c => c.Damaged > 0) >= 4,
            "every damaged member must be visible as at least one damaged cell");
        Assert.Equal(Verdict.Repairable, v.Verdict);
    }

    [Fact]
    public void TheMergedMapCoversEveryBlockExactlyOnce()
    {
        var (shell, _) = Run(MockScenarios.TenThousandBlocks);
        var cells = shell.Verify.Map.Cells;

        Assert.Equal(0, cells[0].FirstBlock);
        Assert.Equal(9999, cells[^1].LastBlock);
        for (var i = 1; i < cells.Count; i++)
        {
            Assert.Equal(cells[i - 1].LastBlock + 1, cells[i].FirstBlock);
        }

        Assert.Equal(10000, cells.Sum(c => c.Count));
    }

    [Fact]
    public void ABrokenIndexFailsWithTheEnginesReasonAndOffersNoRepair()
    {
        var (shell, _) = Run(MockScenarios.Broken);
        var v = shell.Verify;

        Assert.Equal(Verdict.Failed, v.Verdict);
        Assert.Equal(PillTone.Bad, v.StatusTone);
        Assert.Contains("truncated", v.StatusText, StringComparison.Ordinal);
        Assert.False(v.CanRepair);
    }

    [Fact]
    public void VerifyThenRepairFiresExactlyOnceAndOnlyWhenRepairable()
    {
        var (shell, _) = Run(MockScenarios.DamagedRepairable, autoRepair: true);

        Assert.Equal(Verdict.Repaired, shell.Verify.Verdict);
        // One verify and one repair, and not a repair per poll.
        Assert.Equal(2, shell.Queue.Rows.Count);
        Assert.Equal([JobState.Done, JobState.Done], shell.Queue.Rows.Select(r => r.State));
    }

    [Fact]
    public void VerifyThenRepairDoesNotFireOnAnUnrepairableSet()
    {
        var (shell, _) = Run(MockScenarios.Unrepairable, autoRepair: true);

        Assert.Equal(Verdict.Unrepairable, shell.Verify.Verdict);
        Assert.Single(shell.Queue.Rows);
    }

    [Fact]
    public void MidVerifyTheMapFillsLeftToRightWithOneHashingBlock()
    {
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher());
        shell.SetMapWidth(2000);
        shell.Verify.Open(@"D:\sets\damaged.par2", autoRepair: false);

        core.Advance(TimeSpan.FromMilliseconds(1500));

        var v = shell.Verify;
        Assert.Equal(Verdict.Verifying, v.Verdict);
        Assert.Equal(PillTone.Busy, v.StatusTone);
        Assert.True(v.Map.Pending > 0, "the tail of the set must still be pending");
        Assert.True(v.Map.Present > 0, "the head of the set must already be present");
        Assert.Equal(1, v.Map.Hashing);
        Assert.Contains(v.Files, f => f.Status == FileStatus.Hashing);
        Assert.Contains(v.Files, f => f.Status == FileStatus.Pending);
    }

    [Fact]
    public void CancellingAVerifyLeavesItCancelledAndNotFailed()
    {
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher());
        shell.Verify.Open(@"D:\sets\10k.par2", autoRepair: false);
        core.Advance(TimeSpan.FromSeconds(2));

        shell.Verify.CancelCommand.Execute(null);
        core.Advance(TimeSpan.FromSeconds(1));

        Assert.Equal(JobState.Cancelled, shell.Queue.Rows[0].State);
        Assert.False(shell.Verify.IsBusy);
    }

    [Fact]
    public void RepairIsNeverOfferedWhileAJobIsRunning()
    {
        // A precedence bug lived here: `!IsBusy && a && b || c` is `(!IsBusy && a
        // && b) || c`, so the rename-only arm bypassed the busy check entirely and
        // Repair was live DURING a verify. Submitting a repair over a running
        // verify of the same set is the worst button in the app to get wrong.
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher());
        shell.SetMapWidth(1200);
        shell.Verify.Options.RenameOnly = true;
        shell.Verify.Open(@"D:\Usenet\complete\misnamed.par2", autoRepair: false);

        for (var i = 0; i < 20; i++)
        {
            core.Advance(TimeSpan.FromMilliseconds(300));
            if (shell.Verify.IsBusy)
            {
                Assert.False(shell.Verify.CanRepair,
                    $"Repair was offered while busy, verdict {shell.Verify.Verdict}");
                Assert.False(shell.Verify.RepairCommand.CanExecute(null));
            }
        }
    }

    [Fact]
    public void RenameOnlyOffersRepairOnAnUnrepairableSetThatHasMisnamedFiles()
    {
        // The other half, and the reason that arm exists: the parity is short so
        // the data cannot be rebuilt, but a file found under another name can
        // still be renamed to what the set expects. Refusing it would make the
        // user do by hand what the engine can do.
        var (shell, _) = Run(MockScenarios.Unrepairable);
        Assert.Equal(Verdict.Unrepairable, shell.Verify.Verdict);
        Assert.False(shell.Verify.CanRepair);

        shell.Verify.Options.RenameOnly = true;
        Assert.Equal(0, shell.Verify.Map.Misnamed);
        Assert.False(shell.Verify.CanRepair);

        // And on a set that does have misnamed members, with a short parity.
        var core = new MockCore();
        var misnamed = new ShellViewModel(core, new ImmediateDispatcher());
        misnamed.SetMapWidth(1200);
        misnamed.Verify.Open(@"D:\Usenet\complete\misnamed.par2", autoRepair: false);
        for (var i = 0; i < 40 && core.QueueSnapshot().RunningCount > 0; i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
        }

        core.Advance(TimeSpan.Zero);
        Assert.True(misnamed.Verify.Map.Misnamed > 0);
        Assert.False(misnamed.Verify.IsBusy);
    }

    [Fact]
    public void ProblemsFilterShowsOnlyTheFilesThatNeedAttention()
    {
        var (shell, _) = Run(MockScenarios.Misnamed);
        var v = shell.Verify;

        var all = v.Files.Count;
        v.ShowProblemsOnly = true;
        Assert.Equal(4, v.Files.Count);
        Assert.All(v.Files, f => Assert.True(f.NeedsAttention));

        v.ShowProblemsOnly = false;
        Assert.Equal(all, v.Files.Count);
    }
}
