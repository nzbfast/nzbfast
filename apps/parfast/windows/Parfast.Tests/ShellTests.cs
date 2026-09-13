using Parfast.Core;
using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>Drop routing, the queue, the progress sheet and the copy rules.</summary>
public class ShellTests
{
    /// <summary>
    /// A shell over the mock with a FAKE FILESYSTEM: any path answers with a
    /// plausible size, so the drop path and the Create screen can be driven
    /// without files on disk.
    /// </summary>
    private static (ShellViewModel Shell, MockCore Core, NullShellHost Host) New()
    {
        var core = new MockCore();
        var host = new NullShellHost();
        var shell = new ShellViewModel(core, new ImmediateDispatcher(), host, null, FakeStat);
        return (shell, core, host);
    }

    private static (long Size, DateTimeOffset Modified, bool IsFolder)? FakeStat(string path) =>
        PathUtil.Extension(path).Length == 0
            ? (0L, DateTimeOffset.UnixEpoch, true)
            : (256L * 1024 * 1024, DateTimeOffset.UnixEpoch, false);

    [Theory]
    [InlineData(DropTarget.Verify, @"D:\x\set.par2")]
    [InlineData(DropTarget.Verify, @"D:\x\SET.PAR2")]
    [InlineData(DropTarget.ChecksumVerify, @"D:\x\set.sfv")]
    [InlineData(DropTarget.ChecksumVerify, @"D:\x\set.md5")]
    [InlineData(DropTarget.ChecksumVerify, @"D:\x\set.sha256")]
    [InlineData(DropTarget.Create, @"D:\x\movie.mkv")]
    [InlineData(DropTarget.Create, @"D:\x\a folder")]
    public void OneItemRoutesByExtension(DropTarget expected, string path) =>
        Assert.Equal(expected, DropRouter.Route([path]));

    [Fact]
    public void APar2AnywhereInTheDropWins()
    {
        // A folder plus its index file means "verify that set", which is the most
        // specific reading of the gesture.
        Assert.Equal(DropTarget.Verify, DropRouter.Route([@"D:\x", @"D:\x\set.par2"]));
        Assert.Equal(DropTarget.Verify, DropRouter.Route([@"D:\x\a.rar", @"D:\x\set.par2"]));
    }

    [Fact]
    public void AChecksumFileWinsOnlyWhenItIsTheWholeDrop()
    {
        Assert.Equal(DropTarget.ChecksumVerify, DropRouter.Route([@"D:\x\a.sfv", @"D:\x\b.md5"]));
        // Five files one of which is a .sfv is a pile to create a set from.
        Assert.Equal(DropTarget.Create, DropRouter.Route([@"D:\x\a.sfv", @"D:\x\movie.mkv"]));
    }

    [Fact]
    public void TheIndexFileIsPreferredOverAVolume()
    {
        Assert.Equal(@"D:\x\set.par2", DropRouter.Par2Of(
            [@"D:\x\set.vol000+100.par2", @"D:\x\set.par2", @"D:\x\set.vol100+100.par2"]));

        // A drop of volumes only still opens something rather than nothing.
        Assert.Equal(@"D:\x\set.vol000+100.par2", DropRouter.Par2Of(
            [@"D:\x\set.vol000+100.par2", @"D:\x\set.vol100+1000.par2"]));
    }

    [Fact]
    public void DroppingAPar2SwitchesToVerifyAndStartsIt()
    {
        var (shell, core, _) = New();
        shell.Drop([@"D:\sets\damaged.par2"]);

        Assert.Equal(Mode.Verify, shell.Mode);
        Assert.True(shell.Verify.JobId >= 0);
        Assert.True(shell.Progress.IsOpen);

        core.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(Verdict.Repairable, shell.Verify.Verdict);
    }

    [Fact]
    public void DroppingFilesSwitchesToCreateAndPopulatesSources()
    {
        var (shell, _, _) = New();
        shell.Drop([@"D:\work\a.mkv", @"D:\work\b.mkv"]);

        Assert.Equal(Mode.Create, shell.Mode);
        Assert.Equal(2, shell.Create.Sources.Count);
        // The base folder and the output name are filled in from the sources.
        Assert.Equal(@"D:\work", shell.Create.BasePath);
        Assert.EndsWith(".par2", shell.Create.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void DroppingWhileAJobRunsAddsToTheQueueWithoutOpeningTheSheet()
    {
        var (shell, core, _) = New();
        shell.Drop([@"D:\sets\10k.par2"]);
        core.Advance(TimeSpan.FromSeconds(1));
        shell.Progress.Close();

        shell.Drop([@"D:\sets\clean.par2"]);

        Assert.False(shell.Progress.IsOpen);
        core.Advance(TimeSpan.Zero);
        Assert.Equal(2, shell.Queue.Rows.Count);
    }

    [Fact]
    public void TheQueueRunsOneJobAtATimeInOrderByDefault()
    {
        var (shell, core, _) = New();
        var first = shell.Create.Start();
        shell.Create.Add([@"D:\work\a.bin"]);
        var second = shell.Create.Start();
        var third = shell.Create.Start();

        core.Advance(TimeSpan.Zero);
        var states = core.QueueSnapshot().Jobs.ToDictionary(j => j.Id, j => j.State);
        Assert.Equal(JobState.Running, states[first]);
        Assert.Equal(JobState.Queued, states[second]);
        Assert.Equal(JobState.Queued, states[third]);

        // Thirty seconds is exactly one SlowCreate, so after it the first is done
        // and the second has taken its place: the order is kept.
        core.Advance(TimeSpan.FromSeconds(31));
        states = core.QueueSnapshot().Jobs.ToDictionary(j => j.Id, j => j.State);
        Assert.Equal(JobState.Done, states[first]);
        Assert.Equal(JobState.Running, states[second]);
        Assert.Equal(JobState.Queued, states[third]);

        // One second at a time from here, the way the 50 ms timer does it: a
        // single large jump would hand the whole remainder to one job, because
        // the mock starts the next job only after the step that finished the
        // previous one.
        for (var i = 0; i < 120 && core.QueueSnapshot().RunningCount > 0; i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.All(core.QueueSnapshot().Jobs, j => Assert.Equal(JobState.Done, j.State));
    }

    [Fact]
    public void RunNowTakesTheSelectedJobNextWithoutStartingTheOnesAheadOfIt()
    {
        // The two things a host can do WITHOUT pf_job_run_next are both wrong, and
        // this is the test that tells them apart: raising the concurrency would
        // start the two jobs ahead of the chosen one as well, and resuming it only
        // lets the scheduler reach it in its turn. Exactly one job leaves the
        // queue, and WHICH one is the pick.
        var (shell, core, _) = New();
        var first = shell.Create.Start();
        var second = shell.Create.Start();
        var third = shell.Create.Start();
        core.Advance(TimeSpan.Zero);

        // The first is already running, so the pick is between the second and the
        // third. Choose the third.
        shell.Queue.Selected.Clear();
        shell.Queue.Selected.Add(shell.Queue.Rows.First(r => r.Id == third));
        shell.Queue.RunNowCommand.Execute(null);

        // Let the running job finish so the scheduler picks its successor.
        for (var i = 0; i < 40 && core.QueueSnapshot().Jobs.First(j => j.Id == first).State
                 != JobState.Done; i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
        }

        core.Advance(TimeSpan.Zero);
        var states = core.QueueSnapshot().Jobs.ToDictionary(j => j.Id, j => j.State);
        Assert.Equal(JobState.Done, states[first]);
        Assert.Equal(JobState.Running, states[third]);
        Assert.Equal(JobState.Queued, states[second]);
    }

    [Fact]
    public void RaisingTheConcurrencyStartsMoreAtOnce()
    {
        var (shell, core, _) = New();
        shell.Create.Start();
        shell.Create.Start();
        shell.Create.Start();

        shell.Queue.SetConcurrency(3);
        core.Advance(TimeSpan.Zero);

        Assert.Equal(3, core.QueueSnapshot().RunningCount);
        Assert.Equal(3, shell.Queue.Concurrency);
        Assert.Equal(Strings.Fill(Strings.QueueConcurrencyN, "n", "3"), shell.Queue.ConcurrencyText);
    }

    [Fact]
    public void PausingTheQueuePausesWhatIsRunning()
    {
        var (shell, core, _) = New();
        shell.Create.Start();
        core.Advance(TimeSpan.FromSeconds(2));

        shell.Queue.PauseCommand.Execute(null);
        core.Advance(TimeSpan.Zero);
        Assert.True(shell.Queue.Paused);
        Assert.Equal("Resume queue", shell.Queue.PauseText);
        Assert.Equal(JobState.Paused, core.QueueSnapshot().Jobs[0].State);

        var frozen = core.QueueSnapshot().Jobs[0].Progress;
        core.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(frozen, core.QueueSnapshot().Jobs[0].Progress, 6);

        shell.Queue.PauseCommand.Execute(null);
        core.Advance(TimeSpan.FromSeconds(5));
        Assert.True(core.QueueSnapshot().Jobs[0].Progress > frozen);
    }

    [Fact]
    public void SleepAndShutDownAskForConfirmationWhenSetAndNotWhenTheyFire()
    {
        var (shell, _, _) = New();
        shell.Queue.SetPostAction(PostQueueAction.Notify);
        Assert.Null(shell.Queue.PendingConfirmation);

        // Against the shared constants, not their words: what matters is that the
        // right question is raised for the right action, and that the two are not
        // the same question.
        shell.Queue.SetPostAction(PostQueueAction.Shutdown);
        Assert.Equal(Strings.QueueFinishConfirmShutdown, shell.Queue.PendingConfirmation);

        shell.Queue.PendingConfirmation = null;
        shell.Queue.SetPostAction(PostQueueAction.Sleep);
        Assert.Equal(Strings.QueueFinishConfirmSleep, shell.Queue.PendingConfirmation);
        Assert.NotEqual(Strings.QueueFinishConfirmShutdown, Strings.QueueFinishConfirmSleep);
    }

    [Fact]
    public void OnlyAFinishedJobCanBeRemoved()
    {
        var (shell, core, _) = New();
        var id = shell.Create.Start();
        core.Advance(TimeSpan.FromSeconds(1));

        Assert.False(core.Remove(id));
        Assert.Equal("job_running", core.LastError()!.Code);

        core.Advance(TimeSpan.FromSeconds(40));
        Assert.True(core.Remove(id));
        Assert.Empty(core.QueueSnapshot().Jobs);
    }

    [Fact]
    public void TheProgressBarNeverGoesBackwards()
    {
        var (shell, core, _) = New();
        var id = shell.Create.Start();
        shell.Progress.Open(id);

        var seen = new List<double>();
        for (var i = 0; i < 40; i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
            seen.Add(shell.Progress.Progress);
        }

        for (var i = 1; i < seen.Count; i++)
        {
            Assert.True(seen[i] >= seen[i - 1], $"progress went {seen[i - 1]} to {seen[i]} at step {i}");
        }

        Assert.Equal(1.0, seen[^1]);
    }

    [Fact]
    public void AFinishedJobNotifiesOnlyWhenTheWindowIsNotFrontmost()
    {
        var (shell, core, host) = New();
        shell.WindowActive = true;
        shell.Progress.Open(shell.Create.Start());
        core.Advance(TimeSpan.FromSeconds(35));
        Assert.Empty(host.Notifications);

        shell.WindowActive = false;
        shell.Progress.Open(shell.Create.Start());
        core.Advance(TimeSpan.FromSeconds(35));
        Assert.Single(host.Notifications);
        Assert.Contains("finished", host.Notifications[0].Title, StringComparison.Ordinal);
    }

    [Fact]
    public void CopyCommandPutsTheEquivalentLineOnTheClipboard()
    {
        var (shell, _, host) = New();
        shell.Drop([@"D:\work\a.bin", @"D:\work\b.bin"]);
        shell.CopyCommandCommand.Execute(null);

        Assert.NotNull(host.Clipboard);
        Assert.StartsWith("parfast c ", host.Clipboard!, StringComparison.Ordinal);
    }

    [Fact]
    public void CopyingTheCommandSaysItCopied()
    {
        // A button whose whole effect is invisible gets pressed twice, and then the
        // user wonders whether it worked at all.
        var (shell, _, host) = New();
        shell.Drop([@"D:\work\a.bin"]);
        Assert.Null(shell.CopyConfirmation);

        shell.CopyCommandCommand.Execute(null);
        Assert.NotNull(host.Clipboard);
        Assert.Equal(Strings.CommonCommandCopied, shell.CopyConfirmation);

        // And nothing is claimed when there was nothing to copy.
        var (empty, _, emptyHost) = New();
        empty.CopyCommandCommand.Execute(null);
        Assert.Null(emptyHost.Clipboard);
        Assert.Null(empty.CopyConfirmation);
    }

    [Fact]
    public void TheSourcesFooterReadsOneFileAndNotOneFiles()
    {
        var (shell, _, _) = New();
        shell.Drop([@"D:\work\only.bin"]);
        Assert.Contains(Strings.CommonOneFile, shell.Create.SourcesFooter, StringComparison.Ordinal);

        shell.Create.Add([@"D:\work\second.bin"]);
        Assert.DoesNotContain(Strings.CommonOneFile, shell.Create.SourcesFooter, StringComparison.Ordinal);
        Assert.Contains("2", shell.Create.SourcesFooter, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAnswerTheAppCannotReadReachesTheLogInsteadOfVanishing()
    {
        // The decoder is deliberately forgiving so a 10 Hz poll cannot become an
        // exception per tick. The cost is that a shape this build genuinely cannot
        // read degrades to a STALE SCREEN with nothing on it saying so - which
        // looks exactly like a job that stopped making progress, and is the worst
        // failure this app can have.
        var (shell, core, _) = New();
        shell.Verify.Open(@"D:\sets\damaged.par2", autoRepair: false);
        core.Advance(TimeSpan.FromSeconds(1));
        Assert.DoesNotContain(shell.Log, l => l.Contains("could not read", StringComparison.Ordinal));

        core.PendingDecodeError = "JobSnapshot: 'phase' was not a string";
        core.Advance(TimeSpan.FromSeconds(1));

        var reported = shell.Log.Where(l => l.Contains("could not read", StringComparison.Ordinal)).ToList();
        Assert.Single(reported);
        Assert.Contains("was not a string", reported[0], StringComparison.Ordinal);

        // AT THE TOP, because a log tail scrolls and the line explaining why the
        // rest of it stopped moving must not be the one that scrolled away.
        Assert.Equal(reported[0], shell.Log[0]);
    }

    [Fact]
    public void ARepeatingDecodeFailureDoesNotFloodTheLog()
    {
        // A core answering an unreadable shape answers it on EVERY poll, so an
        // uncapped list is ten identical lines a second and the log becomes
        // unreadable at exactly the moment somebody needs to read it.
        var (shell, core, _) = New();
        shell.Verify.Open(@"D:\sets\damaged.par2", autoRepair: false);

        for (var i = 0; i < 30; i++)
        {
            core.PendingDecodeError = "JobSnapshot: same problem every time";
            core.Advance(TimeSpan.FromMilliseconds(100));
        }

        Assert.Single(shell.Log, l => l.Contains("same problem", StringComparison.Ordinal));

        // And distinct problems are kept, up to a handful.
        for (var i = 0; i < 20; i++)
        {
            core.PendingDecodeError = $"JobSnapshot: problem {i}";
            core.Advance(TimeSpan.FromMilliseconds(100));
        }

        var reported = shell.Log.Count(l => l.Contains("could not read", StringComparison.Ordinal));
        Assert.InRange(reported, 2, 5);
    }

    [Fact]
    public void TheModeBadgeCountsRunningPlusWaiting()
    {
        var (shell, core, _) = New();
        shell.Create.Start();
        shell.Create.Start();
        shell.Create.Start();
        core.Advance(TimeSpan.Zero);

        Assert.Equal(3, shell.Queue.BadgeCount);
        Assert.Equal(1, shell.Queue.RunningCount);
        Assert.Equal(2, shell.Queue.WaitingCount);
    }

    [Fact]
    public void PausingAJobIsOfferedOnlyWhenTheCoreSaysItCan()
    {
        var core = new MockCore { Capabilities = new Capabilities { Pause = false } };
        var shell = new ShellViewModel(core, new ImmediateDispatcher());
        shell.Progress.Open(shell.Create.Start());
        core.Advance(TimeSpan.FromSeconds(1));

        Assert.False(shell.Progress.CanPause);
        Assert.False(shell.Progress.PauseCommand.CanExecute(null));
    }
}
