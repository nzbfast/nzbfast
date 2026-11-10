using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The Windows host's fixes from the 2026-11-09 parfast bug sweep, one test per
/// finding (the A-numbers are that sweep's), each written to fail on the code
/// before the fix.
/// </summary>
public class SweepFixTests
{
    private const string Store = @"C:\Users\someone\AppData\Local\parfast\queue.json";

    private static ShellViewModel Shell(MockCore core, string? store = Store) =>
        new(core, new ImmediateDispatcher(), new NullShellHost { QueueStorePath = store });

    // ---- A31: settings saved in the store are what the app starts with ----

    [Fact]
    public void SettingsSavedInTheStoreAreReadBackAndApplied()
    {
        var core = new MockCore
        {
            StoredSettings = new ParfastSettings
            {
                General = new GeneralSettings { Notifications = false, PurgeAfterRepair = true },
                Create = new CreateSettings { BlockCount = 1234 },
                Performance = new PerformanceSettings { Threads = 3 },
            },
        };
        var shell = Shell(core);

        Assert.False(shell.Settings.Notifications);
        Assert.Equal(3, shell.Settings.ThreadCount);
        Assert.Equal(1234, shell.Create.BlockCount);
        Assert.True(shell.Verify.Options.Purge);
        Assert.Equal(3, shell.Verify.Options.Threads);

        // And the first toggle writes the SAVED record plus one change, not the
        // factory defaults plus one change.
        shell.Settings.AutoCloseProgress = true;
        var written = core.GetSettings();
        Assert.False(written.General.Notifications);
        Assert.True(written.General.PurgeAfterRepair);
        Assert.Equal(1234, written.Create.BlockCount);
        Assert.True(written.General.AutoCloseProgress);
    }

    // ---- A3 (host half): an unreadable store is reported ----

    [Theory]
    // The core's two refusals (API.md, pf_queue_open_store, 9 Nov 2026). Shown
    // VERBATIM: a prefix of ours would call the newer-build store unreadable, and
    // the moved-aside case IS saving a fresh queue.
    [InlineData("queue.json was written by a newer parfast (version 3); it is left as it is and this session will not save the queue.")]
    [InlineData("queue.json could not be read and was moved aside to queue.json.unreadable-1762700000-4242; a new queue is being saved.")]
    public void AQueueStoreTheCoreRefusesShowsTheCoresOwnSentence(string message)
    {
        var shell = Shell(new MockCore { StoreFailure = message });

        Assert.Equal(message, shell.QueueStoreError);
        Assert.Equal(message, shell.Log[0]);
    }

    [Fact]
    public void ARefusalWithNoReasonNamesTheFile()
    {
        var shell = Shell(new MockCore { StoreFailure = string.Empty });

        Assert.Equal(Strings.Fill(Strings.ErrorReadFailed, "path", Store), shell.QueueStoreError);
    }

    [Fact]
    public void AQueueStoreThatOpensCarriesNoError() =>
        Assert.Null(Shell(new MockCore()).QueueStoreError);

    // ---- A30: a settings write leaves the queue's own fields alone ----

    [Fact]
    public void ASettingsWriteKeepsTheQueuesConcurrencyAndPostAction()
    {
        var core = new MockCore();
        var shell = Shell(core);

        shell.Queue.SetConcurrency(3);
        shell.Queue.SetPostAction(PostQueueAction.Shutdown);
        shell.Queue.ConfirmPostAction();

        shell.Settings.Notifications = !shell.Settings.Notifications;
        Assert.Equal(3, core.QueueSnapshot().Concurrency);
        Assert.Equal(PostQueueAction.Shutdown, core.QueueSnapshot().PostAction);

        // The other direction: one the user CLEARED must not come back.
        shell.Queue.SetPostAction(PostQueueAction.None);
        shell.Settings.ShowCommand = !shell.Settings.ShowCommand;
        Assert.Equal(PostQueueAction.None, core.QueueSnapshot().PostAction);

        // And resetting the Settings page is a settings write like any other.
        shell.Queue.SetPostAction(PostQueueAction.Notify);
        shell.Settings.ResetCommand.Execute(null);
        Assert.Equal(3, core.QueueSnapshot().Concurrency);
        Assert.Equal(PostQueueAction.Notify, core.QueueSnapshot().PostAction);
    }

    // ---- A32: every control of a Settings page batch handler can change ----

    [Fact]
    public void WritingTheValueAlreadyHeldRaisesNothing()
    {
        var shell = Shell(new MockCore());
        var raised = 0;
        shell.Settings.PropertyChanged += (_, _) => raised++;

        shell.Settings.Notifications = shell.Settings.Notifications;
        shell.Settings.AutomaticThreads = shell.Settings.AutomaticThreads;
        shell.Settings.LogLevelIndex = shell.Settings.LogLevelIndex;
        Assert.Equal(0, raised);
    }

    [Fact]
    public void ReassertingAutoOffKeepsACustomThreadCount()
    {
        var shell = Shell(new MockCore());

        // A count that CANNOT be the processor count, which is what turning Auto
        // off picks: with 4 here the test passed with the fix reverted on any
        // four-core runner.
        var custom = Environment.ProcessorCount + 3;
        shell.Settings.ThreadCount = custom;

        // What the page's performance handler does on a click on ANY checkbox in
        // the group, Fast solver included.
        shell.Settings.AutomaticThreads = false;
        Assert.Equal(custom, shell.Settings.ThreadCount);
    }

    [Fact]
    public void ATypedValueThatNormalisesToTheHeldOneStillRefreshesThePage()
    {
        var core = new MockCore();
        var shell = Shell(core);
        Assert.Equal(0, shell.Settings.MemoryMb);
        var before = core.GetSettings();
        var raised = 0;
        shell.Settings.PropertyChanged += (_, _) => raised++;

        // -5 means "no limit", which is already the setting: nothing to write,
        // but the box holding "-5" has to be told to show what is really set.
        shell.Settings.MemoryMb = -5;
        Assert.Equal(1, raised);
        Assert.Equal(before, core.GetSettings());

        // And a plain re-assertion of the held value stays silent.
        shell.Settings.MemoryMb = 0;
        Assert.Equal(1, raised);
    }

    /// <summary>
    /// The Settings page's batch handler, modelled without WinUI: four checkboxes,
    /// a Sync that rewrites all four from the view model on every notification
    /// (SettingsPage.Sync), and a handler that assigns all four in order
    /// (SettingsPage.OnGeneralChanged). The user flips each box in turn.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void EveryControlOfABatchHandlerCanChange(int touched)
    {
        var vm = Shell(new MockCore()).Settings;
        var boxes = new bool[4];
        var syncing = false;
        void Sync()
        {
            syncing = true;
            boxes[0] = vm.PurgeAfterRepair;
            boxes[1] = vm.KeepDamaged;
            boxes[2] = vm.Notifications;
            boxes[3] = vm.AutoCloseProgress;
            syncing = false;
        }

        void OnGeneralChanged()
        {
            if (syncing)
            {
                return;
            }

            vm.PurgeAfterRepair = boxes[0];
            vm.KeepDamaged = boxes[1];
            vm.Notifications = boxes[2];
            vm.AutoCloseProgress = boxes[3];
        }

        vm.PropertyChanged += (_, _) => Sync();
        Sync();
        var before = (bool[])boxes.Clone();

        boxes[touched] = !boxes[touched];
        OnGeneralChanged();

        bool[] after = [vm.PurgeAfterRepair, vm.KeepDamaged, vm.Notifications, vm.AutoCloseProgress];
        for (var i = 0; i < 4; i++)
        {
            Assert.Equal(i == touched ? !before[i] : before[i], after[i]);
        }
    }

    // ---- A42: closing asks only while work would be lost ----

    [Fact]
    public void ClosingNeedsConfirmationOnlyWhileAJobIsRunningOrPaused()
    {
        var core = new MockCore();
        var shell = Shell(core);
        Assert.False(shell.CloseNeedsConfirmation);

        shell.Verify.Open(@"D:\sets\damaged.par2", autoRepair: false);
        core.Advance(TimeSpan.FromMilliseconds(100));
        Assert.True(shell.CloseNeedsConfirmation);

        for (var i = 0; i < 60 && core.QueueSnapshot().Jobs.Any(j => !j.IsFinished); i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.False(shell.CloseNeedsConfirmation);
    }

    // ---- B (Windows): verify then repair after a verify the screen never saw running ----

    [Fact]
    public void VerifyThenRepairFiresForAVerifyFirstSeenAlreadyDone()
    {
        var core = new MockCore();
        var verify = new VerifyViewModel(core);
        verify.Open(@"D:\sets\damaged.par2", autoRepair: true);

        // The whole verify happens between two polls: the first snapshot this
        // screen applies is already Done.
        for (var i = 0; i < 60 && core.QueueSnapshot().Jobs.Any(j => !j.IsFinished); i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
        }

        verify.Apply(core.QueueSnapshot(), 100);
        Assert.Equal(2, core.QueueSnapshot().Jobs.Count);
        Assert.Equal(JobKind.Repair, core.QueueSnapshot().Jobs[^1].Kind);

        // Once, not per poll: the repair is now the screen's job, and the verify
        // the arm belonged to is spent.
        verify.Apply(core.QueueSnapshot(), 100);
        verify.Apply(core.QueueSnapshot(), 100);
        Assert.Equal(2, core.QueueSnapshot().Jobs.Count);
    }

    // ---- B (Windows): a verify that failed says why ----

    private static VerifyViewModel Ended(JobState state, JobKind kind, Verdict verdict)
    {
        var verify = new VerifyViewModel(new MockCore());
        verify.Open(@"D:\sets\a.par2", autoRepair: false);

        // The real core's shape (parfast_session runner, Outcome::failed): the
        // job is Failed, and the survey is still the PENDING one, reading
        // Verifying, because a failed load publishes no survey of its own.
        verify.Apply(new QueueSnapshot
        {
            Jobs =
            [
                new JobSnapshot
                {
                    Id = verify.JobId,
                    Kind = kind,
                    State = state,
                    Error = new JobError { Code = "load_failed", Message = @"could not load D:\sets\a.par2" },
                    Survey = new Survey { SetName = "a.par2", Verdict = verdict },
                },
            ],
        }, 100);
        return verify;
    }

    [Fact]
    public void AFailedVerifyShowsItsReasonRatherThanVerifyingForever()
    {
        var verify = Ended(JobState.Failed, JobKind.Verify, Verdict.Verifying);

        Assert.Equal(PillTone.Bad, verify.StatusTone);
        Assert.Contains("could not load", verify.StatusText, StringComparison.Ordinal);
        Assert.DoesNotContain("Verifying", verify.StatusText, StringComparison.Ordinal);
    }

    [Fact]
    public void ACancelledVerifySaysCancelled()
    {
        var verify = Ended(JobState.Cancelled, JobKind.Verify, Verdict.Verifying);

        Assert.Equal(Strings.VerifyPillCancelled, verify.StatusText);
        Assert.Equal(PillTone.Neutral, verify.StatusTone);
    }

    [Fact]
    public void AFailedRepairKeepsTheRepairFailedPill()
    {
        // A repair's own Failed verdict is settled and keeps its copy.
        var verify = Ended(JobState.Failed, JobKind.Repair, Verdict.Failed);

        Assert.Equal(PillTone.Bad, verify.StatusTone);
        Assert.StartsWith(Strings.VerifyPillRepairFailed.Split('{')[0], verify.StatusText, StringComparison.Ordinal);
    }

    // ---- Core lane adaptations (9 Nov 2026 contract) ----

    private static JobSnapshot Decode(string json) =>
        ParfastJson.TryRead<JobSnapshot>(json, out var error) ?? throw new Xunit.Sdk.XunitException(error);

    [Fact]
    public void TheQueueNamesAJobByTheCoresTitle()
    {
        var job = Decode("""{"id":7,"kind":"verify","state":"done","title":"D:\\sets\\Show.par2"}""");
        Assert.Equal("Show.par2", new QueueRow(job).Name);

        // No title and no fallback: blank, not a crash.
        Assert.Equal(string.Empty, new QueueRow(Decode("""{"id":8,"kind":"verify","state":"done","title":""}""")).Name);
    }

    [Fact]
    public void TheMockTitlesItsJobsAsTheCoreDoes()
    {
        var core = new MockCore();
        var shell = Shell(core);
        shell.Verify.Open(@"D:\sets\damaged.par2", autoRepair: false);
        core.Advance(TimeSpan.FromMilliseconds(100));

        var job = core.QueueSnapshot().Jobs.Single();
        Assert.Equal("damaged.par2", job.Title);
        Assert.Equal("damaged.par2", shell.Queue.Rows.Single().Name);
    }

    [Fact]
    public void CancellingAFinishedJobLeavesItAsItFinished()
    {
        var core = new MockCore();
        var verify = new VerifyViewModel(core);
        verify.Open(@"D:\sets\clean.par2", autoRepair: false);
        for (var i = 0; i < 60 && core.QueueSnapshot().Jobs.Any(j => !j.IsFinished); i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.Equal(JobState.Done, core.Snapshot(verify.JobId)!.State);
        core.Cancel(verify.JobId);
        Assert.Equal(JobState.Done, core.Snapshot(verify.JobId)!.State);
    }

    [Fact]
    public void WarningsOnAResultAreShownBesideDone()
    {
        var job = Decode("""
            {"id":3,"kind":"create","state":"done","title":"x.par2",
             "result":{"warnings":["Skipping 0 byte file: empty.bin","D:\\x\\locked could not be read"]}}
            """);

        var row = new QueueRow(job);
        Assert.StartsWith(Strings.QueueStateDone, row.StatusText, StringComparison.Ordinal);
        Assert.Contains("Skipping 0 byte file", row.StatusText, StringComparison.Ordinal);
        Assert.Contains("could not be read", row.Detail, StringComparison.Ordinal);
        Assert.Equal(PillTone.Warn, row.Tone);

        Assert.Null(new QueueRow(job with { Result = new JobResult() }).Detail);
    }

    [Theory]
    [InlineData(5.5, true)]
    [InlineData(5.0, false)]
    public void AProgressSheetWithWarningsIsNotAutoClosed(double percent, bool warns)
    {
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher(), new NullShellHost(), null,
            _ => (256L * 1024 * 1024, DateTimeOffset.UnixEpoch, false));
        shell.Settings.AutoCloseProgress = true;
        shell.Create.Add([@"D:\work\a.bin"]);
        shell.Create.RecoveryMode = RecoveryMode.Percent;
        // 5.5% is rounded to a whole percent, which the planner warns about.
        shell.Create.RecoveryPercent = percent;
        shell.StartCreate(showProgress: true);

        for (var i = 0; i < 90 && core.QueueSnapshot().Jobs.Any(j => !j.IsFinished); i++)
        {
            core.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.Equal(JobState.Done, core.QueueSnapshot().Jobs.Single().State);
        Assert.Equal(warns, shell.Progress.HasWarnings);
        Assert.Equal(warns, shell.Progress.IsOpen);
    }

    [Theory]
    [InlineData("internal")]
    [InlineData("not_utf8")]
    [InlineData("output_is_a_source")]
    [InlineData("duplicate_name")]
    [InlineData("a_code_from_a_later_core")]
    public void AnyErrorCodeDecodesAndItsMessageIsShown(string code)
    {
        var job = Decode($$$"""
            {"id":4,"kind":"posting_set","state":"failed","title":"Show",
             "error":{"code":"{{{code}}}","message":"The core's own sentence."}}
            """);

        Assert.Equal(code, job.Error!.Code);
        Assert.Equal("The core's own sentence.", new QueueRow(job).Detail);
    }

    [Fact]
    public void AnUnrepairableVerdictWithNoShortfallOffersNoRepairAndCountsNoBlocks()
    {
        // Exit 6: a member the Main packet declares has no FileDesc. The set may
        // have every block it needs and still not be repairable.
        var verify = new VerifyViewModel(new MockCore());
        verify.Options.RenameOnly = true;
        verify.Open(@"D:\sets\a.par2", autoRepair: false);
        verify.Apply(new QueueSnapshot
        {
            Jobs =
            [
                new JobSnapshot
                {
                    Id = verify.JobId,
                    Kind = JobKind.Verify,
                    State = JobState.Done,
                    Result = new JobResult { ExitCode = 6 },
                    Survey = new Survey
                    {
                        SetName = "a.par2",
                        Verdict = Verdict.Unrepairable,
                        RecoveryAvailable = 10,
                        RecoveryNeeded = 0,
                    },
                },
            ],
        }, 100);

        Assert.Equal(Verdict.Unrepairable, verify.Verdict);
        Assert.Equal(PillTone.Bad, verify.StatusTone);
        Assert.False(verify.CanRepair);
        Assert.DoesNotContain("0", verify.StatusText, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(verify.StatusText));
    }

    [Fact]
    public void AnOversizedEngineCountDoesNotFailTheWholeSnapshot()
    {
        // u64 values past int: the snapshot used to fail to decode outright.
        var queue = ParfastJson.TryRead<QueueSnapshot>("""
            {"jobs":[{"id":1,"kind":"verify","state":"done","title":"a.par2",
              "survey":{"source_blocks":5000000000,"recovery_available":18446744073709551615,
                        "recovery_needed":3,"verdict":"repairable",
                        "files":[{"name":"a.bin","blocks_ok":4294967296,"blocks_total":4294967296}],
                        "block_runs":[[1,5000000000]]}}]}
            """, out var error);

        Assert.Null(error);
        var survey = queue!.Jobs[0].Survey!;
        Assert.Equal(int.MaxValue, survey.SourceBlocks);
        Assert.Equal(int.MaxValue, survey.RecoveryAvailable);
        Assert.Equal(3, survey.RecoveryNeeded);
        Assert.Equal(int.MaxValue, survey.Files[0].BlocksTotal);
        Assert.Equal([1, int.MaxValue], survey.BlockRuns[0]);

        var preview = ParfastJson.TryRead<PlanPreview>(
            """{"block_count":5000000000,"recovery_blocks":70000,"source_files":3,"files":[{"name":"a","blocks":9999999999}]}""",
            out var previewError);
        Assert.Null(previewError);
        Assert.Equal(int.MaxValue, preview!.BlockCount);
        Assert.Equal(70000, preview.RecoveryBlocks);
        Assert.Equal(int.MaxValue, preview.Files[0].Blocks);

        // Writing is untouched.
        Assert.Contains("\"concurrency\":3", ParfastJson.Write(new ParfastSettings { Concurrency = 3 }), StringComparison.Ordinal);
    }
    // ---- Show in folder after a repair (first Windows run, 9 Nov 2026) ----

    [Fact]
    public void ARepairSurveyWithNoFolderStillNamesTheSetAndItsFolder()
    {
        var shell = Shell(new MockCore());
        shell.Verify.Open(@"D:\sets\holiday.par2", autoRepair: false);
        shell.Mode = Mode.Verify;

        // What the core sends for a repair: a survey whose set_name and folder
        // are EMPTY strings, not absent.
        var repair = new JobSnapshot
        {
            Id = shell.Verify.JobId,
            Kind = JobKind.Repair,
            State = JobState.Done,
            Survey = new Survey { SetName = string.Empty, Folder = string.Empty },
        };
        shell.Verify.Apply(new QueueSnapshot { Jobs = [repair] }, 64);

        Assert.Equal(@"D:\sets", shell.Verify.Folder);
        Assert.Equal("holiday.par2", shell.Verify.SetName);
        Assert.True(shell.RevealCommand.CanExecute(null));

        // Negative control: a survey that does name them still wins.
        var named = repair with { Survey = new Survey { SetName = "x.par2", Folder = @"E:\x" } };
        shell.Verify.Apply(new QueueSnapshot { Jobs = [named] }, 64);
        Assert.Equal(@"E:\x", shell.Verify.Folder);
        Assert.Equal("x.par2", shell.Verify.SetName);
    }
}
