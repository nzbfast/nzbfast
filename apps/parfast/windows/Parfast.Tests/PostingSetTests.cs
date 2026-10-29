using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The posting-set screen (plan B1) against the mock's RECORDED core frames: both
/// routes to Done, a cancel mid run, the capability gate, the spec the form
/// builds, and the password never leaving the spec.
/// </summary>
/// <remarks>
/// The mock plays apps/parfast/shared/contract/posting-set-snapshots.json, which
/// the core wrote on 25 Oct 2026, so what these tests see a finished job carry is
/// what the real core sends, not what a script here assumed it would.
/// </remarks>
public class PostingSetTests
{
    private const string Film = @"D:\Usenet\post\film.mkv";

    private static (ShellViewModel Shell, MockCore Core) NewShell(Capabilities? caps = null)
    {
        // Speed 0: the timer still ticks but moves no clock, so only Advance does.
        var core = new MockCore(speed: 0);
        if (caps is not null)
        {
            core.Capabilities = caps;
        }

        var shell = new ShellViewModel(core, new ImmediateDispatcher(), null, null, FakeStat);
        return (shell, core);
    }

    private static void Drain(MockCore core, ShellViewModel shell)
    {
        for (var i = 0; i < 120; i++)
        {
            core.Advance(TimeSpan.FromMilliseconds(250));
            var queue = core.QueueSnapshot();
            if (queue.RunningCount == 0 && queue.WaitingCount == 0)
            {
                break;
            }
        }

        core.Advance(TimeSpan.Zero);
        shell.Posting.Apply(core.QueueSnapshot());
    }

    private static PostingSetViewModel Filled(ShellViewModel shell)
    {
        shell.Mode = Mode.Posting;
        var p = shell.Posting;
        p.Add([Film]);
        return p;
    }

    [Fact]
    public void TheRecordingsLoadAndCarryBothRoutes()
    {
        Assert.Equal(PostingRoute.OnePass, PostingRecordings.OnePass.Snapshots[^1].Result?.Posting?.Route);
        Assert.Equal(PostingRoute.TwoPass, PostingRecordings.TwoPass.Snapshots[^1].Result?.Posting?.Route);
        Assert.Equal(JobKind.PostingSet, PostingRecordings.OnePass.Spec.Kind);
        Assert.False(string.IsNullOrEmpty(PostingRecordings.TwoPass.Snapshots[^1].Result!.Posting!.RouteReason));
    }

    [Fact]
    public void SourcesFillTheOutputFolderAndTheNameOnce()
    {
        var (shell, _) = NewShell();
        var p = Filled(shell);

        Assert.Equal(@"D:\Usenet\post", p.OutputDir);
        Assert.Equal("film", p.Name);

        p.Name = "Movie.2026";
        p.Add([@"D:\Usenet\post\extras.mkv"]);
        Assert.Equal("Movie.2026", p.Name);
    }

    [Fact]
    public void TheDefaultsAreThePostingDefaults()
    {
        var (shell, _) = NewShell();
        var spec = Filled(shell).ToSpec();

        Assert.Equal(RarSplit.None, spec.Rar.Volumes.Split);
        Assert.Equal(0, spec.Rar.Compression);
        Assert.False(spec.Rar.Solid);
        Assert.Null(spec.Rar.Password);
        Assert.Equal(0, spec.Rar.RecoveryPercent);
        Assert.True(spec.Rar.EncryptHeaders);
        Assert.True(shell.Posting.ExpectsOnePass);
        Assert.Equal(Strings.PostingRouteExpectOnePass, shell.Posting.RouteText);
    }

    [Fact]
    public void TheSpecSerialisesToTheContractShape()
    {
        var (shell, _) = NewShell();
        var p = Filled(shell);
        p.Name = "Movie.2026";
        p.Split = RarSplit.Size;
        p.VolumeSizeText = "100 MiB";
        p.Compression = 3;
        p.RecoveryRecordPercent = 5;

        var json = ParfastJson.Write(JobSpec.ForPostingSet(p.ToSpec()));

        Assert.Contains("\"kind\":\"posting_set\"", json);
        Assert.Contains("\"output_dir\":", json);
        Assert.Contains("\"name\":\"Movie.2026\"", json);
        Assert.Contains("\"volumes\":{\"split\":\"size\",\"size\":104857600}", json);
        Assert.Contains("\"compression\":3", json);
        Assert.Contains("\"recovery_percent\":5", json);
        Assert.DoesNotContain("\"password\"", json);
        Assert.DoesNotContain("one_pass_shaped", json);
    }

    [Fact]
    public void AVolumeUnderTheFloorBlocksTheJob()
    {
        var (shell, _) = NewShell();
        var p = Filled(shell);
        p.Split = RarSplit.Size;
        p.VolumeSize = 1024;

        Assert.Equal(Strings.PostingVolumesMinSize, p.ValidationText);
        Assert.False(p.CreateCommand.CanExecute(null));

        p.VolumeSize = RarVolumes.MinSize;
        Assert.True(p.CreateCommand.CanExecute(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData(@"a\b")]
    [InlineData("what?")]
    public void ANameThatIsNotOnePathComponentIsRefused(string name)
    {
        var (shell, _) = NewShell();
        var p = Filled(shell);
        p.Name = name;

        Assert.False(PostingSetViewModel.IsValidName(name));
        Assert.False(p.CreateCommand.CanExecute(null));
    }

    [Fact]
    public void OneStoredArchiveRunsTheOnePassRoute()
    {
        var (shell, core) = NewShell();
        var p = Filled(shell);
        p.Name = "Holiday.2026";

        shell.StartPosting(showProgress: true);
        Assert.True(p.JobId >= 0);
        Drain(core, shell);

        Assert.Equal(JobState.Done, p.State);
        Assert.Equal(PostingRoute.OnePass, p.RouteTaken);
        Assert.Equal(Strings.PostingRouteOnePass, p.RouteText);
        Assert.Equal(PillTone.Good, p.Tone);

        // RAR first, then PAR2, named after what the user typed.
        Assert.Equal("Holiday.2026.rar", p.OutputFiles[0].Name);
        Assert.Equal(PostingHalf.Rar, p.OutputFiles[0].Half);
        Assert.All(p.OutputFiles.Skip(1), f => Assert.Equal(PostingHalf.Par2, f.Half));
        Assert.Contains(p.OutputFiles, f => f.Name == "Holiday.2026.par2");
        Assert.Equal(PostingRecordings.OnePass.Snapshots[^1].Result!.Written.Count, p.OutputFiles.Count);
        Assert.False(string.IsNullOrEmpty(p.OutputTotalText));
    }

    [Fact]
    public void AVolumeSetRunsTwoPassesAndSaysWhy()
    {
        var (shell, core) = NewShell();
        var p = Filled(shell);
        p.Name = "Holiday.2026";
        p.Split = RarSplit.Size;

        Assert.False(p.ExpectsOnePass);
        Assert.Equal(Strings.PostingRouteExpectTwoPass, p.RouteText);

        shell.StartPosting(showProgress: false);
        Assert.Equal(Mode.Queue, shell.Mode);
        Drain(core, shell);

        Assert.Equal(JobState.Done, p.State);
        Assert.Equal(PostingRoute.TwoPass, p.RouteTaken);
        var reason = PostingRecordings.TwoPass.Snapshots[^1].Result!.Posting!.RouteReason;
        Assert.Contains(reason, p.RouteText);
        Assert.StartsWith("Done in two passes, because ", p.RouteText);

        var rar = p.OutputFiles.Where(f => f.Half == PostingHalf.Rar).Select(f => f.Name).ToList();
        Assert.Equal(11, rar.Count);
        Assert.Equal("Holiday.2026.part01.rar", rar[0]);
        Assert.Equal("Holiday.2026.part11.rar", rar[^1]);

        // The core's command line is the PAR2 half's, and the shell shows it.
        shell.Mode = Mode.Posting;
        Assert.Contains("Holiday.2026.par2", shell.CommandText);
    }

    [Fact]
    public void CompressionOrARecoveryRecordAlsoTakesTwoPasses()
    {
        var (shell, _) = NewShell();
        var p = Filled(shell);

        p.Compression = 1;
        Assert.False(p.ExpectsOnePass);
        p.Compression = 0;
        Assert.True(p.ExpectsOnePass);
        p.RecoveryRecordPercent = 3;
        Assert.False(p.ExpectsOnePass);
    }

    [Fact]
    public void CancellingMidRunStopsTheJobAndShowsNoFiles()
    {
        var (shell, core) = NewShell();
        var p = Filled(shell);
        p.Name = "Holiday.2026";
        p.Split = RarSplit.Count;

        shell.StartPosting(showProgress: true);
        core.Advance(TimeSpan.FromMilliseconds(PostingRecordings.TwoPass.DurationMs * PostingRecordings.ReplayStretch / 3));
        Assert.True(p.IsBusy);
        Assert.True(p.Progress > 0);
        Assert.False(string.IsNullOrEmpty(p.PhaseText));
        Assert.True(p.CancelCommand.CanExecute(null));

        p.CancelCommand.Execute(null);
        Drain(core, shell);

        Assert.Equal(JobState.Cancelled, p.State);
        Assert.False(p.IsBusy);
        Assert.Empty(p.OutputFiles);
        Assert.Equal(Strings.ErrorCancelled, p.ErrorText);
        Assert.Equal(PillTone.Warn, p.Tone);
        Assert.False(p.CancelCommand.CanExecute(null));

        // Before it finished, the route line is still the prediction.
        Assert.Null(p.RouteTaken);
        Assert.Equal(Strings.PostingRouteExpectTwoPass, p.RouteText);
    }

    [Fact]
    public void PauseHoldsTheReplayWhereItIs()
    {
        var (shell, core) = NewShell();
        var p = Filled(shell);
        shell.StartPosting(showProgress: true);
        core.Advance(TimeSpan.FromMilliseconds(600));
        var before = p.Progress;

        core.Pause(p.JobId);
        core.Advance(TimeSpan.FromSeconds(30));
        shell.Posting.Apply(core.QueueSnapshot());

        Assert.Equal(JobState.Paused, p.State);
        Assert.Equal(before, p.Progress);
    }

    [Fact]
    public void ThePasswordNeverReachesASnapshotOrAString()
    {
        const string secret = "hunter2-correct-horse";
        var (shell, core) = NewShell();
        var p = Filled(shell);
        p.Name = "Holiday.2026";
        p.Password = secret;

        Assert.True(p.HasPassword);
        var spec = p.ToSpec();
        Assert.Equal(secret, spec.Rar.Password);
        Assert.Contains("\"encrypt_headers\":true", ParfastJson.Write(spec));

        // A record prints every property by default; this one must not.
        Assert.DoesNotContain(secret, spec.Rar.ToString());
        Assert.DoesNotContain(secret, spec.ToString());
        Assert.DoesNotContain(secret, JobSpec.ForPostingSet(spec).ToString());

        shell.StartPosting(showProgress: true);
        Drain(core, shell);

        var snapshotJson = ParfastJson.Write(core.QueueSnapshot());
        Assert.DoesNotContain(secret, snapshotJson);
        Assert.DoesNotContain(secret, string.Join("\n", shell.Log));
        Assert.DoesNotContain(secret, shell.CommandText);
        Assert.DoesNotContain(secret, p.RouteText);
    }

    [Fact]
    public void AnEmptyPasswordFieldSendsNoPassword()
    {
        var (shell, _) = NewShell();
        var p = Filled(shell);
        p.Password = "x";
        p.Password = string.Empty;

        Assert.False(p.HasPassword);
        Assert.Null(p.ToSpec().Rar.Password);
    }

    [Fact]
    public void WithoutTheCapabilityTheScreenIsHiddenAndUnreachable()
    {
        var (shell, _) = NewShell(new MockCore().Capabilities with { PostingSet = false });

        Assert.False(shell.ShowPosting);
        Assert.False(shell.Posting.IsAvailable);

        shell.Mode = Mode.Posting;
        Assert.NotEqual(Mode.Posting, shell.Mode);

        shell.Posting.Add([Film]);
        Assert.False(shell.Posting.CreateCommand.CanExecute(null));
        Assert.Equal(-1, shell.Posting.Start());
    }

    [Fact]
    public void WithTheCapabilityTheScreenIsReachable()
    {
        var (shell, _) = NewShell();

        Assert.True(shell.ShowPosting);
        shell.Mode = Mode.Posting;
        Assert.True(shell.IsPosting);
    }

    [Fact]
    public void ThePostingSetKindHasItsOwnWord()
    {
        Assert.Equal(Strings.JobKindPostingSet, ProgressViewModel.KindWord(JobKind.PostingSet));
    }

    [Fact]
    public void ThePar2HalfTakesTheSettingsCreateDefaults()
    {
        var (shell, _) = NewShell();
        var create = shell.Settings.Current.Create;

        Assert.Equal(create.BlockCount, shell.Posting.BlockCount);
        Assert.Equal(create.RecoveryPercent, shell.Posting.RecoveryPercent);
    }

    [Fact]
    public void AFailureCodeIsShownInTheCopyTablesWords()
    {
        var failed = new JobSnapshot
        {
            Id = 7,
            Kind = JobKind.PostingSet,
            State = JobState.Failed,
            Error = new JobError { Code = "password_required", Message = "withheld" },
        };

        var (shell, core) = NewShell();
        var p = Filled(shell);
        p.Name = "x";
        var id = p.Start();
        p.Apply(new QueueSnapshot { Jobs = [failed with { Id = id }] });

        Assert.Equal(Strings.ErrorPasswordRequired, p.ErrorText);
        Assert.Equal(PillTone.Bad, p.Tone);
        core.Cancel(id);
    }

    private static (long Size, DateTimeOffset Modified, bool IsFolder)? FakeStat(string path) =>
        (1024L * 1024 * 1024, DateTimeOffset.UnixEpoch, false);
}
