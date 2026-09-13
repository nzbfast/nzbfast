using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The capability rule of plan 4.5: a UI hides any control whose capability is
/// false.
/// </summary>
/// <remarks>
/// This is what keeps the app honest about the engine under it, and against
/// today's engine it is not theoretical: TWO capabilities are false
/// (crates/parfast-ffi/API.md's table - <c>unicode_policy</c> and
/// <c>low_priority</c>), so two controls are absent. A control that is shown
/// and ignored is the app telling the user something that is not true, and it
/// is invisible in a screenshot.
/// <para>
/// It was five until 12 Sep 2026 and the count is written out here because it
/// went stale twice that day in the direction that is harder to notice: the
/// mock kept claiming false after the engine said true, which HIDES shipped
/// controls rather than inventing ones.
/// </para>
/// </remarks>
public class CapabilityTests
{
    private static (ShellViewModel Shell, MockCore Core) With(Capabilities caps)
    {
        var core = new MockCore { Capabilities = caps };
        return (new ShellViewModel(core, new ImmediateDispatcher()), core);
    }

    [Fact]
    public void TheMockClaimsWhatTodaysEngineClaims()
    {
        // A mock that claimed everything would demo controls the engine does not
        // have, so the screenshots would show an app nobody can ship. The
        // converse bites too and did on 12 Sep 2026: a mock that claims LESS
        // hides controls the engine HAS, and the screenshot set then advertises
        // an app missing features it ships. `par2-comment-packet` and
        // `parfast-create-capability-flips` landed that morning and flipped
        // three of these; `par2gen-create-control` flipped the other three that
        // afternoon. The mock had to follow both times, and did not.
        //
        // THIS TEST IS A MIRROR, NOT A RULE. When the engine's table in
        // apps/parfast/crates/parfast-ffi/API.md moves, the fix is to re-read it
        // and change BOTH the mock and these lines together - never to relax an
        // assertion so the survivors agree. Its mac counterpart is
        // MockCoreTests.testTheMockClaimsExactlyWhatTheRealEngineClaims, and the
        // two mocks are meant to answer identically.
        var caps = new MockCore().Capabilities;
        Assert.True(caps.StdNaming);
        Assert.False(caps.UnicodePolicy);
        Assert.True(caps.Comment);
        Assert.True(caps.VolumeLimitExplicit);
        Assert.False(caps.LowPriority);
        Assert.True(caps.DataSkipping);
        Assert.True(caps.FastSolver);
        Assert.True(caps.Pause);

        // The three in-fold keys, which `par2gen-create-control` flipped on the
        // afternoon of 12 Sep 2026 and this mock followed a day late. They are
        // not per-kind: they cover a repair AND a create, and API.md's per-job
        // table is what says where each one lands.
        Assert.True(caps.PauseInFold);
        Assert.True(caps.CancelInFold);
        Assert.True(caps.ProgressInFold);
    }

    [Fact]
    public void EveryFalseCapabilityHidesItsControl()
    {
        var (off, _) = With(new Capabilities());
        Assert.False(off.Create.ShowStdNaming);
        Assert.False(off.Create.ShowUnicodePolicy);
        Assert.False(off.Create.ShowComment);
        Assert.False(off.Create.ShowExplicitVolumeLimit);
        Assert.False(off.Verify.Options.ShowDataSkipping);
        Assert.False(off.Verify.Options.ShowFastSolver);
        Assert.False(off.Settings.ShowFastSolver);
        Assert.False(off.Settings.ShowLowPriority);

        var (on, _) = With(new Capabilities
        {
            StdNaming = true, UnicodePolicy = true, Comment = true, VolumeLimitExplicit = true,
            DataSkipping = true, FastSolver = true, LowPriority = true,
        });
        Assert.True(on.Create.ShowStdNaming);
        Assert.True(on.Create.ShowUnicodePolicy);
        Assert.True(on.Create.ShowComment);
        Assert.True(on.Create.ShowExplicitVolumeLimit);
        Assert.True(on.Verify.Options.ShowDataSkipping);
        Assert.True(on.Verify.Options.ShowFastSolver);
        Assert.True(on.Settings.ShowLowPriority);
    }

    [Fact]
    public void AnUnavailableVolumeLimitCannotEvenBeSetProgrammatically()
    {
        // Settings restoring a saved "blocks" limit against an engine that has
        // since lost the capability would otherwise leave the form in a state the
        // preview cannot honour.
        var (shell, _) = With(new Capabilities());
        shell.Create.Pow2LimitArm = "blocks";
        Assert.Equal("largest", shell.Create.Pow2LimitArm);

        var (capable, _) = With(new Capabilities { VolumeLimitExplicit = true });
        capable.Create.Pow2LimitArm = "blocks";
        Assert.Equal("blocks", capable.Create.Pow2LimitArm);
    }

    [Fact]
    public void ARunningCreateCanBePausedAgainstAnEngineThatParksInTheFold()
    {
        // API.md's table, rewritten on 12 Sep 2026: `pause_in_fold` says the
        // engine parks a create mid run, so a RUNNING create is pausable. This
        // test asserted the opposite until the mock caught up with the engine.
        //
        // What it pins is THIS APP's rule, which is all a view-model test can
        // pin: Pause is offered exactly when the capability says the engine
        // honours it. Whether the shipped engine really does is a different
        // question and the answer today is no for a create - see
        // ProgressViewModel.CanPause's remark and the handoff it cites.
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher(), null, null, FakeStat);
        shell.Create.Add([@"D:\work\a.bin"]);
        shell.Progress.Open(shell.Create.Start());

        core.Advance(TimeSpan.FromSeconds(2));
        Assert.True(shell.Progress.IsActive);
        Assert.True(shell.Progress.CanPause);
        Assert.Null(shell.Progress.PauseUnavailableReason);
    }

    [Fact]
    public void ACreateCannotBePausedOnceItIsRunningWithoutThatCapability()
    {
        // The arm CanPause keeps for an engine that does NOT park a create mid
        // run - one driving the create with no control at all. A button that
        // stays enabled and does nothing teaches the user the app is broken, so
        // it is disabled with the reason instead, and the reason comes from the
        // copy table rather than a literal in the view model.
        var core = new MockCore
        {
            Capabilities = new MockCore().Capabilities with { PauseInFold = false },
        };
        var shell = new ShellViewModel(core, new ImmediateDispatcher(), null, null, FakeStat);
        shell.Create.Add([@"D:\work\a.bin"]);
        shell.Progress.Open(shell.Create.Start());

        core.Advance(TimeSpan.FromSeconds(2));
        Assert.True(shell.Progress.IsActive);
        Assert.False(shell.Progress.CanPause);
        Assert.Equal(Strings.ProgressPauseNotAfterStart, shell.Progress.PauseUnavailableReason);
    }

    [Fact]
    public void ACreatesBarIsMeasuredAgainstAnEngineThatReportsInTheFold()
    {
        // ProgressIsUnmeasured is gated on !ProgressInFold, so with the shipped
        // engine's answer it is false for a create: the bar keeps a number
        // through the phases it used to go indeterminate in, rather than
        // shrugging. Confirmed here rather than argued from the wiring, and
        // both arms are pinned so the fallback does not rot. The number itself
        // is a separate matter - against the real engine a create's bar pins at
        // 90% - and that is an engine meter bug, recorded in the handoff.
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher(), null, null, FakeStat);
        shell.Create.Add([@"D:\work\a.bin"]);
        shell.Progress.Open(shell.Create.Start());
        core.Advance(TimeSpan.FromSeconds(2));

        Assert.True(shell.Progress.IsActive);
        Assert.False(shell.Progress.ProgressIsUnmeasured);

        // And the fallback arm, so it does not rot: the same create under an
        // engine that cannot report from the fold goes indeterminate the moment
        // it leaves the hashing phase.
        var blind = new MockCore
        {
            Capabilities = new MockCore().Capabilities with { ProgressInFold = false },
        };
        var other = new ShellViewModel(blind, new ImmediateDispatcher(), null, null, FakeStat);
        other.Create.Add([@"D:\work\a.bin"]);
        other.Progress.Open(other.Create.Start());

        var reached = false;
        for (var i = 0; i < 200 && !reached; i++)
        {
            blind.Advance(TimeSpan.FromSeconds(1));
            reached = blind.Snapshot(other.Progress.JobId)?.Phase is JobPhase.Solving or JobPhase.Writing
                      && other.Progress.IsActive;
        }

        Assert.True(reached, "the mock create never reached a folding or writing phase while running");
        Assert.True(other.Progress.ProgressIsUnmeasured);
    }

    [Fact]
    public void AVerifyCanBePausedWhileItRuns()
    {
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher());
        shell.Verify.Open(@"D:\sets\10k.par2", autoRepair: false);
        shell.Progress.Open(shell.Verify.JobId);

        core.Advance(TimeSpan.FromSeconds(2));
        Assert.True(shell.Progress.CanPause);
        Assert.Null(shell.Progress.PauseUnavailableReason);
    }

    [Fact]
    public void ThePostQueueActionIsPerformedByTheHostAndClearedOnce()
    {
        // The core reports it due and refuses to do it; the host does it and says
        // so. Clearing matters: an uncleared action would be re-performed on every
        // snapshot, which for "shut down" is a shutdown attempt ten times a second.
        var core = new MockCore();
        var host = new NullShellHost();
        var shell = new ShellViewModel(core, new ImmediateDispatcher(), host);

        shell.Queue.SetPostAction(PostQueueAction.Sleep);
        core.RaisePostActionDue();
        core.Advance(TimeSpan.Zero);
        core.Advance(TimeSpan.Zero);
        core.Advance(TimeSpan.Zero);

        Assert.Equal([PostQueueAction.Sleep], host.Performed);
    }

    [Fact]
    public void ARefusedPostQueueActionIsStillClearedRatherThanRetriedForever()
    {
        var core = new MockCore();
        var host = new NullShellHost { AllowPostQueueAction = false };
        var shell = new ShellViewModel(core, new ImmediateDispatcher(), host);

        shell.Queue.SetPostAction(PostQueueAction.Shutdown);
        core.RaisePostActionDue();
        for (var i = 0; i < 10; i++)
        {
            core.Advance(TimeSpan.Zero);
        }

        Assert.Empty(host.Performed);
        Assert.False(core.QueueSnapshot().PostActionDue);
    }

    [Fact]
    public void TheQueueStoreIsOpenedAtTheHostsPathWhenItNamesOne()
    {
        var core = new MockCore();
        var host = new NullShellHost { QueueStorePath = @"C:\ProgramData\parfast-test\queue.json" };
        _ = new ShellViewModel(core, new ImmediateDispatcher(), host);
        Assert.Equal(host.QueueStorePath, core.LastQueueStorePath);
    }

    [Fact]
    public void AChecksumVerifyWithNoPerFileRowsSaysSoInsteadOfShowingAnEmptyTable()
    {
        // The landed contract carries three counts and no per-file list (plan 4.5,
        // recorded as an open gap), so this screen WILL hit that path on a real
        // build. An empty table reads as "nothing was checked", which is a result
        // rather than a missing capability, and that is the lie this note prevents.
        var core = new MockCore();
        var shell = new ShellViewModel(core, new ImmediateDispatcher());
        shell.Checksums.Open(@"D:\sets\damaged.sfv");
        core.Advance(TimeSpan.FromSeconds(12));

        Assert.NotNull(shell.Checksums.Result);
        Assert.False(shell.Checksums.ShowNoDetailNote, "the mock DOES carry rows, so the note stays hidden");
        Assert.NotEmpty(shell.Checksums.Rows);

        // And with the rows removed, the way the real engine leaves them.
        shell.Checksums.Rows.Clear();
        Assert.True(shell.Checksums.ShowNoDetailNote);
        Assert.False(string.IsNullOrWhiteSpace(shell.Checksums.NoDetailNote));
        Assert.True(shell.Checksums.HasContent, "counts alone are still content worth showing");
    }

    private static (long Size, DateTimeOffset Modified, bool IsFolder)? FakeStat(string path) =>
        (256L * 1024 * 1024, DateTimeOffset.UnixEpoch, false);
}
