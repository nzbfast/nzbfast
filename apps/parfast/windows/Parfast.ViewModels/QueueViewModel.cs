using Parfast.Core;
using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>One row of the queue table of plan section 5.5.</summary>
public sealed class QueueRow : Observable
{
    private JobSnapshot _job;

    public QueueRow(JobSnapshot job) => _job = job;

    public long Id => _job.Id;

    // One mapping from a job kind to its word, shared with the progress sheet's
    // title so the Queue table and the sheet cannot call the same job two things.
    public string KindText => ProgressViewModel.KindWord(_job.Kind);

    public string Name => _job.Name;

    public JobState State => _job.State;

    public string StatusText => _job.State switch
    {
        JobState.Queued => Strings.QueueStateQueued,
        JobState.Running => _job.PhaseText,
        JobState.Paused => Strings.QueueStatePaused,
        JobState.Done => Strings.QueueStateDone,
        JobState.Failed => Strings.QueueStateFailed,
        JobState.Cancelled => Strings.QueueStateCancelled,
        JobState.Interrupted => Strings.QueueStateInterrupted,
        _ => string.Empty,
    };

    public double Progress => _job.Progress;

    public string ProgressText => _job.State == JobState.Running ? Fmt.Percent(_job.Progress) : string.Empty;

    public bool IsIndeterminate => _job.State == JobState.Running && _job.Progress <= 0;

    public string AddedText => Fmt.When(_job.AddedAt);

    public bool IsFinished => _job.IsFinished;

    public bool IsRunning => _job.State == JobState.Running;

    public PillTone Tone => _job.State switch
    {
        JobState.Done => PillTone.Good,
        JobState.Failed => PillTone.Bad,
        JobState.Interrupted => PillTone.Warn,
        JobState.Running => PillTone.Busy,
        _ => PillTone.Neutral,
    };

    public void Apply(JobSnapshot job)
    {
        _job = job;
        RaiseAll(nameof(KindText), nameof(Name), nameof(State), nameof(StatusText), nameof(Progress),
            nameof(ProgressText), nameof(IsIndeterminate), nameof(AddedText), nameof(IsFinished),
            nameof(IsRunning), nameof(Tone));
    }
}

/// <summary>
/// Queue (plan section 5.5): the table, the toolbar, the concurrency and the
/// when-the-queue-finishes action.
/// </summary>
/// <remarks>
/// The queue is not a separate scheduler in the app. Every job the app submits
/// goes into the core's queue, including one the user started directly from
/// Create, which is what makes this screen the truth rather than a second
/// opinion (plan section 5.3). So this view model owns no state of its own
/// beyond the selection: it renders a snapshot and sends commands.
/// <para>
/// Sleep and shut down ask for confirmation ONCE when set, not when they fire:
/// asking as the machine is about to sleep, possibly with nobody at the desk,
/// would either block the action forever or be dismissed by a stray keypress.
/// <see cref="PendingConfirmation"/> is how the view is told to ask.
/// </para>
/// </remarks>
public sealed class QueueViewModel : Observable
{
    private readonly ICoreClient _core;
    private QueueSnapshot _snapshot = QueueSnapshot.Empty;
    private string? _pendingConfirmation;

    public QueueViewModel(ICoreClient core)
    {
        _core = core;
        PauseCommand = new Command(TogglePause);
        RunNowCommand = new Command(RunNow, () => Selected.Any(r => r.State == JobState.Queued));
        RemoveCommand = new Command(RemoveSelected, () => Selected.Any(r => r.IsFinished));
        ClearFinishedCommand = new Command(ClearFinished, () => Rows.Any(r => r.IsFinished));
        CancelSelectedCommand = new Command(CancelSelected, () => Selected.Any(r => !r.IsFinished));
    }

    public Rows<QueueRow> Rows { get; } = [];

    public List<QueueRow> Selected { get; } = [];

    public Command PauseCommand { get; }

    public Command RunNowCommand { get; }

    public Command RemoveCommand { get; }

    public Command ClearFinishedCommand { get; }

    public Command CancelSelectedCommand { get; }

    public bool Paused => _snapshot.Paused;

    public string PauseText => Paused ? Strings.QueueResume : Strings.QueuePause;

    public int RunningCount => _snapshot.RunningCount;

    public int WaitingCount => _snapshot.WaitingCount;

    /// <summary>The count on the mode picker's badge: running plus waiting.</summary>
    public int BadgeCount => RunningCount + WaitingCount;

    public int Concurrency => _snapshot.Concurrency;

    public string ConcurrencyText => Concurrency <= 1
        ? Strings.QueueConcurrencyOne
        : Strings.Fill(Strings.QueueConcurrencyN, "n", Fmt.Count(Concurrency));

    public PostQueueAction PostAction => _snapshot.PostAction;

    public bool IsEmpty => Rows.Count == 0;

    /// <summary>Set when the view should ask the user to confirm; cleared by the view.</summary>
    public string? PendingConfirmation
    {
        get => _pendingConfirmation;
        set => Set(ref _pendingConfirmation, value);
    }

    public void Apply(QueueSnapshot snapshot)
    {
        _snapshot = snapshot;
        Rows.Sync(
            snapshot.Jobs.Select(j => new QueueRow(j)).ToList(),
            row => row.Id,
            (existing, fresh) => existing.Apply(snapshot.Jobs.First(j => j.Id == fresh.Id)));
        RaiseAll(nameof(Paused), nameof(PauseText), nameof(RunningCount), nameof(WaitingCount), nameof(BadgeCount),
            nameof(Concurrency), nameof(ConcurrencyText), nameof(PostAction), nameof(IsEmpty));
        PauseCommand.Refresh();
        RunNowCommand.Refresh();
        RemoveCommand.Refresh();
        ClearFinishedCommand.Refresh();
        CancelSelectedCommand.Refresh();
    }

    public void SetConcurrency(int n) => _core.SetConcurrency((uint)Math.Max(1, n));

    public void SetPostAction(PostQueueAction action)
    {
        _core.SetPostAction(action);
        PendingConfirmation = action switch
        {
            PostQueueAction.Sleep => Strings.QueueFinishConfirmSleep,
            PostQueueAction.Shutdown => Strings.QueueFinishConfirmShutdown,
            _ => null,
        };
    }

    private void TogglePause() => _core.SetQueuePaused(!Paused);

    private void RunNow()
    {
        // pf_job_run_next, which chip A added at this lane's request. Before it,
        // the two things a host could do were both wrong: raising the concurrency
        // starts everything queued AHEAD of the chosen job too, and resuming it
        // only lets the scheduler reach it in its turn. Neither is "run this now".
        //
        // Only the FIRST selection is taken. "Run these three next" has no meaning
        // against a single next-pick flag, and quietly flagging all three would
        // make the last one win, which is the opposite of what the order on screen
        // says.
        var first = Selected.FirstOrDefault(r => r.State == JobState.Queued);
        if (first is not null)
        {
            _core.RunNext(first.Id);
        }
    }

    private void RemoveSelected()
    {
        foreach (var row in Selected.Where(r => r.IsFinished).ToList())
        {
            _core.Remove(row.Id);
        }

        Selected.Clear();
    }

    private void CancelSelected()
    {
        foreach (var row in Selected.Where(r => !r.IsFinished).ToList())
        {
            _core.Cancel(row.Id);
        }
    }

    private void ClearFinished()
    {
        foreach (var row in Rows.Where(r => r.IsFinished).ToList())
        {
            _core.Remove(row.Id);
        }
    }
}
