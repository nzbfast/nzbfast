using Parfast.Core;
using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>
/// The progress sheet of plan section 5.3, used by every job kind: title,
/// determinate bar, elapsed and remaining and rate, the status line, the
/// message log, pause, run in background, notify and cancel.
/// </summary>
/// <remarks>
/// One rule shows up in the code twice, and it is a promise from section 5.7:
/// A PROGRESS BAR NEVER JUMPS BACKWARDS. The core's progress can dip when a
/// phase boundary recomputes a denominator, and the dip is meaningless to a
/// person watching. So <see cref="Progress"/> is monotone per job and resets
/// only when the job id changes.
/// </remarks>
public sealed class ProgressViewModel : Observable
{
    private readonly ICoreClient _core;
    private JobSnapshot? _job;
    private long _jobId = -1;
    private double _highWater;
    private bool _notify = true;

    public ProgressViewModel(ICoreClient core)
    {
        _core = core;
        PauseCommand = new Command(TogglePause, () => CanPause);
        CancelCommand = new Command(Cancel, () => IsActive);
    }

    public Command PauseCommand { get; }

    public Command CancelCommand { get; }

    /// <summary>Raised when the job finishes, so the shell can close the sheet and notify.</summary>
    public event Action<JobSnapshot>? Finished;

    public bool IsOpen { get; private set; }

    public long JobId => _jobId;

    public JobKind Kind => _job?.Kind ?? JobKind.Unknown;

    public string Title => _job is null
        ? string.Empty
        : Strings.Fill(Strings.ProgressTitle, "kind", KindWord(_job.Kind), "name", _job.Name);

    public double Progress => _highWater;

    public bool IsIndeterminate =>
        _job?.State == JobState.Running && (_highWater <= 0 || ProgressIsUnmeasured);

    public string StatusLine => _job?.PhaseText ?? string.Empty;

    public string ElapsedText => Fmt.Duration(_job?.ElapsedMs ?? 0);

    public string RemainingText => _job?.EtaMs is { } eta ? Fmt.Duration(eta) : "unknown";

    public string RateText => Fmt.Rate(_job?.RateBytesPerS ?? 0);

    /// <summary>
    /// The last couple of minutes of the rate, for the sparkline beside the figure.
    /// </summary>
    /// <remarks>
    /// One instantaneous rate answers "how fast" and nothing answers "is it slowing
    /// down", which is the question a person watching a long create actually has.
    /// The history is fed from <see cref="Apply"/> and thrown away in
    /// <see cref="Open"/>, so a second job in the same sheet starts with a clean
    /// chart rather than inheriting the shape of the first.
    /// </remarks>
    public RateHistory Rates { get; } = new();

    /// <summary>Whether the sparkline has anything to draw.</summary>
    /// <remarks>
    /// Two samples and a non-zero peak. A job whose engine reports no rate at all -
    /// a phase that moves no bytes - would otherwise draw a flat line along the
    /// floor, and a flat line at the bottom of a chart reads as a stall rather than
    /// as an absence of measurement. The figure beside it still prints 0 MB/s, which
    /// is the honest answer, and the picture stays away.
    /// </remarks>
    public bool ShowRateTrend => Rates.HasShape;

    /// <summary>The trend in words, for the figure under the chart and for the reader.</summary>
    public string RateTrendText => Rates.TrendText;

    public string PercentText => Fmt.Percent(_highWater);

    public IReadOnlyList<string> Log => _job?.LogTail ?? [];

    /// <summary>The exit code the equivalent parfast line would have returned, once finished.</summary>
    public int? ExitCode => _job?.Result?.ExitCode;

    public bool IsPaused => _job?.State == JobState.Paused;

    public bool IsActive => _job?.IsActive == true;

    /// <summary>
    /// Whether Pause can actually reach this job RIGHT NOW.
    /// </summary>
    /// <remarks>
    /// Not simply the pause capability. crates/parfast-ffi/API.md's table says
    /// where pause lands per job kind, and that table was REWRITTEN on 12 Sep
    /// 2026: verify and the checksum kinds still park between members, and a
    /// repair and a CREATE now park inside the engine - a repair everywhere but
    /// the solve, a create everywhere but a transform. So against a shipped
    /// engine every line below is true and a running create IS pausable.
    /// <para>
    /// The create arm stays anyway, because <c>PauseInFold</c> and not the job
    /// kind is what separates the two cases: a create the engine is driving with
    /// no control still stops only before it starts. A button that stays enabled
    /// and does nothing is worse than one that is honestly disabled - the user
    /// presses it, the bar keeps moving, and they conclude the app is broken
    /// rather than that the engine cannot stop there.
    /// </para>
    /// <para>
    /// AND THAT LAST SENTENCE IS CURRENTLY THE STATE OF A CREATE, which is
    /// worth knowing before anyone treats this gate as a verified promise. Run
    /// against the real engine on 12 Sep 2026, three times: a create paused
    /// just after it starts reports Paused, parks some of its threads, and
    /// then runs to completion and writes the whole set, so
    /// <c>pause_in_fold</c> over-claims for that job kind.
    /// </para>
    /// <para>
    /// WHERE, named off the timing trace and not off which arm is configured
    /// as default: this remark first blamed par2gen/stripe_first.rs on that
    /// bad reasoning and was wrong, since that arm refuses a single-batch or
    /// fused create and never ran. The arm that runs is the mapped
    /// SINGLE-WINDOW transform in par2gen/ntt.rs - 10.73 s of a 12.85 s
    /// create - which holds no gate at all and whose stripe workers poll
    /// cancel only, deliberately ("Cancel only, never a park", ntt.rs:299).
    /// One window, so no between-windows park point either. API.md's stated
    /// exception, that a pause during a transform lands at the END of it, is
    /// honoured to the letter and swallows the operation. Cancel is sound.
    /// Owned as claim <c>par2gen-create-pause-and-bar</c>; the measurement,
    /// and why the fix belongs to the engine or the capability rather than to
    /// a per-app hard-code, are in
    /// the maintainer notes.
    /// </para>
    /// </remarks>
    public bool CanPause =>
        IsActive
        && _core.Capabilities.Pause
        && (_core.Capabilities.PauseInFold
            || _job?.Kind is not JobKind.Create
            || _job.State == JobState.Queued);

    /// <summary>Why Pause is unavailable, for the tooltip, or null when it is available.</summary>
    /// <remarks>
    /// FROM THE COPY TABLE, not a literal here. This was an English sentence
    /// spelled out in the view model, which is both a second copy of a string
    /// the shared table already carries and one the sixteen locales can never
    /// reach; the mac app shows the same key in the same place.
    /// <para>
    /// The only state that reaches it is a create the engine will not park mid
    /// run, which is what <c>CanPause</c>'s remaining create arm tests, so the
    /// sentence names the ENGINE rather than telling the user a create cannot
    /// be paused. Against a shipped engine it is unreachable.
    /// </para>
    /// </remarks>
    public string? PauseUnavailableReason =>
        !IsActive || CanPause || !_core.Capabilities.Pause
            ? null
            : Strings.ProgressPauseNotAfterStart;

    /// <summary>
    /// True while the engine is in a phase that cannot report progress, so the bar
    /// should stop claiming a number and the phase text should carry the meaning.
    /// </summary>
    /// <remarks>
    /// API.md, of an engine without <c>progress_in_fold</c>: during a fold there
    /// is no in-engine progress, so the bar stays where the hashing left it, and
    /// a bar that sat at a number would be a claim. This is what turns that into
    /// something the view can draw: an indeterminate bar says "working, cannot
    /// say how far", which is the truth.
    /// <para>
    /// AGAINST A SHIPPED ENGINE THIS IS ALWAYS FALSE, including for a create,
    /// and that is the point rather than dead code. <c>progress_in_fold</c> has
    /// been true since 12 Sep 2026 - the repair reports four phases and the
    /// create reports its hashing and fold as one rising fraction and then the
    /// volume writes - so the first clause below switches the whole property
    /// off and the bar draws a number through the phases it used to go
    /// indeterminate in. <c>CapabilityTests</c> pins both arms.
    /// </para>
    /// <para>
    /// A claim about a create's bar stood here and has been WITHDRAWN, which
    /// is worth more to the next reader than the claim was. Watching the mac
    /// app on 12 Sep 2026 caught a frame with the phase text at 79% and the
    /// bar at 90%, and this comment explained it as the fused arm never
    /// sizing its Verify meter. The timing trace then said the create was not
    /// fused at all (the NTT transform only runs when it is not), so
    /// <c>begin</c> HAD sized that meter and the explanation was fiction. The
    /// frame is what the design does on purpose: hashing and the fold share
    /// the 0-90% span and the session takes whichever is further, so a fold
    /// that finishes while the hash is still at 79% puts the bar at 90%.
    /// Nothing here is known to be wrong. If a create's bar ever does look
    /// stuck, re-observe it with an instrument whose elapsed counter is
    /// actually moving - mine read 0.0 s across frames that were seconds
    /// apart, and I believed the reading anyway.
    /// </para>
    /// </remarks>
    public bool ProgressIsUnmeasured =>
        IsActive
        && !_core.Capabilities.ProgressInFold
        && _job?.Phase is JobPhase.Solving or JobPhase.Writing
        && _job.Kind is JobKind.Create or JobKind.Repair;

    public string PauseText => IsPaused ? Strings.ProgressResume : Strings.ProgressPause;

    public bool LowPriority
    {
        get => _job?.LowPriority ?? false;
        set
        {
            if (_jobId >= 0)
            {
                _core.SetLowPriority(_jobId, value);
            }
        }
    }

    public bool ShowLowPriority => _core.Capabilities.LowPriority;

    public bool Notify
    {
        get => _notify;
        set => Set(ref _notify, value);
    }

    public void Open(long jobId)
    {
        _jobId = jobId;
        _job = null;
        _highWater = 0;
        Rates.Reset();
        IsOpen = true;
        RaiseEverything();
    }

    public void Close()
    {
        IsOpen = false;
        Raise(nameof(IsOpen));
    }

    public void Apply(QueueSnapshot queue)
    {
        if (_jobId < 0)
        {
            return;
        }

        var job = queue.Jobs.FirstOrDefault(j => j.Id == _jobId);
        if (job is null)
        {
            return;
        }

        var wasActive = _job?.IsActive ?? _job is null;
        _job = job;
        _highWater = Math.Max(_highWater, job.Progress);

        // The rate history is fed only while the job is ACTIVE. A finished job keeps
        // reporting its last snapshot on every poll, so pushing here unconditionally
        // would extend the chart with a carried-forward tail for as long as the sheet
        // stayed open - a flat line growing to the right, which claims the job is
        // still running at the rate it stopped at.
        if (job.IsActive)
        {
            Rates.Push(job.ElapsedMs, job.RateBytesPerS);
        }
        if (job.IsFinished)
        {
            // A finished job reads 100 percent even if the core's last snapshot
            // said 0.97: the work is done and a bar stopped short of the end is
            // read as a hang.
            _highWater = job.State == JobState.Done ? 1 : _highWater;
        }

        RaiseEverything();

        if (wasActive && job.IsFinished)
        {
            Finished?.Invoke(job);
        }
    }

    /// <summary>
    /// The one word for a job kind, from the shared table's job.kind group.
    /// </summary>
    /// <remarks>
    /// The title is composed from this plus the set name rather than from five
    /// separate "Creating {0}" templates, because the shared table has the four
    /// kind words and does not have the templates. Composing keeps the copy in one
    /// owned place and gives the Queue table's Kind column the same words as the
    /// progress sheet's title, which five templates would not have guaranteed.
    /// </remarks>
    public static string KindWord(JobKind kind) => kind switch
    {
        JobKind.Create => Strings.JobKindCreate,
        JobKind.Verify => Strings.JobKindVerify,
        JobKind.Repair => Strings.JobKindRepair,
        _ => Strings.JobKindChecksums,
    };

    private void TogglePause()
    {
        if (_jobId < 0)
        {
            return;
        }

        if (IsPaused)
        {
            _core.Resume(_jobId);
        }
        else
        {
            _core.Pause(_jobId);
        }
    }

    private void Cancel()
    {
        if (_jobId >= 0)
        {
            _core.Cancel(_jobId);
        }
    }

    private void RaiseEverything()
    {
        RaiseAll(nameof(IsOpen), nameof(JobId), nameof(Kind), nameof(Title), nameof(Progress),
            nameof(IsIndeterminate), nameof(StatusLine), nameof(ElapsedText), nameof(RemainingText),
            nameof(RateText), nameof(PercentText), nameof(Log), nameof(IsPaused), nameof(IsActive),
            nameof(CanPause), nameof(PauseText), nameof(LowPriority),
            nameof(PauseUnavailableReason), nameof(ProgressIsUnmeasured), nameof(ExitCode),
            nameof(Rates), nameof(ShowRateTrend), nameof(RateTrendText));
        PauseCommand.Refresh();
        CancelCommand.Refresh();
    }
}
