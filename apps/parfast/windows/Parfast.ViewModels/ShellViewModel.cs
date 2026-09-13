using Parfast.Core;
using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>The four modes of plan section 5.1, plus settings.</summary>
public enum Mode
{
    Verify,
    Create,
    Checksums,
    Queue,
    Settings,
}

/// <summary>What the shell asks its host to do. The host is the only Windows-aware part.</summary>
public interface IShellHost
{
    void Notify(string title, string body);

    void Reveal(string path);

    void SetClipboard(string text);

    /// <summary>
    /// Carries out a due post-queue action: sleep or shut down.
    /// </summary>
    /// <remarks>
    /// THE HOST DOES THIS, NOT THE CORE, and the core says so
    /// (crates/parfast-ffi/API.md): sleeping or shutting down a machine is a
    /// platform call, and it is a decision a human has to be able to stop.
    /// </remarks>
    /// <returns>False when the host could not or would not do it.</returns>
    bool PerformPostQueueAction(PostQueueAction action);

    /// <summary>Where this platform keeps an app's data. The core has no opinion.</summary>
    string? QueueStorePath { get; }
}

/// <summary>Host that does nothing, for the tests.</summary>
public sealed class NullShellHost : IShellHost
{
    public List<(string Title, string Body)> Notifications { get; } = [];

    public string? LastRevealed { get; private set; }

    public string? Clipboard { get; private set; }

    public List<PostQueueAction> Performed { get; } = [];

    /// <summary>Set false by a test that wants to see a refused action handled.</summary>
    public bool AllowPostQueueAction { get; set; } = true;

    public string? QueueStorePath { get; set; }

    public void Notify(string title, string body) => Notifications.Add((title, body));

    public void Reveal(string path) => LastRevealed = path;

    public void SetClipboard(string text) => Clipboard = text;

    public bool PerformPostQueueAction(PostQueueAction action)
    {
        if (!AllowPostQueueAction)
        {
            return false;
        }

        Performed.Add(action);
        return true;
    }
}

/// <summary>
/// The window's view model: the mode picker, the drop routing, the one
/// <see cref="JobMonitor"/> every screen is fed from, and the progress sheet.
/// </summary>
/// <remarks>
/// ONE MONITOR, ONE POLL, FOUR SCREENS. Each screen could have polled the core
/// itself, and then four timers would race one another and a snapshot read by
/// Verify could be a tick older than the one read by Queue, which shows up as
/// the two disagreeing on the same job. Instead the shell holds the single
/// monitor and hands every fresh snapshot to all of them in a fixed order, so
/// the whole window is always one consistent picture of one instant.
/// </remarks>
public sealed class ShellViewModel : Observable, IDisposable
{
    private readonly ICoreClient _core;
    private readonly IShellHost _host;
    private readonly JobMonitor _monitor;
    private Mode _mode = Mode.Verify;
    private int _mapCells = 1000;
    private bool _windowActive = true;

    /// <param name="stat">
    /// How a dropped path is sized. The Windows app passes the real filesystem;
    /// the tests pass a table. It is a parameter rather than a static call
    /// because otherwise the drop path could only be exercised against real
    /// files on a real Windows box, which is the whole of Create's input side.
    /// </param>
    public ShellViewModel(
        ICoreClient core,
        IUiDispatcher ui,
        IShellHost? host = null,
        IShellIntegration? integration = null,
        Func<string, (long Size, DateTimeOffset Modified, bool IsFolder)?>? stat = null)
    {
        _core = core;
        _host = host ?? new NullShellHost();
        Verify = new VerifyViewModel(core);
        Create = new CreateViewModel(core, stat);
        Checksums = new ChecksumsViewModel(core, stat);
        Queue = new QueueViewModel(core);
        Settings = new SettingsViewModel(core, integration);
        Progress = new ProgressViewModel(core);
        Progress.Finished += OnJobFinished;

        _monitor = new JobMonitor(core, ui);
        _monitor.Updated += OnSnapshot;

        CopyCommandCommand = new Command(CopyCommand);
        RevealCommand = new Command(() => _host.Reveal(RevealTarget() ?? string.Empty),
            () => RevealTarget() is not null);

        ApplySettings();

        // Persist the queue where this platform keeps app data. The core has no
        // opinion about that path and says so, so the host names it.
        if (_host.QueueStorePath is { } store)
        {
            var loaded = core.OpenQueueStore(store);
            if (loaded > 0)
            {
                // A job that was running when the app quit comes back Interrupted
                // and re-runnable (plan 5.5), so landing on the Queue is the only
                // screen that explains what the user is looking at.
                Mode = Mode.Queue;
            }
        }

        _monitor.Refresh();
    }

    public VerifyViewModel Verify { get; }

    public CreateViewModel Create { get; }

    public ChecksumsViewModel Checksums { get; }

    public QueueViewModel Queue { get; }

    public SettingsViewModel Settings { get; }

    public ProgressViewModel Progress { get; }

    public Command CopyCommandCommand { get; }

    public Command RevealCommand { get; }

    public Capabilities Capabilities => _core.Capabilities;

    /// <summary>True when the core is the mock, which the window says out loud.</summary>
    public bool IsMock => _core is Parfast.Core.Mock.MockCore;

    public string MockBanner => Strings.MockBanner;

    public Mode Mode
    {
        get => _mode;
        set
        {
            if (Set(ref _mode, value))
            {
                RaiseAll(nameof(IsVerify), nameof(IsCreate), nameof(IsChecksums), nameof(IsQueue),
                    nameof(IsSettings), nameof(LogVisible));
                RevealCommand.Refresh();
            }
        }
    }

    public bool IsVerify => _mode == Mode.Verify;

    public bool IsCreate => _mode == Mode.Create;

    public bool IsChecksums => _mode == Mode.Checksums;

    public bool IsQueue => _mode == Mode.Queue;

    public bool IsSettings => _mode == Mode.Settings;

    /// <summary>The log drawer, which is shared by every mode (plan section 5.2).</summary>
    public bool LogOpen
    {
        get;
        private set;
    }

    public bool LogVisible => LogOpen && _mode is Mode.Verify or Mode.Create or Mode.Checksums;

    public IReadOnlyList<string> Log
    {
        get
        {
            var log = _mode switch
            {
                Mode.Verify => Verify.Log,
                _ => Progress.Log,
            };

            // Decode failures go at the TOP, not the bottom. A log tail scrolls and
            // the thing that explains why the rest of it stopped moving must not be
            // the line that scrolled away.
            return _decodeErrors.Count == 0 ? log : _decodeErrors.Concat(log).ToList();
        }
    }

    private readonly List<string> _decodeErrors = [];
    private readonly HashSet<string> _decodeErrorsSeen = new(StringComparer.Ordinal);

    /// <summary>
    /// The equivalent parfast command line.
    /// </summary>
    /// <remarks>
    /// THE CORE'S LINE WINS whenever there is a job to ask about: it carries a
    /// `command` field now (crates/parfast-ffi/API.md), and the CLI's dialect is
    /// the one thing a script user already knows. An app whose "equivalent
    /// command" is its own guess is unreproducible from a terminal, which is the
    /// whole point of showing it. The planner's line is the fallback for a form
    /// nobody has run yet.
    /// </remarks>
    public string CommandText
    {
        get
        {
            var running = _mode switch
            {
                Mode.Create => JobCommand(Create.JobId),
                Mode.Checksums => JobCommand(Checksums.JobId),
                _ => JobCommand(Verify.JobId),
            };

            if (!string.IsNullOrEmpty(running))
            {
                return running;
            }

            return _mode switch
            {
                Mode.Create => Create.CommandText,
                _ => Verify.CommandText,
            };
        }
    }

    private string JobCommand(long id) =>
        id < 0 ? string.Empty : _monitor.Latest.Jobs.FirstOrDefault(j => j.Id == id)?.Command ?? string.Empty;

    public bool ShowCommand => Settings.ShowCommand;

    /// <summary>Whether the window has focus. A completed job notifies only when it does not.</summary>
    public bool WindowActive
    {
        get => _windowActive;
        set => Set(ref _windowActive, value);
    }

    public void ToggleLog()
    {
        LogOpen = !LogOpen;
        RaiseAll(nameof(LogOpen), nameof(LogVisible));
    }

    /// <summary>Tells Verify how many cells the block map has room for.</summary>
    public void SetMapWidth(int cells)
    {
        if (cells == _mapCells || cells <= 0)
        {
            return;
        }

        _mapCells = cells;
        Verify.Resize(cells);
    }

    /// <summary>
    /// The global drop routing of plan section 5.1. A drop while a job runs adds
    /// to the queue instead of replacing, which here means the progress sheet is
    /// not opened for it: the job is submitted and the Queue tab shows it.
    /// </summary>
    public void Drop(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
        {
            return;
        }

        var busy = Queue.RunningCount > 0;
        switch (DropRouter.Route(paths))
        {
            case DropTarget.Verify when DropRouter.Par2Of(paths) is { } par2:
                Mode = Mode.Verify;
                Verify.Open(par2, Settings.VerifyThenRepair);
                if (!busy)
                {
                    Progress.Open(Verify.JobId);
                }

                break;

            case DropTarget.ChecksumVerify when DropRouter.ChecksumFileOf(paths) is { } file:
                Mode = Mode.Checksums;
                Checksums.Open(file);
                break;

            default:
                Mode = Mode.Create;
                Create.Add(paths);
                break;
        }
    }

    /// <summary>A file handed in on the command line, by the association or the shell verb.</summary>
    public void OpenFromCommandLine(string path) => Drop([path]);

    /// <summary>Starts a create and shows the sheet. Add to queue starts it without one.</summary>
    public void StartCreate(bool showProgress)
    {
        var id = Create.Start();
        if (showProgress && id >= 0)
        {
            Progress.Open(id);
        }
        else
        {
            Mode = Mode.Queue;
        }
    }

    public void Dispose()
    {
        _monitor.Updated -= OnSnapshot;
        Progress.Finished -= OnJobFinished;
        _monitor.Dispose();
    }

    private void OnSnapshot(QueueSnapshot snapshot)
    {
        // Asked BEFORE the screens are updated: if this snapshot was the one that
        // could not be read, the screens are about to redraw stale data and the
        // reason should already be in the log when they do.
        if (_core.TakeDecodeError() is { } decodeError)
        {
            RecordDecodeError(decodeError);
        }

        // Fixed order, so every screen in the window renders the same instant.
        Queue.Apply(snapshot);
        CarryOutDuePostAction(snapshot);
        Verify.Apply(snapshot, _mapCells);
        Checksums.Apply(snapshot);
        Progress.Apply(snapshot);
        RaiseAll(nameof(Log), nameof(CommandText));
    }

    /// <summary>
    /// Performs the post-queue action once the core reports it due, and clears it.
    /// </summary>
    /// <remarks>
    /// CLEARED WHETHER OR NOT THE HOST MANAGED IT. If it is not cleared, the core
    /// reports it due on the next snapshot and this runs again ten times a second,
    /// which for "shut down" means a shutdown attempt per tick. A host that refuses
    /// gets one attempt and a log line, which is the behaviour a user who cancelled
    /// a shutdown expects.
    /// </remarks>
    private void CarryOutDuePostAction(QueueSnapshot snapshot)
    {
        if (!snapshot.PostActionDue || snapshot.PostAction == PostQueueAction.None)
        {
            return;
        }

        if (snapshot.PostAction == PostQueueAction.Notify)
        {
            _host.Notify(Strings.QueueWhenFinished, Strings.QueueStateDone);
        }
        else
        {
            _host.PerformPostQueueAction(snapshot.PostAction);
        }

        _core.ClearPostAction();
    }

    /// <summary>
    /// Keeps a short list of decode failures for the log drawer.
    /// </summary>
    /// <remarks>
    /// DE-DUPLICATED AND CAPPED. A core answering a shape this build cannot read
    /// answers it on EVERY poll, so an uncapped list is ten identical lines a
    /// second and the log becomes unreadable at exactly the moment somebody needs
    /// to read it. The first few distinct messages are what diagnose it; the
    /// hundredth copy of the first is not.
    /// </remarks>
    private void RecordDecodeError(string message)
    {
        // Compared on the RAW message and stored FORMATTED. The first spelling
        // compared the raw message against the formatted list, so it never matched
        // and the de-duplication did nothing at all - the cap was quietly doing the
        // whole job, which is how a broken guard hides behind a working one. The
        // seen set is what makes the comparison and the storage the same thing.
        if (!_decodeErrorsSeen.Add(message))
        {
            return;
        }

        if (_decodeErrors.Count >= 5)
        {
            return;
        }

        _decodeErrors.Add($"parfast: could not read the core's answer ({message})");
        Raise(nameof(Log));
    }

    private void OnJobFinished(JobSnapshot job)
    {
        if (Settings.Notifications && !WindowActive)
        {
            // The shared table spells the failure as one sentence carrying both
            // the job and the reason, so the reason goes in the title and the body
            // carries the phase rather than repeating it.
            var reason = job.Error?.Message ?? job.PhaseText;
            var title = job.State == JobState.Done
                ? Strings.Fill(Strings.NotifyDoneTitle, "job", job.Name)
                : Strings.Fill(Strings.NotifyFailed, "job", job.Name, "reason", reason);
            _host.Notify(title, job.State == JobState.Done ? reason : string.Empty);
        }

        if (Settings.AutoCloseProgress && job.State == JobState.Done)
        {
            Progress.Close();
        }
    }

    private void CopyCommand()
    {
        if (string.IsNullOrEmpty(CommandText))
        {
            return;
        }

        _host.SetClipboard(CommandText);

        // A button whose whole effect is invisible gets pressed twice, and then
        // the user wonders whether it worked at all. The view clears this once it
        // has shown it.
        CopyConfirmation = Strings.CommonCommandCopied;
    }

    /// <summary>Set after a successful copy; the view shows it briefly and clears it.</summary>
    public string? CopyConfirmation
    {
        get => _copyConfirmation;
        set => Set(ref _copyConfirmation, value);
    }

    private string? _copyConfirmation;

    private string? RevealTarget() => _mode switch
    {
        Mode.Verify => string.IsNullOrEmpty(Verify.Folder) ? null : Verify.Folder,
        Mode.Create => string.IsNullOrEmpty(Create.Output) ? null : Create.Output,
        Mode.Checksums => Checksums.ChecksumFile,
        _ => null,
    };

    /// <summary>
    /// Applies the create defaults from Settings to the Create screen. Called at
    /// startup only: a settings change mid session must not rewrite a form the
    /// user is in the middle of filling in.
    /// </summary>
    private void ApplySettings()
    {
        var s = Settings.Current;
        var create = s.Create;
        Create.BlockMode = create.BlockAllocation == "size" ? BlockMode.Size : BlockMode.Count;
        if (create.BlockSize > 0)
        {
            // The core sends 0 for "not chosen", and a zero block size would be
            // clamped to four bytes and produce a set of a million blocks.
            Create.BlockSize = create.BlockSize;
        }

        Create.BlockCount = create.BlockCount;
        Create.RecoveryMode = create.RecoveryAllocation switch
        {
            "count" => RecoveryMode.Count,
            "size" => RecoveryMode.Size,
            _ => RecoveryMode.Percent,
        };
        Create.RecoveryPercent = create.RecoveryPercent;
        if (create.RecoveryCount > 0)
        {
            Create.RecoveryCount = create.RecoveryCount;
        }

        if (create.RecoverySize > 0)
        {
            Create.RecoverySize = create.RecoverySize;
        }

        Create.Scheme = create.Scheme;
        Create.StdNaming = create.StdNaming;
        Create.Unicode = create.Unicode;
        Create.Overwrite = create.Overwrite;
        Verify.Options.Purge = s.General.PurgeAfterRepair;
        Verify.Options.KeepDamaged = s.General.KeepDamagedCopies;
        Verify.Options.FastSolver = s.Performance.FastSolver;
        Verify.Options.Threads = s.Performance.Threads;
        Verify.AutoRepairWhenRepairable = s.AutoRepairOnOpen;
    }
}
