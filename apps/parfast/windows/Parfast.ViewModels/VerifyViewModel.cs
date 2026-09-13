using Parfast.Core;
using Parfast.Core.Contracts;
using Parfast.Core.Mock;

namespace Parfast.ViewModels;

/// <summary>How the status pill is coloured. The exact colours are in Tokens.Pill.</summary>
public enum PillTone
{
    Neutral,
    Busy,
    Good,
    Warn,
    Bad,
}

/// <summary>One row of the file table of plan section 5.2.</summary>
public sealed class FileRow : Observable
{
    private SurveyFile _file = new();

    public FileRow(SurveyFile file, FileStripModel? strip = null) => Apply(file, strip);

    public string Name => _file.Name;

    public long Size => _file.Size;

    public string SizeText => Fmt.Bytes(_file.Size);

    public FileStatus Status => _file.Status;

    public string StatusText => _file.Status switch
    {
        FileStatus.Complete => Strings.VerifyFileComplete,
        FileStatus.Damaged => _file.BlocksTotal > _file.BlocksOk
            ? Strings.Fill(Strings.VerifyFileDamagedN, "bad", Fmt.Count(_file.BlocksTotal - _file.BlocksOk))
            : Strings.VerifyFileDamaged,
        FileStatus.Missing => Strings.VerifyFileMissing,
        FileStatus.Misnamed => _file.FoundAs is { } found
            ? Strings.Fill(Strings.VerifyFileFoundAs, "path", PathUtil.FileName(found))
            : Strings.VerifyFileMisnamed,
        FileStatus.Extra => Strings.VerifyFileExtra,
        FileStatus.Hashing => Strings.VerifyFileHashing,
        _ => Strings.VerifyFilePending,
    };

    public string BlocksText => _file.BlocksTotal == 0
        ? string.Empty
        : $"{Fmt.Count(_file.BlocksOk)} / {Fmt.Count(_file.BlocksTotal)}";

    public double Progress => _file.Progress;

    public bool IsHashing => _file.Status == FileStatus.Hashing;

    public bool NeedsAttention => _file.NeedsAttention;

    public string? FoundAs => _file.FoundAs;

    private bool _excluded;

    /// <summary>Set by the row's context menu. Excluded rows are left out of a repair.</summary>
    public bool Excluded
    {
        get => _excluded;
        set
        {
            if (Set(ref _excluded, value))
            {
                Raise(nameof(RowOpacity));
            }
        }
    }

    public double RowOpacity => Excluded ? 0.45 : 1.0;

    /// <summary>
    /// This row's own slice of the block map, or null when the set's block totals
    /// did not reconcile with the strip (see <see cref="FileStripModel"/>).
    /// </summary>
    /// <remarks>
    /// A FRESH INSTANCE IS A CHANGE, which is the other way round from the block map
    /// and deliberately so. The verify page's map model is one object mutated in
    /// place for the life of the page, which is why <c>BlockMap</c> had to grow an
    /// explicit <c>Refresh()</c> - assigning a dependency property the value it
    /// already holds raises nothing. A row strip lives inside a
    /// <c>DataTemplate</c>, where there is nothing to call Refresh ON, so the model
    /// handed to it is REPLACED rather than mutated and the dependency property's
    /// own change callback does the work. <see cref="FileStripModel.Build"/> hands
    /// back the previous instance unchanged when the picture has not moved, so a
    /// settled table is still not repainting at ten hertz.
    /// </remarks>
    public FileStripModel? Strip { get; private set; }

    public void Apply(SurveyFile file, FileStripModel? strip = null)
    {
        _file = file;
        Strip = strip;
        RaiseAll(nameof(Name), nameof(Size), nameof(SizeText), nameof(Status), nameof(StatusText),
            nameof(BlocksText), nameof(Progress), nameof(IsHashing), nameof(NeedsAttention), nameof(FoundAs),
            nameof(Strip));
    }
}

/// <summary>
/// Verify &amp; repair: the landing mode, and the one a .par2 opens into
/// (plan section 5.2).
/// </summary>
/// <remarks>
/// It owns the set under inspection, the verify or repair job running over it,
/// the block map model, the file table and the action bar's enablement. It holds
/// no WinUI type and is driven entirely by <see cref="Apply"/> calls carrying a
/// snapshot, which is what lets the tests walk it through every state of the
/// scenario catalogue with no window.
/// </remarks>
public sealed class VerifyViewModel : Observable
{
    private readonly ICoreClient _core;
    private JobSnapshot? _job;

    public VerifyViewModel(ICoreClient core)
    {
        _core = core;
        Options = new VerifyOptionsViewModel(core.Capabilities);
        VerifyAgainCommand = new Command(() => Start(repair: false), () => Par2Path is not null && !IsBusy);
        RepairCommand = new Command(() => Start(repair: true), () => CanRepair);
        CancelCommand = new Command(Cancel, () => IsBusy);
        PurgeCommand = new Command(Purge, () => Verdict == Verdict.Repaired && !Purged);
    }

    public VerifyOptionsViewModel Options { get; }

    public BlockMapModel Map { get; } = new();

    public Rows<FileRow> Files { get; } = [];

    public Rows<string> ExtraDirs { get; } = [];

    public Command VerifyAgainCommand { get; }

    public Command RepairCommand { get; }

    public Command CancelCommand { get; }

    public Command PurgeCommand { get; }

    public string? Par2Path { get; private set; }

    public long JobId { get; private set; } = -1;

    public bool HasSet => Par2Path is not null;

    private bool _showProblemsOnly;

    public bool ShowProblemsOnly
    {
        get => _showProblemsOnly;
        set
        {
            if (Set(ref _showProblemsOnly, value))
            {
                RebuildRows();
            }
        }
    }

    public Survey? Survey => _job?.Survey;

    public string SetName => Survey?.SetName ?? PathUtil.FileName(Par2Path ?? string.Empty);

    public string Folder => Survey?.Folder ?? PathUtil.DirectoryName(Par2Path ?? string.Empty);

    public string FileCountText => Fmt.Count(Survey?.Files.Count(f => f.Status != FileStatus.Extra) ?? 0);

    public string BlockSizeText => Fmt.Bytes(Survey?.BlockSize ?? 0);

    public string SourceBlocksText => Fmt.Count(Survey?.SourceBlocks ?? 0);

    public string RecoveryBlocksText => Fmt.Count(Survey?.RecoveryAvailable ?? 0);

    public Verdict Verdict => Survey?.Verdict ?? Verdict.Unknown;

    public bool IsBusy => _job?.IsActive == true;

    public bool IsRepairJob => _job?.Kind == JobKind.Repair;

    public double Progress => _job?.Progress ?? 0;

    public bool Purged => _job?.Result?.Purged == true;

    /// <summary>
    /// Repair is offered only when the verdict says the set can be repaired.
    /// Offering it on an unrepairable set and failing is the single most
    /// annoying thing a PAR2 tool does, and the verdict is the whole reason the
    /// survey exists.
    /// </summary>
    public bool CanRepair =>
        !IsBusy
        && Par2Path is not null
        && (Verdict is Verdict.Repairable
            // Rename-only on an unrepairable set is a REAL and useful case: the
            // parity is short, so the data cannot be rebuilt, but files found
            // under other names can still be renamed to what the set expects.
            // Refusing it would make the user do by hand what the engine can do.
            || (Verdict is Verdict.Unrepairable && Options.RenameOnly && Map.Misnamed > 0));

    public string StatusText => Verdict switch
    {
        Verdict.Verifying => Strings.Fill(Strings.VerifyPillVerifying, "percent", Fmt.Percent(Progress)),
        Verdict.Complete => Strings.VerifyPillComplete,
        Verdict.Repairable => Strings.Fill(Strings.VerifyPillRepairable,
            "needed", Fmt.Count(Survey?.RecoveryNeeded ?? 0),
            "available", Fmt.Count(Survey?.RecoveryAvailable ?? 0)),
        Verdict.Unrepairable => Strings.Fill(Strings.VerifyPillUnrepairable,
            "short", Fmt.Count(Math.Max(0, (Survey?.RecoveryNeeded ?? 0) - (Survey?.RecoveryAvailable ?? 0)))),
        Verdict.Repaired => Strings.VerifyPillRepaired,
        Verdict.Failed => Strings.Fill(Strings.VerifyPillRepairFailed,
            "reason", _job?.Error?.Message ?? "reason unknown"),
        _ => string.Empty,
    };

    public PillTone StatusTone => Verdict switch
    {
        Verdict.Verifying => PillTone.Busy,
        Verdict.Complete => PillTone.Good,
        Verdict.Repaired => PillTone.Good,
        Verdict.Repairable => PillTone.Warn,
        Verdict.Unrepairable => PillTone.Bad,
        Verdict.Failed => PillTone.Bad,
        _ => PillTone.Neutral,
    };

    /// <summary>The post-repair summary card of plan section 5.2, or null.</summary>
    public string? SummaryText =>
        IsRepairJob && _job is { State: JobState.Done, Result: { } result } && Verdict == Verdict.Repaired
            ? Strings.Fill(
                result.RepairedFiles == 1 ? Strings.VerifySummaryRepairedOne : Strings.VerifySummaryRepaired,
                "files", Fmt.Count(result.RepairedFiles), "time", Fmt.Duration(_job.ElapsedMs))
            : null;

    public IReadOnlyList<string> Log => _job?.LogTail ?? [];

    public string CommandText => Par2Path is null
        ? string.Empty
        : MockPlanner.CommandLine(Par2Path, Options.ToOptions(), IsRepairJob, Options.Purge);

    /// <summary>Opens a set and starts a verify, which is what a drop or a double click does.</summary>
    public void Open(string par2Path, bool autoRepair)
    {
        Par2Path = par2Path;
        AutoRepairWhenRepairable = autoRepair;
        _job = null;
        Files.Clear();
        _strips = [];
        Map.Update(null, 0);
        RaiseEverything();
        Start(repair: false);
    }

    /// <summary>Settings: verify only, or verify then repair if repairable.</summary>
    public bool AutoRepairWhenRepairable { get; set; }

    public void AddExtraDir(string dir)
    {
        if (!ExtraDirs.Contains(dir))
        {
            ExtraDirs.Add(dir);
        }
    }

    /// <summary>
    /// Called on the UI thread with each fresh queue snapshot. It picks out this
    /// screen's job by id, so a queue full of other jobs cannot move this screen.
    /// </summary>
    public void Apply(QueueSnapshot queue, int mapCells)
    {
        var job = queue.Jobs.FirstOrDefault(j => j.Id == JobId);
        if (job is null)
        {
            return;
        }

        var wasVerifying = _job?.State == JobState.Running;
        _job = job;
        Map.Update(job.Survey, mapCells);
        RebuildRows();
        RaiseEverything();

        // Verify then repair, from Settings. Fired exactly once, on the
        // transition into a finished verify with a repairable verdict: doing it
        // on every snapshot would submit a repair per poll.
        if (AutoRepairWhenRepairable
            && wasVerifying
            && job is { State: JobState.Done, Kind: JobKind.Verify }
            && Verdict == Verdict.Repairable)
        {
            Start(repair: true);
        }
    }

    /// <summary>Recomputes the cells for a new control width without a new snapshot.</summary>
    public void Resize(int mapCells)
    {
        Map.Update(_job?.Survey, mapCells);
        Raise(nameof(Map));
    }

    private void Start(bool repair)
    {
        if (Par2Path is null)
        {
            return;
        }

        var verify = new VerifySpec
        {
            Par2 = Par2Path,
            ExtraDirs = ExtraDirs.ToList(),
            Options = Options.ToOptions(),
        };

        JobId = _core.Submit(repair
            ? JobSpec.ForRepair(RepairSpec.From(verify, Options.Purge, Options.KeepDamaged))
            : JobSpec.ForVerify(verify));
        RaiseEverything();
    }

    private void Cancel()
    {
        if (JobId >= 0)
        {
            _core.Cancel(JobId);
        }
    }

    private void Purge()
    {
        if (Par2Path is null)
        {
            return;
        }

        // Purge on its own is a repair with nothing to repair and purge set,
        // which is how the CLI spells it (-p on `parfast r`). No separate
        // verb, so no second code path to keep correct.
        var verify = new VerifySpec { Par2 = Par2Path, ExtraDirs = ExtraDirs.ToList(), Options = Options.ToOptions() };
        JobId = _core.Submit(JobSpec.ForRepair(RepairSpec.From(verify, purge: true, Options.KeepDamaged)));
        RaiseEverything();
    }

    private IReadOnlyList<FileStripModel?> _strips = [];

    private void RebuildRows()
    {
        var all = Survey?.Files ?? [];

        // THE STRIPS ARE CUT OVER THE UNFILTERED LIST, and that is load-bearing. A
        // member's blocks are the range starting at the running sum of every
        // PRECEDING member's blocks_total, so the Problems only filter - which
        // removes rows from the TABLE - must not be allowed anywhere near the
        // offsets. Cutting over the filtered list would slide every surviving strip
        // onto some other file's blocks and draw a confident picture of the wrong
        // file, which is the one failure this control must not have.
        _strips = FileStripModel.Build(Map.States, all, _strips);
        var strips = new Dictionary<string, FileStripModel?>(StringComparer.Ordinal);
        for (var i = 0; i < all.Count; i++)
        {
            strips[all[i].Name] = _strips[i];
        }

        var incoming = all
            .Where(f => !ShowProblemsOnly || f.NeedsAttention)
            .ToList();
        Files.Sync(
            incoming.Select(f => new FileRow(f, StripFor(strips, f.Name))).ToList(),
            row => row.Name,
            (existing, fresh) => existing.Apply(
                FindFile(incoming, fresh.Name), StripFor(strips, fresh.Name)));
        Raise(nameof(ProblemCount));
    }

    private static FileStripModel? StripFor(
        IReadOnlyDictionary<string, FileStripModel?> strips, string name) =>
        strips.TryGetValue(name, out var strip) ? strip : null;

    private static SurveyFile FindFile(IReadOnlyList<SurveyFile> files, string name) =>
        files.FirstOrDefault(f => f.Name == name) ?? new SurveyFile { Name = name };

    public int ProblemCount => Survey?.Files.Count(f => f.NeedsAttention) ?? 0;

    private void RaiseEverything()
    {
        RaiseAll(nameof(HasSet), nameof(SetName), nameof(Folder), nameof(FileCountText), nameof(BlockSizeText),
            nameof(SourceBlocksText), nameof(RecoveryBlocksText), nameof(Verdict), nameof(StatusText),
            nameof(StatusTone), nameof(IsBusy), nameof(IsRepairJob), nameof(Progress), nameof(CanRepair),
            nameof(SummaryText), nameof(Log), nameof(CommandText), nameof(Survey), nameof(Map),
            nameof(Purged), nameof(JobId), nameof(ProblemCount));
        VerifyAgainCommand.Refresh();
        RepairCommand.Refresh();
        CancelCommand.Refresh();
        PurgeCommand.Refresh();
    }
}

/// <summary>
/// The Options popover of the action bar. Each control is hidden when the core
/// says it cannot do that thing, which is the capability rule of plan 4.5.
/// </summary>
public sealed class VerifyOptionsViewModel(Capabilities capabilities) : Observable
{
    private bool _purge;
    private bool _keepDamaged;
    private bool _renameOnly;
    private bool _dataSkipping;
    private int _skipLeaway = 64;
    private bool _fastSolver;
    private int? _threads;

    public bool Purge { get => _purge; set => Set(ref _purge, value); }

    public bool KeepDamaged { get => _keepDamaged; set => Set(ref _keepDamaged, value); }

    public bool RenameOnly { get => _renameOnly; set => Set(ref _renameOnly, value); }

    public bool DataSkipping { get => _dataSkipping; set => Set(ref _dataSkipping, value); }

    public int SkipLeaway { get => _skipLeaway; set => Set(ref _skipLeaway, value); }

    public bool FastSolver { get => _fastSolver; set => Set(ref _fastSolver, value); }

    public int? Threads { get => _threads; set => Set(ref _threads, value); }

    public bool ShowDataSkipping => capabilities.DataSkipping;

    public bool ShowFastSolver => capabilities.FastSolver;

    public VerifyOptions ToOptions() => new()
    {
        RenameOnly = RenameOnly,
        DataSkipping = DataSkipping && ShowDataSkipping,
        SkipLeaway = SkipLeaway,
        FastSolver = ShowFastSolver ? FastSolver : null,
        Threads = Threads,
    };
}
