using Parfast.Core;
using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>Which half of a posting set wrote a file.</summary>
public enum PostingHalf
{
    Rar,
    Par2,
}

/// <summary>One row of the posting set's written-files list.</summary>
public sealed class PostingFileRow(PostingHalf half, WrittenFile file)
{
    public PostingHalf Half { get; } = half;

    public string Name { get; } = file.Name;

    public long Size { get; } = file.Size;

    public string SizeText => Fmt.Bytes(Size);

    public string HalfText => Half == PostingHalf.Rar ? Strings.PostingOutputRar : Strings.PostingOutputPar2;
}

/// <summary>One compression choice: the level the spec carries and the word the picker shows.</summary>
public sealed record CompressionLevel(int Level, string Label);

/// <summary>
/// Create a posting set (plan B1 of research/PLAN-PARFAST-APP-RARFAST-AND-1.0-2026-10-25.md):
/// sources in, a RAR 5 archive or volume set and a PAR2 set over it out, as ONE job.
/// </summary>
/// <remarks>
/// GATED ON THE posting_set CAPABILITY. <see cref="IsAvailable"/> is what the shell
/// hides the nav entry behind, because an engine without the RAR half refuses every
/// job this screen could submit.
/// <para>
/// THE ROUTE IS THE CORE'S. Before a job has run the screen shows the route the form
/// is SHAPED for (one stored archive with no recovery record is one pass, anything
/// else two), labelled as what to expect; once a job finishes, result.posting.route
/// and its route_reason replace it. The prediction is the API's own route table and
/// nothing more, so it cannot drift from it without the table moving too.
/// </para>
/// <para>
/// THE PASSWORD IS HELD HERE AND IN THE SPEC, AND NOWHERE ELSE. It is never part of
/// a status line, a log line or a command: the core answers <c>{"withheld":true}</c>
/// for it in every snapshot, <see cref="RarSpec"/> redacts it from its ToString, and
/// no property of this class derives text from it beyond <see cref="HasPassword"/>.
/// </para>
/// </remarks>
public sealed class PostingSetViewModel : Observable
{
    /// <summary>The default volume size when a user picks "split by size": 100 MiB.</summary>
    public const long DefaultVolumeSize = 100L * 1024 * 1024;

    private readonly ICoreClient _core;
    private readonly Func<string, (long Size, DateTimeOffset Modified, bool IsFolder)?> _stat;

    private string _outputDir = string.Empty;
    private string _name = string.Empty;
    private RarSplit _split = RarSplit.None;
    private long _volumeSize = DefaultVolumeSize;
    private int _volumeCount = 20;
    private int _compression;
    private bool _solid;
    private string _password = string.Empty;
    private bool _encryptHeaders = true;
    private int _recoveryRecordPercent;
    private RecoveryMode _recoveryMode = RecoveryMode.Percent;
    private double _recoveryPercent = 10;
    private int _recoveryCount = 200;
    private long _recoverySize = 100L * 1024 * 1024;
    private int _blockCount = 2000;
    private VolumeScheme _par2Scheme = VolumeScheme.Pow2;
    private bool _overwrite;
    private long _jobId = -1;
    private JobSnapshot? _job;

    public PostingSetViewModel(
        ICoreClient core,
        Func<string, (long Size, DateTimeOffset Modified, bool IsFolder)?>? stat = null)
    {
        _core = core;
        _stat = stat ?? DefaultStat;
        Sources.CollectionChanged += (_, _) =>
        {
            AutoOutputAndName();
            Changed();
        };
        CreateCommand = new Command(() => Start(), () => CanStart);
        AddToQueueCommand = new Command(() => Start(), () => CanStart);
        CancelCommand = new Command(() => Cancel(), () => IsBusy);
        RemoveCommand = new Command(RemoveSelected, () => Selected.Count > 0);
    }

    public Command CreateCommand { get; }

    public Command AddToQueueCommand { get; }

    public Command CancelCommand { get; }

    public Command RemoveCommand { get; }

    /// <summary>Whether this engine accepts a posting set at all. False hides the screen.</summary>
    public bool IsAvailable => _core.Capabilities.PostingSet;

    public long JobId => _jobId;

    public JobSnapshot? Job => _job;

    // ---- sources ----

    public Rows<SourceRow> Sources { get; } = [];

    public List<SourceRow> Selected { get; } = [];

    public bool HasSources => Sources.Count > 0;

    public string SourcesFooter => Sources.Count == 0
        ? string.Empty
        : Strings.Fill(Strings.CreateSourcesFooter,
            "files", Fmt.FileCount(Sources.Count),
            "size", Fmt.Bytes(Sources.Sum(s => s.Size)));

    public void Add(IEnumerable<string> paths, bool recursive = true)
    {
        foreach (var path in paths)
        {
            if (Sources.Any(s => string.Equals(s.Path, path, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (_stat(path) is { } stat)
            {
                Sources.Add(new SourceRow(path, stat.Size, stat.Modified, stat.IsFolder, recursive));
            }
        }
    }

    private void RemoveSelected()
    {
        foreach (var row in Selected.ToList())
        {
            Sources.Remove(row);
        }

        Selected.Clear();
        RemoveCommand.Refresh();
    }

    // ---- output ----

    public string OutputDir
    {
        get => _outputDir;
        set { if (Set(ref _outputDir, value ?? string.Empty)) { Changed(); } }
    }

    /// <summary>The archive name: one path component, the stem of every file in the set.</summary>
    public string Name
    {
        get => _name;
        set { if (Set(ref _name, (value ?? string.Empty).Trim())) { Changed(); } }
    }

    /// <summary>Where the set will be written, spelled with this name, for the field's hint.</summary>
    public string NameTip => Strings.Fill(Strings.PostingNameTip, "name", string.IsNullOrEmpty(_name) ? "name" : _name);

    /// <summary>
    /// A name the core would refuse with bad_spec: empty, a dot entry, or one
    /// carrying a separator or a character no Windows file name may hold.
    /// </summary>
    public static bool IsValidName(string name) =>
        !string.IsNullOrWhiteSpace(name)
        && name is not ("." or "..")
        && name.IndexOfAny(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) < 0
        && !name.Any(char.IsControl);

    public bool Overwrite
    {
        get => _overwrite;
        set => Set(ref _overwrite, value);
    }

    // ---- volumes ----

    public RarSplit Split
    {
        get => _split;
        set
        {
            if (Set(ref _split, value))
            {
                RaiseAll(nameof(SplitNone), nameof(SplitBySize), nameof(SplitByCount));
                Changed();
            }
        }
    }

    public bool SplitNone
    {
        get => _split == RarSplit.None;
        set { if (value) { Split = RarSplit.None; } }
    }

    public bool SplitBySize
    {
        get => _split == RarSplit.Size;
        set { if (value) { Split = RarSplit.Size; } }
    }

    public bool SplitByCount
    {
        get => _split == RarSplit.Count;
        set { if (value) { Split = RarSplit.Count; } }
    }

    /// <summary>The volume FILE size, rar's -v. Not clamped: an under-floor value is shown as an error.</summary>
    public long VolumeSize
    {
        get => _volumeSize;
        set { if (Set(ref _volumeSize, Math.Max(0, value))) { Changed(); } }
    }

    public string VolumeSizeText
    {
        get => Fmt.Bytes(_volumeSize);
        set
        {
            if (Fmt.ParseSize(value) is { } parsed)
            {
                VolumeSize = parsed;
            }

            Raise();
        }
    }

    public int VolumeCount
    {
        get => _volumeCount;
        set { if (Set(ref _volumeCount, Math.Clamp(value, 1, 9999))) { Changed(); } }
    }

    // ---- archive ----

    /// <summary>The six levels in the order the picker lists them. 0 stores, the posting default.</summary>
    public static IReadOnlyList<CompressionLevel> CompressionLevels { get; } =
    [
        new(0, Strings.PostingCompressionStore),
        new(1, Strings.PostingCompressionFastest),
        new(2, Strings.PostingCompressionFast),
        new(3, Strings.PostingCompressionNormal),
        new(4, Strings.PostingCompressionGood),
        new(5, Strings.PostingCompressionBest),
    ];

    public int Compression
    {
        get => _compression;
        set { if (Set(ref _compression, Math.Clamp(value, 0, 5))) { Changed(); } }
    }

    public bool Solid
    {
        get => _solid;
        set => Set(ref _solid, value);
    }

    /// <summary>The archive password. Empty for none. Never logged or echoed by anything here.</summary>
    public string Password
    {
        get => _password;
        set
        {
            if (Set(ref _password, value ?? string.Empty))
            {
                Raise(nameof(HasPassword));
            }
        }
    }

    public bool HasPassword => _password.Length > 0;

    /// <summary>rar's -hp, on by default; only read when there is a password, so only shown then.</summary>
    public bool EncryptHeaders
    {
        get => _encryptHeaders;
        set => Set(ref _encryptHeaders, value);
    }

    /// <summary>The RAR recovery record as a percent of the archive. 0 writes none.</summary>
    public int RecoveryRecordPercent
    {
        get => _recoveryRecordPercent;
        set { if (Set(ref _recoveryRecordPercent, Math.Clamp(value, 0, 100))) { Changed(); } }
    }

    // ---- PAR2 ----

    public RecoveryMode RecoveryMode
    {
        get => _recoveryMode;
        set
        {
            if (Set(ref _recoveryMode, value))
            {
                RaiseAll(nameof(ByPercent), nameof(ByRecoveryCount), nameof(ByRecoverySize));
            }
        }
    }

    public bool ByPercent
    {
        get => _recoveryMode == RecoveryMode.Percent;
        set { if (value) { RecoveryMode = RecoveryMode.Percent; } }
    }

    public bool ByRecoveryCount
    {
        get => _recoveryMode == RecoveryMode.Count;
        set { if (value) { RecoveryMode = RecoveryMode.Count; } }
    }

    public bool ByRecoverySize
    {
        get => _recoveryMode == RecoveryMode.Size;
        set { if (value) { RecoveryMode = RecoveryMode.Size; } }
    }

    public double RecoveryPercent
    {
        get => _recoveryPercent;
        set => Set(ref _recoveryPercent, Math.Clamp(value, 0, 1000));
    }

    public int RecoveryCount
    {
        get => _recoveryCount;
        set => Set(ref _recoveryCount, Math.Clamp(value, 0, 65535));
    }

    public long RecoverySize
    {
        get => _recoverySize;
        set => Set(ref _recoverySize, Math.Max(0, value));
    }

    public string RecoverySizeText
    {
        get => Fmt.Bytes(_recoverySize);
        set
        {
            if (Fmt.ParseSize(value) is { } parsed)
            {
                RecoverySize = parsed;
            }

            Raise();
        }
    }

    /// <summary>The same four chips as Create, so the two screens offer one set of levels.</summary>
    public static IReadOnlyList<double> PercentChips => CreateViewModel.PercentChips;

    public void ApplyChip(double percent)
    {
        RecoveryMode = RecoveryMode.Percent;
        RecoveryPercent = percent;
    }

    public int BlockCount
    {
        get => _blockCount;
        set => Set(ref _blockCount, Math.Clamp(value, 1, 32768));
    }

    public VolumeScheme Par2Scheme
    {
        get => _par2Scheme;
        set => Set(ref _par2Scheme, value);
    }

    // ---- route ----

    /// <summary>Whether the form, as filled in, takes the one-pass route.</summary>
    public bool ExpectsOnePass => ToRarSpec().OnePassShaped;

    /// <summary>
    /// The route line: what to expect before a job has run, what happened after.
    /// </summary>
    public string RouteText
    {
        get
        {
            if (_job?.Result?.Posting is { } posting)
            {
                return posting.Route switch
                {
                    PostingRoute.OnePass => Strings.PostingRouteOnePass,
                    PostingRoute.TwoPass => Strings.Fill(Strings.PostingRouteTwoPassBecause,
                        "reason", posting.RouteReason.TrimEnd('.')),
                    _ => string.Empty,
                };
            }

            return ExpectsOnePass ? Strings.PostingRouteExpectOnePass : Strings.PostingRouteExpectTwoPass;
        }
    }

    /// <summary>The route the finished job took, or null before one has finished.</summary>
    public PostingRoute? RouteTaken => _job?.Result?.Posting?.Route;

    // ---- the job ----

    public bool IsBusy => _job is { } job && !job.IsFinished;

    public double Progress => _job?.Progress ?? 0;

    public string PhaseText => _job?.PhaseText ?? string.Empty;

    public JobState? State => _job?.State;

    /// <summary>Every file the set wrote, RAR first then PAR2, from result.posting.</summary>
    public Rows<PostingFileRow> OutputFiles { get; } = [];

    public string OutputTotalText => OutputFiles.Count == 0
        ? string.Empty
        : Strings.Fill(Strings.CreatePreviewTotal,
            "files", Fmt.Count(OutputFiles.Count),
            "size", Fmt.Bytes(OutputFiles.Sum(f => f.Size)));

    /// <summary>What went wrong, in the copy table's words where it has them.</summary>
    public string? ErrorText
    {
        get
        {
            if (_job is null)
            {
                return null;
            }

            if (_job.State == JobState.Cancelled)
            {
                return Strings.ErrorCancelled;
            }

            if (_job.State != JobState.Failed)
            {
                return null;
            }

            var error = _job.Error;
            return error?.Code switch
            {
                "password_required" => Strings.ErrorPasswordRequired,
                "rar_failed" => Strings.Fill(Strings.ErrorRarFailed, "reason", error.Message),
                "exists" => Strings.ErrorOutputExists,
                _ => error?.Message is { Length: > 0 } message ? message : Strings.ErrorTitle,
            };
        }
    }

    public PillTone Tone => _job?.State switch
    {
        null => PillTone.Neutral,
        JobState.Done => PillTone.Good,
        JobState.Failed => PillTone.Bad,
        JobState.Cancelled or JobState.Interrupted => PillTone.Warn,
        _ => PillTone.Busy,
    };

    // ---- validation ----

    /// <summary>Why the form cannot be submitted, or null when it can.</summary>
    public string? ValidationText
    {
        get
        {
            if (Sources.Count == 0)
            {
                return Strings.ErrorNoSources;
            }

            if (_split == RarSplit.Size && _volumeSize < RarVolumes.MinSize)
            {
                return Strings.PostingVolumesMinSize;
            }

            return null;
        }
    }

    public bool CanStart =>
        ValidationText is null && IsValidName(_name) && _outputDir.Length > 0 && IsAvailable;

    // ---- spec ----

    public PostingSetSpec ToSpec() => new()
    {
        Sources = Sources.Select(s => new SourceSpec
        {
            Path = s.Path,
            Recursive = s.IsFolder ? s.Recursive : null,
        }).ToList(),
        OutputDir = _outputDir,
        Name = _name,
        Rar = ToRarSpec(),
        Par2 = new PostingPar2Spec
        {
            Block = BlockSpec.ByCount(_blockCount),
            Recovery = _recoveryMode switch
            {
                RecoveryMode.Percent => RecoverySpec.ByPercent(_recoveryPercent),
                RecoveryMode.Count => RecoverySpec.ByCount(_recoveryCount),
                _ => RecoverySpec.BySize(_recoverySize),
            },
            Volumes = _par2Scheme == VolumeScheme.None ? VolumeSpec.None() : VolumeSpec.Pow2(),
        },
        Overwrite = _overwrite,
    };

    private RarSpec ToRarSpec() => new()
    {
        Volumes = _split switch
        {
            RarSplit.Size => RarVolumes.BySize(_volumeSize),
            RarSplit.Count => RarVolumes.ByCount(_volumeCount),
            _ => RarVolumes.None(),
        },
        Compression = _compression,
        Solid = _solid,
        // An empty field is NO password, sent as an absent key rather than "".
        Password = _password.Length > 0 ? _password : null,
        EncryptHeaders = _encryptHeaders,
        RecoveryPercent = _recoveryRecordPercent,
    };

    /// <summary>
    /// Submits the job and returns its id. Create and Add to queue both call this;
    /// everything goes through the queue, as on Create.
    /// </summary>
    public long Start()
    {
        if (!CanStart)
        {
            return -1;
        }

        _jobId = _core.Submit(JobSpec.ForPostingSet(ToSpec()));
        _job = _jobId >= 0 ? _core.Snapshot(_jobId) : null;
        OutputFiles.Clear();
        RaiseJob();
        return _jobId;
    }

    /// <summary>Stops the running job. The core removes every file it wrote, so nothing is left to clean.</summary>
    public bool Cancel() => _jobId >= 0 && _core.Cancel(_jobId);

    /// <summary>Takes this screen's job out of the shell's one queue snapshot.</summary>
    public void Apply(QueueSnapshot queue)
    {
        if (_jobId < 0 || queue.Jobs.FirstOrDefault(j => j.Id == _jobId) is not { } job)
        {
            return;
        }

        _job = job;
        if (job.Result?.Posting is { } posting)
        {
            var rows = posting.Rar.Select(f => new PostingFileRow(PostingHalf.Rar, f))
                .Concat(posting.Par2.Select(f => new PostingFileRow(PostingHalf.Par2, f)))
                .ToList();
            if (rows.Count != OutputFiles.Count)
            {
                OutputFiles.Reset(rows);
            }
        }
        else if (OutputFiles.Count > 0)
        {
            OutputFiles.Clear();
        }

        RaiseJob();
    }

    private void RaiseJob()
    {
        RaiseAll(nameof(Job), nameof(JobId), nameof(IsBusy), nameof(Progress), nameof(PhaseText), nameof(State),
            nameof(RouteText), nameof(RouteTaken), nameof(OutputTotalText), nameof(ErrorText), nameof(Tone));
        CancelCommand.Refresh();
        CreateCommand.Refresh();
        AddToQueueCommand.Refresh();
    }

    private void Changed()
    {
        RaiseAll(nameof(HasSources), nameof(SourcesFooter), nameof(NameTip), nameof(ExpectsOnePass),
            nameof(RouteText), nameof(ValidationText), nameof(CanStart), nameof(VolumeSizeText));
        CreateCommand.Refresh();
        AddToQueueCommand.Refresh();
        RemoveCommand.Refresh();
    }

    /// <summary>
    /// Fills the output folder and the archive name from the sources, the first
    /// time only, exactly as Create fills its output: a starting point the user
    /// can change, never a value that overwrites what they typed.
    /// </summary>
    private void AutoOutputAndName()
    {
        if (Sources.Count == 0)
        {
            return;
        }

        var parent = CreateViewModel.CommonParent(Sources.Select(s => s.Path).ToList());
        if (string.IsNullOrEmpty(_outputDir) && parent is not null)
        {
            _outputDir = parent;
            Raise(nameof(OutputDir));
        }

        if (!string.IsNullOrEmpty(_name))
        {
            return;
        }

        // A single folder names the set after itself; files after their common stem.
        var stem = Sources.Count == 1 && Sources[0].IsFolder
            ? Sources[0].Name
            : CreateViewModel.CommonStem(Sources.Select(s => s.Name).ToList());
        if (string.IsNullOrEmpty(stem) && parent is not null)
        {
            stem = PathUtil.FileName(parent);
        }

        if (!string.IsNullOrEmpty(stem))
        {
            _name = stem;
            Raise(nameof(Name));
        }
    }

    private static (long Size, DateTimeOffset Modified, bool IsFolder)? DefaultStat(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                var dir = new DirectoryInfo(path);
                var size = dir.EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
                return (size, dir.LastWriteTimeUtc, true);
            }

            var file = new FileInfo(path);
            return file.Exists ? (file.Length, file.LastWriteTimeUtc, false) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Skipped rather than thrown into a drop handler, as on Create.
            return null;
        }
    }
}
