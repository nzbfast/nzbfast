using Parfast.Core;
using Parfast.Core.Contracts;
using Parfast.Core.Mock;

namespace Parfast.ViewModels;

/// <summary>Which quantity the user is choosing source blocks by.</summary>
public enum BlockMode
{
    Size,
    Count,
}

/// <summary>Which quantity the user is choosing recovery by.</summary>
public enum RecoveryMode
{
    Percent,
    Count,
    Size,
}

/// <summary>One row of the Sources table.</summary>
public sealed class SourceRow(string path, long size, DateTimeOffset modified, bool isFolder, bool recursive)
    : Observable
{
    private bool _recursive = recursive;

    public string Path { get; } = path;

    public string Name { get; } = PathUtil.FileName(path);

    public long Size { get; } = size;

    public string SizeText => IsFolder ? string.Empty : Fmt.Bytes(Size);

    public DateTimeOffset Modified { get; } = modified;

    public string ModifiedText => Fmt.When(Modified);

    public bool IsFolder { get; } = isFolder;

    /// <summary>Only meaningful for a folder row; the picker's accessory sets it.</summary>
    public bool Recursive
    {
        get => _recursive;
        set => Set(ref _recursive, value);
    }
}

/// <summary>
/// Create (plan section 5.3): sources, source blocks, recovery, output and the
/// live preview.
/// </summary>
/// <remarks>
/// The rule that shapes this class: EVERY EDIT RECOMPUTES THE PREVIEW, and the
/// preview is the core's answer, not this class's arithmetic. The non-chosen
/// quantities on screen (the block size when you are choosing a count, the
/// recovery percent when you are choosing a size) are read back OUT of the
/// preview rather than computed here, which is what keeps the two apps and the
/// CLI from each having their own rounding.
/// <para>
/// <see cref="Recompute"/> is therefore called on every keystroke, and it does
/// no I/O beyond stat by contract. It is also cheap enough to call that often,
/// which is the reason the plan put the planner behind pf_plan_preview rather
/// than behind a job.
/// </para>
/// </remarks>
public sealed class CreateViewModel : Observable
{
    private readonly ICoreClient _core;
    private readonly Func<string, (long Size, DateTimeOffset Modified, bool IsFolder)?> _stat;

    private BlockMode _blockMode = BlockMode.Count;
    private long _blockSize = 1048576;
    private int _blockCount = 2000;
    private RecoveryMode _recoveryMode = RecoveryMode.Percent;
    private double _recoveryPercent = 10;
    private int _recoveryCount = 200;
    private long _recoverySize = 100L * 1024 * 1024;
    private PathMode _pathMode = PathMode.Basename;
    private string? _basePath;
    private string _output = string.Empty;
    private VolumeScheme _scheme = VolumeScheme.None;
    private int _uniformFiles = 7;
    private int _uniformBlocksPerFile = 100;
    private long _uniformFileSize = 10L * 1024 * 1024;
    private string _uniformArm = "files";
    private string _pow2LimitArm = "largest";
    private int _pow2LimitBlocks = 512;
    private long _pow2LimitSize = 50L * 1024 * 1024;
    private int _firstRecoveryBlock;
    private string _comment = string.Empty;
    private bool _overwrite;
    private bool _stdNaming;
    private UnicodePolicy _unicode = UnicodePolicy.Auto;
    private PlanPreview _preview = PlanPreview.Empty;
    private long _jobId = -1;

    public CreateViewModel(
        ICoreClient core,
        Func<string, (long Size, DateTimeOffset Modified, bool IsFolder)?>? stat = null)
    {
        _core = core;
        _stat = stat ?? DefaultStat;
        Sources.CollectionChanged += (_, _) =>
        {
            AutoBaseAndOutput();
            Recompute();
        };
        CreateCommand = new Command(() => Start(), () => Sources.Count > 0);
        AddToQueueCommand = new Command(() => Start(), () => Sources.Count > 0);
        RemoveCommand = new Command(RemoveSelected, () => Selected.Count > 0);
        RefreshCommand = new Command(RefreshSizes, () => Sources.Count > 0);
    }

    public Rows<SourceRow> Sources { get; } = [];

    public List<SourceRow> Selected { get; } = [];

    public Command CreateCommand { get; }

    public Command AddToQueueCommand { get; }

    public Command RemoveCommand { get; }

    public Command RefreshCommand { get; }

    public Capabilities Capabilities => _core.Capabilities;

    public long JobId => _jobId;

    // ---- sources ----

    /// <remarks>
    /// Fmt.FileCount supplies the NOUN as well as the number ("1 file", "3
    /// files"), so `create.sources.footer` must not supply it too. It read
    /// "{files} files, {size}" until 12 Sep 2026 and this screen rendered
    /// "3 files files, 2.05 GiB" - found on the first Windows screenshot of
    /// Create, with every test green, because a doubled word is only wrong to a
    /// reader. The key lost its noun rather than this call site losing
    /// FileCount, because FileCount is what knows that one file is not "1
    /// files"; ShellTests.TheSourcesFooterReadsOneFileAndNotOneFiles pins that,
    /// and passing a bare count here is the change that test exists to catch.
    /// The mac app was filling the same key with a bare count and so said
    /// "1 files"; it now has the same helper.
    /// </remarks>
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

            var stat = _stat(path);
            if (stat is null)
            {
                continue;
            }

            Sources.Add(new SourceRow(path, stat.Value.Size, stat.Value.Modified, stat.Value.IsFolder, recursive));
        }

        Raise(nameof(SourcesFooter));
    }

    private void RemoveSelected()
    {
        foreach (var row in Selected.ToList())
        {
            Sources.Remove(row);
        }

        Selected.Clear();
        RemoveCommand.Refresh();
        Raise(nameof(SourcesFooter));
    }

    private void RefreshSizes()
    {
        var paths = Sources.Select(s => s.Path).ToList();
        Sources.Clear();
        Add(paths);
    }

    // ---- source blocks ----

    public BlockMode BlockMode
    {
        get => _blockMode;
        set
        {
            if (Set(ref _blockMode, value))
            {
                RaiseAll(nameof(ByBlockSize), nameof(ByBlockCount));
                Recompute();
            }
        }
    }

    public bool ByBlockSize
    {
        get => _blockMode == BlockMode.Size;
        set { if (value) { BlockMode = BlockMode.Size; } }
    }

    public bool ByBlockCount
    {
        get => _blockMode == BlockMode.Count;
        set { if (value) { BlockMode = BlockMode.Count; } }
    }

    public long BlockSize
    {
        get => _blockSize;
        set { if (Set(ref _blockSize, Math.Max(4, value))) { Recompute(); } }
    }

    /// <summary>What the user typed in the block size field, unit suffix and all.</summary>
    public string BlockSizeText
    {
        get => Fmt.Bytes(_blockSize);
        set
        {
            if (Fmt.ParseSize(value) is { } parsed and > 0)
            {
                BlockSize = parsed;
            }

            Raise();
        }
    }

    public int BlockCount
    {
        get => _blockCount;
        set { if (Set(ref _blockCount, Math.Clamp(value, 1, 32768))) { Recompute(); } }
    }

    /// <summary>The quantity the user is NOT choosing, read out of the preview.</summary>
    public string DerivedBlockText => _preview.BlockCount == 0
        ? string.Empty
        : _blockMode == BlockMode.Count
            ? Fmt.Bytes(_preview.BlockSize)
            : Fmt.Count(_preview.BlockCount);

    public string PaddingText => _preview.BlockCount == 0
        ? string.Empty
        : $"{Fmt.Bytes(_preview.PaddingBytes)} ({Fmt.Pct(_preview.PaddingPct)})";

    public string EfficiencyText => _preview.BlockCount == 0 ? string.Empty : Fmt.Pct(_preview.EfficiencyPct);

    // ---- recovery ----

    public RecoveryMode RecoveryMode
    {
        get => _recoveryMode;
        set
        {
            if (Set(ref _recoveryMode, value))
            {
                RaiseAll(nameof(ByPercent), nameof(ByRecoveryCount), nameof(ByRecoverySize));
                Recompute();
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
        set { if (Set(ref _recoveryPercent, Math.Clamp(value, 0, 1000))) { Recompute(); } }
    }

    public int RecoveryCount
    {
        get => _recoveryCount;
        set { if (Set(ref _recoveryCount, Math.Clamp(value, 0, 65535))) { Recompute(); } }
    }

    public long RecoverySize
    {
        get => _recoverySize;
        set { if (Set(ref _recoverySize, Math.Max(0, value))) { Recompute(); } }
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

    /// <summary>The two recovery quantities the user is not choosing.</summary>
    public string DerivedRecoveryText => _preview.BlockCount == 0
        ? string.Empty
        : _recoveryMode switch
        {
            RecoveryMode.Percent =>
                $"{Fmt.Count(_preview.RecoveryBlocks)} blocks, {Fmt.Bytes(_preview.RecoveryBytes)}",
            RecoveryMode.Count =>
                $"{Fmt.Pct(_preview.RecoveryPercent, 1)}, {Fmt.Bytes(_preview.RecoveryBytes)}",
            _ => $"{Fmt.Count(_preview.RecoveryBlocks)} blocks, {Fmt.Pct(_preview.RecoveryPercent, 1)}",
        };

    /// <summary>The recovery quick chips of plan section 5.3.</summary>
    /// <remarks>
    /// 30 ADDED AND 15 DROPPED, 12 SEP 2026. The set stopped at 20, which read as
    /// a ceiling and is not one: <see cref="RecoveryPercent"/> clamps to 0-1000
    /// and the mac app does not clamp at all, so 30 percent has always been
    /// reachable by typing it. What was missing was the one click - and this
    /// project's own parfast round book publishes 25 and 30 percent parity rows,
    /// so those are working levels here rather than exotic ones.
    /// <para>
    /// FOUR CHIPS, AND THE COUNT IS LOAD-BEARING - it is what the mac's row
    /// fits. A six-chip set came back from that app's screenshot harness with
    /// the middle labels ellipsised, "5% 10... 15... 2... 25% 30%"; four render
    /// in full. The two apps keep the same set, so the narrower row sets it, and
    /// a fifth needs a SCREENSHOT rather than a green test.
    /// </para>
    /// <para>
    /// THIS LIST IS DUPLICATED. The mac app spells the same numbers inline in
    /// CreateView.swift's ForEach, so the two can drift and this change had to be
    /// made twice. It belongs in the shared table with the rest of what both apps
    /// agree on; it is not there because the shared files carry copy and design
    /// tokens, and a list of numbers that is neither has no home yet. If a third
    /// thing needs one, make the home rather than adding a third copy.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<double> PercentChips { get; } = [5, 10, 20, 30];

    public void ApplyChip(double percent)
    {
        RecoveryMode = RecoveryMode.Percent;
        RecoveryPercent = percent;
    }

    // ---- output ----

    public PathMode PathMode
    {
        get => _pathMode;
        set
        {
            if (Set(ref _pathMode, value))
            {
                Raise(nameof(ShowBasePath));
                Recompute();
            }
        }
    }

    public bool ShowBasePath => _pathMode == PathMode.Relative;

    public string? BasePath
    {
        get => _basePath;
        set { if (Set(ref _basePath, value)) { Recompute(); } }
    }

    public string Output
    {
        get => _output;
        set { if (Set(ref _output, value)) { Recompute(); } }
    }

    public VolumeScheme Scheme
    {
        get => _scheme;
        set
        {
            if (Set(ref _scheme, value))
            {
                RaiseAll(nameof(ShowUniform), nameof(ShowPow2Limit));
                Recompute();
            }
        }
    }

    public bool ShowUniform => _scheme == VolumeScheme.Uniform;

    public bool ShowPow2Limit => _scheme == VolumeScheme.Pow2Limit;

    /// <summary>files, per_file or file_size: which of the three uniform fields is live.</summary>
    public string UniformArm
    {
        get => _uniformArm;
        set { if (Set(ref _uniformArm, value)) { Recompute(); } }
    }

    public int UniformFiles
    {
        get => _uniformFiles;
        set { if (Set(ref _uniformFiles, Math.Clamp(value, 1, 32768))) { Recompute(); } }
    }

    public int UniformBlocksPerFile
    {
        get => _uniformBlocksPerFile;
        set { if (Set(ref _uniformBlocksPerFile, Math.Max(1, value))) { Recompute(); } }
    }

    public long UniformFileSize
    {
        get => _uniformFileSize;
        set { if (Set(ref _uniformFileSize, Math.Max(1, value))) { Recompute(); } }
    }

    /// <summary>largest, blocks or size: which pow2 limit is live.</summary>
    public string Pow2LimitArm
    {
        get => _pow2LimitArm;
        set
        {
            // A capability the core says it lacks cannot be selected, even
            // programmatically: Settings restoring a saved "blocks" limit against
            // an engine that has since lost the capability would otherwise put the
            // form in a state the preview cannot honour.
            var wanted = ShowExplicitVolumeLimit ? value : "largest";
            if (Set(ref _pow2LimitArm, wanted))
            {
                Recompute();
            }
        }
    }

    public int Pow2LimitBlocks
    {
        get => _pow2LimitBlocks;
        set { if (Set(ref _pow2LimitBlocks, Math.Max(1, value))) { Recompute(); } }
    }

    public long Pow2LimitSize
    {
        get => _pow2LimitSize;
        set { if (Set(ref _pow2LimitSize, Math.Max(1, value))) { Recompute(); } }
    }

    public int FirstRecoveryBlock
    {
        get => _firstRecoveryBlock;
        set { if (Set(ref _firstRecoveryBlock, Math.Max(0, value))) { Recompute(); } }
    }

    public string Comment
    {
        get => _comment;
        set => Set(ref _comment, value);
    }

    public bool Overwrite
    {
        get => _overwrite;
        set => Set(ref _overwrite, value);
    }

    public bool StdNaming
    {
        get => _stdNaming;
        set { if (Set(ref _stdNaming, value)) { Recompute(); } }
    }

    public UnicodePolicy Unicode
    {
        get => _unicode;
        set => Set(ref _unicode, value);
    }

    public bool ShowStdNaming => _core.Capabilities.StdNaming;

    public bool ShowUnicodePolicy => _core.Capabilities.UnicodePolicy;

    /// <summary>
    /// The engine writes no PAR2 comment packet today, so the field is hidden
    /// rather than shown and ignored (crates/parfast-ffi/API.md).
    /// </summary>
    public bool ShowComment => _core.Capabilities.Comment;

    /// <summary>
    /// Whether a pow2 volume ceiling can be given as a block count or a size. It
    /// cannot today: a create runs through the reference's dialect, which has
    /// exactly ONE ceiling, so "largest source file" is the only real limit and
    /// the other two arms are hidden. Offering them would let a user set a number
    /// the run silently ignores.
    /// </summary>
    public bool ShowExplicitVolumeLimit => _core.Capabilities.VolumeLimitExplicit;

    // ---- preview ----

    public PlanPreview Preview => _preview;

    /// <summary>
    /// What the set will cost on disk, as the proportion bar of the preview card.
    /// </summary>
    /// <remarks>
    /// Rebuilt inside <see cref="Recompute"/>, which every edit on this screen runs
    /// through, so the bar moves with the recovery slider. Mutated in place like the
    /// verify page's map model, so the view must call the control's Refresh after
    /// assigning it - see CostBar's own remarks for why assigning alone raises
    /// nothing.
    /// </remarks>
    public CostBarModel Cost { get; } = new();

    public Rows<PlannedFile> PreviewFiles { get; } = [];

    public Rows<string> Warnings { get; } = [];

    public string PreviewTotalText => _preview.Files.Count == 0
        ? string.Empty
        : $"{Fmt.Count(_preview.Files.Count)} files, {Fmt.Bytes(_preview.TotalBytes)}";

    public string CommandText => _preview.Command;

    public bool HasSources => Sources.Count > 0;

    public CreateSpec ToSpec() => new()
    {
        Sources = Sources.Select(s => new SourceSpec
        {
            Path = s.Path,
            Recursive = s.IsFolder ? s.Recursive : null,
        }).ToList(),
        PathMode = _pathMode,
        BasePath = _pathMode == PathMode.Relative ? _basePath : null,
        Block = _blockMode == BlockMode.Size ? BlockSpec.BySize(_blockSize) : BlockSpec.ByCount(_blockCount),
        Recovery = _recoveryMode switch
        {
            RecoveryMode.Percent => RecoverySpec.ByPercent(_recoveryPercent),
            RecoveryMode.Count => RecoverySpec.ByCount(_recoveryCount),
            _ => RecoverySpec.BySize(_recoverySize),
        },
        Output = _output,
        Volumes = ToVolumeSpec(),
        FirstRecoveryBlock = _firstRecoveryBlock,
        Comment = _comment,
        Overwrite = _overwrite,
        StdNaming = _stdNaming && ShowStdNaming,
        Unicode = ShowUnicodePolicy ? _unicode : UnicodePolicy.Auto,
    };

    private VolumeSpec ToVolumeSpec() => _scheme switch
    {
        VolumeScheme.None => VolumeSpec.None(),
        VolumeScheme.Pow2 => VolumeSpec.Pow2(),
        VolumeScheme.Uniform => _uniformArm switch
        {
            "per_file" => VolumeSpec.UniformBlocksPerFile(_uniformBlocksPerFile),
            "file_size" => VolumeSpec.UniformFileSize(_uniformFileSize),
            _ => VolumeSpec.UniformFiles(_uniformFiles),
        },
        _ => _pow2LimitArm switch
        {
            "blocks" => VolumeSpec.Pow2LimitBlocks(_pow2LimitBlocks),
            "size" => VolumeSpec.Pow2LimitSize(_pow2LimitSize),
            _ => VolumeSpec.Pow2LargestSource(),
        },
    };

    public void Recompute()
    {
        _preview = Sources.Count == 0 ? PlanPreview.Empty : _core.PlanPreview(ToSpec());
        PreviewFiles.Reset(_preview.Files);
        Warnings.Reset(_preview.Warnings);
        Cost.Update(_preview);
        RaiseAll(nameof(Preview), nameof(DerivedBlockText), nameof(PaddingText), nameof(EfficiencyText),
            nameof(DerivedRecoveryText), nameof(PreviewTotalText), nameof(CommandText), nameof(SourcesFooter),
            nameof(HasSources), nameof(BlockSizeText), nameof(RecoverySizeText), nameof(Cost));
        CreateCommand.Refresh();
        AddToQueueCommand.Refresh();
        RemoveCommand.Refresh();
        RefreshCommand.Refresh();
    }

    /// <summary>
    /// Submits the job and returns its id. Both Create and Add to queue call
    /// this: everything goes through the queue (plan section 5.3), so the Queue
    /// tab always shows the truth and the only difference is whether the
    /// progress sheet is shown.
    /// </summary>
    public long Start()
    {
        _jobId = _core.Submit(JobSpec.ForCreate(ToSpec()));
        Raise(nameof(JobId));
        return _jobId;
    }

    /// <summary>
    /// Fills the base folder and the output name from the sources, the first
    /// time. Both stay editable: this is a starting point, not a policy, and
    /// overwriting a name the user typed would be the worse bug.
    /// </summary>
    private void AutoBaseAndOutput()
    {
        if (Sources.Count == 0)
        {
            return;
        }

        var parent = CommonParent(Sources.Select(s => s.Path).ToList());
        if (string.IsNullOrEmpty(_basePath) && parent is not null)
        {
            _basePath = parent;
            Raise(nameof(BasePath));
        }

        if (!string.IsNullOrEmpty(_output) || parent is null)
        {
            return;
        }

        // The set name: the common stem of the sources when there is one (so
        // "x.part1.rar", "x.part2.rar" becomes "x.par2"), else the folder's name.
        var stem = CommonStem(Sources.Select(s => s.Name).ToList());
        var name = string.IsNullOrEmpty(stem) ? PathUtil.FileName(parent) : stem;
        _output = PathUtil.Combine(parent, $"{name}.par2");
        Raise(nameof(Output));
    }

    public static string? CommonParent(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
        {
            return null;
        }

        var dirs = paths.Select(p => PathUtil.DirectoryName(p)).Where(d => d.Length > 0).ToList();
        if (dirs.Count == 0)
        {
            return null;
        }

        var separator = dirs[0].Contains('\\', StringComparison.Ordinal) ? '\\' : '/';
        var parts = PathUtil.Split(dirs[0]);
        var take = parts.Length;
        foreach (var dir in dirs.Skip(1))
        {
            var other = PathUtil.Split(dir);
            var i = 0;
            while (i < take && i < other.Length
                   && string.Equals(parts[i], other[i], StringComparison.OrdinalIgnoreCase))
            {
                i++;
            }

            take = i;
        }

        if (take == 0)
        {
            return null;
        }

        var joined = string.Join(separator, parts.Take(take));
        // A drive-rooted Windows path keeps its root ("C:\\a"), and a
        // slash-rooted one keeps its leading slash, which Split dropped.
        return separator == '/' && dirs[0].StartsWith('/') ? "/" + joined : joined;
    }

    /// <summary>
    /// The longest leading run shared by every name, trimmed back to a
    /// separator so a set of "x.part1.rar" and "x.part2.rar" yields "x" and not
    /// "x.part".
    /// </summary>
    public static string CommonStem(IReadOnlyList<string> names)
    {
        if (names.Count == 0)
        {
            return string.Empty;
        }

        if (names.Count == 1)
        {
            return PathUtil.FileNameWithoutExtension(names[0]);
        }

        var shortest = names.Min(n => n.Length);
        var common = 0;
        while (common < shortest && names.All(n => char.ToLowerInvariant(n[common])
                                                  == char.ToLowerInvariant(names[0][common])))
        {
            common++;
        }

        var prefix = names[0][..common];
        var cut = prefix.LastIndexOfAny(['.', '-', '_', ' ']);
        return cut > 0 ? prefix[..cut] : prefix;
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
            // A path the user dropped that cannot be read is skipped rather than
            // throwing into a drop handler. The row simply does not appear, which
            // is what the user sees when they drop something they cannot read.
            return null;
        }
    }
}
