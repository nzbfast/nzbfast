using Parfast.Core;
using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>One row of the checksum verify table.</summary>
public sealed class ChecksumRow(ChecksumEntry entry) : Observable
{
    public string Name => entry.Name;

    public string Expected => entry.Expected;

    public string StatusText => entry.Status switch
    {
        "ok" => Strings.ChecksumsStatusOk,
        "mismatch" => Strings.ChecksumsStatusMismatch,
        _ => Strings.ChecksumsStatusMissing,
    };

    public bool IsOk => entry.Status == "ok";

    public bool IsMismatch => entry.Status == "mismatch";

    public bool IsMissing => entry.Status is not "ok" and not "mismatch";
}

/// <summary>
/// Checksums (plan section 5.4): two sub-modes on a segmented control, create
/// and verify, over SFV, MD5, SHA-1 and SHA-256.
/// </summary>
/// <remarks>
/// It reuses <see cref="CreateViewModel.Sources"/>'s shape rather than the class
/// itself. The Create screen's sources carry block sizing and a base path, none
/// of which a checksum file has, and inheriting it would have put PAR2
/// vocabulary on a screen that has no blocks in it.
/// </remarks>
public sealed class ChecksumsViewModel : Observable
{
    private readonly ICoreClient _core;
    private readonly Func<string, (long Size, DateTimeOffset Modified, bool IsFolder)?> _stat;
    private bool _verifying;
    private ChecksumFormat _format = ChecksumFormat.Sfv;
    private string _output = string.Empty;
    private bool _relative = true;
    private string? _checksumFile;
    private JobSnapshot? _job;
    private long _jobId = -1;

    public ChecksumsViewModel(
        ICoreClient core,
        Func<string, (long Size, DateTimeOffset Modified, bool IsFolder)?>? stat = null)
    {
        _core = core;
        _stat = stat ?? (path =>
        {
            var file = new FileInfo(path);
            return file.Exists ? (file.Length, file.LastWriteTimeUtc, false)
                : Directory.Exists(path) ? (0L, Directory.GetLastWriteTimeUtc(path), true)
                : null;
        });
        CreateCommand = new Command(StartCreate, () => Sources.Count > 0 && !string.IsNullOrEmpty(_output));
        VerifyAgainCommand = new Command(StartVerify, () => _checksumFile is not null);
    }

    public Rows<SourceRow> Sources { get; } = [];

    public Rows<ChecksumRow> Rows { get; } = [];

    public Command CreateCommand { get; }

    public Command VerifyAgainCommand { get; }

    /// <summary>False is the Create sub-mode, true is Verify.</summary>
    public bool Verifying
    {
        get => _verifying;
        set
        {
            if (Set(ref _verifying, value))
            {
                RaiseAll(nameof(Creating), nameof(HasContent));
            }
        }
    }

    public bool Creating => !_verifying;

    public ChecksumFormat Format
    {
        get => _format;
        set
        {
            if (Set(ref _format, value))
            {
                RetargetOutput();
            }
        }
    }

    public string Output
    {
        get => _output;
        set
        {
            if (Set(ref _output, value))
            {
                CreateCommand.Refresh();
            }
        }
    }

    public bool Relative
    {
        get => _relative;
        set => Set(ref _relative, value);
    }

    public string? ChecksumFile => _checksumFile;

    public long JobId => _jobId;

    public bool HasContent => _verifying ? Rows.Count > 0 || Result is not null : Sources.Count > 0;

    /// <summary>
    /// True when a verify has finished with counts but the core gave no per-file
    /// rows, so the table would be empty and look like "no files were checked".
    /// </summary>
    /// <remarks>
    /// THE ENGINE DOES NOT CARRY THE LIST, as of 12 Sep 2026. Plan section 5.4
    /// asks for a Name | Expected | Status table; plan 4.5's snapshot carries only
    /// the three counts, and the landed ChecksumResult in parfast-session is those
    /// three and nothing else. It is recorded as an open contract gap in plan 4.5.
    /// <para>
    /// An empty table is the WRONG way to render that: it reads as a result - that
    /// nothing was checked - rather than as a missing capability. So the screen
    /// says which it is. The moment the core grows `result.checksum_entries` the
    /// rows appear and this note disappears, with no edit here.
    /// </para>
    /// </remarks>
    public bool ShowNoDetailNote => _verifying && Result is not null && Rows.Count == 0;

    public string NoDetailNote => Strings.ChecksumsNoDetail;

    public ChecksumResult? Result => _job?.Result?.Checksum;

    public bool IsBusy => _job?.IsActive == true;

    public double Progress => _job?.Progress ?? 0;

    public string SummaryText => Result is { } r
        ? Strings.Fill(Strings.ChecksumsResult, "ok", Fmt.Count(r.Ok), "mismatch", Fmt.Count(r.Mismatch), "missing", Fmt.Count(r.Missing))
        : string.Empty;

    public PillTone SummaryTone => Result is null
        ? PillTone.Neutral
        : Result.Mismatch + Result.Missing == 0 ? PillTone.Good
        : Result.Mismatch > 0 ? PillTone.Bad : PillTone.Warn;

    /// <summary>The pass fraction the simple bar draws instead of a block map.</summary>
    public double PassFraction => Result is { Total: > 0 } r ? (double)r.Ok / r.Total : 0;

    public void Add(IEnumerable<string> paths)
    {
        Verifying = false;
        foreach (var path in paths)
        {
            if (Sources.Any(s => string.Equals(s.Path, path, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (_stat(path) is { } stat)
            {
                Sources.Add(new SourceRow(path, stat.Size, stat.Modified, stat.IsFolder, true));
            }
        }

        RetargetOutput();
        RaiseAll(nameof(HasContent));
        CreateCommand.Refresh();
    }

    /// <summary>Opens a checksum file, which is what a .sfv drop does.</summary>
    public void Open(string path)
    {
        _checksumFile = path;
        Verifying = true;
        Format = FormatOf(path);
        Rows.Clear();
        StartVerify();
        Raise(nameof(ChecksumFile));
    }

    public void Apply(QueueSnapshot queue)
    {
        var job = queue.Jobs.FirstOrDefault(j => j.Id == _jobId);
        if (job is null)
        {
            return;
        }

        _job = job;
        if (job.Result?.Checksum?.Entries.Count > 0)
        {
            Rows.Reset(job.Result.Checksum.Entries.Select(e => new ChecksumRow(e)));
        }

        RaiseAll(nameof(Result), nameof(IsBusy), nameof(Progress), nameof(SummaryText), nameof(SummaryTone),
            nameof(PassFraction), nameof(HasContent), nameof(ShowNoDetailNote), nameof(NoDetailNote));
        VerifyAgainCommand.Refresh();
    }

    public static ChecksumFormat FormatOf(string path) => PathUtil.Extension(path).ToLowerInvariant() switch
    {
        ".md5" => ChecksumFormat.Md5,
        ".sha1" => ChecksumFormat.Sha1,
        ".sha256" => ChecksumFormat.Sha256,
        _ => ChecksumFormat.Sfv,
    };

    public static string ExtensionOf(ChecksumFormat format) => format switch
    {
        ChecksumFormat.Md5 => ".md5",
        ChecksumFormat.Sha1 => ".sha1",
        ChecksumFormat.Sha256 => ".sha256",
        _ => ".sfv",
    };

    private void StartCreate()
    {
        _jobId = _core.Submit(JobSpec.ForChecksumCreate(new ChecksumCreateSpec
        {
            Sources = Sources.Select(s => new SourceSpec { Path = s.Path, Recursive = s.IsFolder ? true : null })
                .ToList(),
            Format = _format,
            Output = _output,
            Relative = _relative,
        }));
        Raise(nameof(JobId));
    }

    private void StartVerify()
    {
        if (_checksumFile is null)
        {
            return;
        }

        _jobId = _core.Submit(JobSpec.ForChecksumVerify(new ChecksumVerifySpec { File = _checksumFile }));
        Raise(nameof(JobId));
    }

    /// <summary>
    /// Keeps the output name in step with the format and the sources, without
    /// overwriting a path the user typed: the check is whether the current value
    /// is one this method itself produced.
    /// </summary>
    private void RetargetOutput()
    {
        if (Sources.Count == 0)
        {
            return;
        }

        var parent = CreateViewModel.CommonParent(Sources.Select(s => s.Path).ToList());
        if (parent is null)
        {
            return;
        }

        var stem = CreateViewModel.CommonStem(Sources.Select(s => s.Name).ToList());
        if (string.IsNullOrEmpty(stem))
        {
            stem = PathUtil.FileName(parent);
        }

        var suggested = PathUtil.Combine(parent, stem + ExtensionOf(_format));
        var wasSuggested = string.IsNullOrEmpty(_output)
            || DropRouter.IsChecksumFile(_output)
               && string.Equals(
                   PathUtil.FileNameWithoutExtension(_output), stem, StringComparison.OrdinalIgnoreCase);

        if (wasSuggested)
        {
            Output = suggested;
        }
    }
}
