using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

// The pf_job_submit payload of plan section 4.5. Serialised with
// ParfastJson.Options, which writes snake_case and drops nulls, so an
// unset optional field never reaches the core as an explicit null.
//
// Every "one of" in the contract (block by size OR count, recovery by
// percent OR count OR size, the volume schemes) is modelled as a record
// with nullable members and a factory per arm. That is deliberate: a C#
// discriminated union would need a converter each, and the UI needs to
// hold a half-filled state anyway while someone is typing in the other
// radio's field.

public sealed record JobSpec
{
    [JsonPropertyName("kind")] public JobKind Kind { get; init; }
    [JsonPropertyName("create")] public CreateSpec? Create { get; init; }
    [JsonPropertyName("verify")] public VerifySpec? Verify { get; init; }
    [JsonPropertyName("repair")] public RepairSpec? Repair { get; init; }
    [JsonPropertyName("checksum_create")] public ChecksumCreateSpec? ChecksumCreate { get; init; }
    [JsonPropertyName("checksum_verify")] public ChecksumVerifySpec? ChecksumVerify { get; init; }
    [JsonPropertyName("posting_set")] public PostingSetSpec? PostingSet { get; init; }

    public static JobSpec ForCreate(CreateSpec s) => new() { Kind = JobKind.Create, Create = s };
    public static JobSpec ForVerify(VerifySpec s) => new() { Kind = JobKind.Verify, Verify = s };
    public static JobSpec ForRepair(RepairSpec s) => new() { Kind = JobKind.Repair, Repair = s };
    public static JobSpec ForChecksumCreate(ChecksumCreateSpec s) =>
        new() { Kind = JobKind.ChecksumCreate, ChecksumCreate = s };
    public static JobSpec ForChecksumVerify(ChecksumVerifySpec s) =>
        new() { Kind = JobKind.ChecksumVerify, ChecksumVerify = s };
    public static JobSpec ForPostingSet(PostingSetSpec s) =>
        new() { Kind = JobKind.PostingSet, PostingSet = s };

    /// <summary>The set or output name a progress title uses, without a path.</summary>
    public string DisplayName()
    {
        var path = Kind switch
        {
            JobKind.Create => Create?.Output,
            JobKind.Verify => Verify?.Par2,
            JobKind.Repair => Repair?.Par2,
            JobKind.ChecksumCreate => ChecksumCreate?.Output,
            JobKind.ChecksumVerify => ChecksumVerify?.File,
            // A posting set's name is already one path component, not a path.
            JobKind.PostingSet => PostingSet?.Name,
            _ => null,
        };
        return string.IsNullOrEmpty(path) ? string.Empty : PathUtil.FileName(path);
    }
}

public sealed record SourceSpec
{
    [JsonPropertyName("path")] public string Path { get; init; } = string.Empty;
    [JsonPropertyName("recursive")] public bool? Recursive { get; init; }
}

public sealed record BlockSpec
{
    [JsonPropertyName("size")] public long? Size { get; init; }
    [JsonPropertyName("count")] public int? Count { get; init; }

    public static BlockSpec BySize(long bytes) => new() { Size = bytes };
    public static BlockSpec ByCount(int count) => new() { Count = count };
}

public sealed record RecoverySpec
{
    [JsonPropertyName("percent")] public double? Percent { get; init; }
    [JsonPropertyName("count")] public int? Count { get; init; }
    [JsonPropertyName("size")] public long? Size { get; init; }

    public static RecoverySpec ByPercent(double pct) => new() { Percent = pct };
    public static RecoverySpec ByCount(int count) => new() { Count = count };
    public static RecoverySpec BySize(long bytes) => new() { Size = bytes };
}

/// <summary>
/// The limit of the pow2_limit scheme, which the contract spells either as
/// the bare string "largest_source" or as an object with one of two keys.
/// </summary>
public sealed record VolumeLimit
{
    [JsonPropertyName("blocks")] public int? Blocks { get; init; }
    [JsonPropertyName("size")] public long? Size { get; init; }
}

public sealed record VolumeSpec
{
    [JsonPropertyName("scheme")] public VolumeScheme Scheme { get; init; }
    [JsonPropertyName("files")] public int? Files { get; init; }
    [JsonPropertyName("blocks_per_file")] public int? BlocksPerFile { get; init; }
    [JsonPropertyName("file_size")] public long? FileSize { get; init; }

    // The contract's "limit" is either the literal string
    // "largest_source" or an object. Two properties rather than one
    // object?, so the writer emits the right shape and neither arm needs a
    // custom converter.
    [JsonPropertyName("limit")] public object? Limit { get; init; }

    public static VolumeSpec None() => new() { Scheme = VolumeScheme.None };
    public static VolumeSpec Pow2() => new() { Scheme = VolumeScheme.Pow2 };
    public static VolumeSpec UniformFiles(int files) =>
        new() { Scheme = VolumeScheme.Uniform, Files = files };
    public static VolumeSpec UniformBlocksPerFile(int blocks) =>
        new() { Scheme = VolumeScheme.Uniform, BlocksPerFile = blocks };
    public static VolumeSpec UniformFileSize(long bytes) =>
        new() { Scheme = VolumeScheme.Uniform, FileSize = bytes };
    public static VolumeSpec Pow2LargestSource() =>
        new() { Scheme = VolumeScheme.Pow2Limit, Limit = "largest_source" };
    public static VolumeSpec Pow2LimitBlocks(int blocks) =>
        new() { Scheme = VolumeScheme.Pow2Limit, Limit = new VolumeLimit { Blocks = blocks } };
    public static VolumeSpec Pow2LimitSize(long bytes) =>
        new() { Scheme = VolumeScheme.Pow2Limit, Limit = new VolumeLimit { Size = bytes } };
}

public sealed record PerfSpec
{
    [JsonPropertyName("threads")] public int? Threads { get; init; }
    [JsonPropertyName("memory_mb")] public int? MemoryMb { get; init; }
    [JsonPropertyName("low_priority")] public bool LowPriority { get; init; }
}

public sealed record CreateSpec
{
    [JsonPropertyName("sources")] public IReadOnlyList<SourceSpec> Sources { get; init; } = [];
    [JsonPropertyName("path_mode")] public PathMode PathMode { get; init; } = PathMode.Basename;
    [JsonPropertyName("base_path")] public string? BasePath { get; init; }
    [JsonPropertyName("block")] public BlockSpec Block { get; init; } = BlockSpec.ByCount(2000);
    [JsonPropertyName("recovery")] public RecoverySpec Recovery { get; init; } = RecoverySpec.ByPercent(10.0);
    [JsonPropertyName("output")] public string Output { get; init; } = string.Empty;
    [JsonPropertyName("volumes")] public VolumeSpec Volumes { get; init; } = VolumeSpec.None();
    [JsonPropertyName("first_recovery_block")] public int FirstRecoveryBlock { get; init; }
    [JsonPropertyName("comment")] public string Comment { get; init; } = string.Empty;
    [JsonPropertyName("overwrite")] public bool Overwrite { get; init; }
    [JsonPropertyName("std_naming")] public bool StdNaming { get; init; }
    [JsonPropertyName("unicode")] public UnicodePolicy Unicode { get; init; } = UnicodePolicy.Auto;
    [JsonPropertyName("perf")] public PerfSpec? Perf { get; init; }
}

public sealed record VerifyOptions
{
    [JsonPropertyName("rename_only")] public bool RenameOnly { get; init; }
    [JsonPropertyName("data_skipping")] public bool DataSkipping { get; init; }
    [JsonPropertyName("skip_leaway")] public int SkipLeaway { get; init; } = 64;
    [JsonPropertyName("fast_solver")] public bool? FastSolver { get; init; }
    [JsonPropertyName("threads")] public int? Threads { get; init; }
}

public sealed record VerifySpec
{
    [JsonPropertyName("par2")] public string Par2 { get; init; } = string.Empty;
    [JsonPropertyName("extra_dirs")] public IReadOnlyList<string> ExtraDirs { get; init; } = [];
    [JsonPropertyName("options")] public VerifyOptions Options { get; init; } = new();
}

public sealed record RepairSpec
{
    [JsonPropertyName("par2")] public string Par2 { get; init; } = string.Empty;
    [JsonPropertyName("extra_dirs")] public IReadOnlyList<string> ExtraDirs { get; init; } = [];
    [JsonPropertyName("options")] public VerifyOptions Options { get; init; } = new();
    [JsonPropertyName("purge")] public bool Purge { get; init; }
    [JsonPropertyName("keep_damaged")] public bool KeepDamaged { get; init; }

    public static RepairSpec From(VerifySpec v, bool purge, bool keepDamaged) => new()
    {
        Par2 = v.Par2,
        ExtraDirs = v.ExtraDirs,
        Options = v.Options,
        Purge = purge,
        KeepDamaged = keepDamaged,
    };
}

public sealed record ChecksumCreateSpec
{
    [JsonPropertyName("sources")] public IReadOnlyList<SourceSpec> Sources { get; init; } = [];
    [JsonPropertyName("format")] public ChecksumFormat Format { get; init; } = ChecksumFormat.Sfv;
    [JsonPropertyName("output")] public string Output { get; init; } = string.Empty;
    [JsonPropertyName("relative")] public bool Relative { get; init; } = true;
}

public sealed record ChecksumVerifySpec
{
    [JsonPropertyName("file")] public string File { get; init; } = string.Empty;
}

/// <summary>rar.volumes of a posting set: one archive, a volume FILE size, or about N volumes.</summary>
public sealed record RarVolumes
{
    [JsonPropertyName("split")] public RarSplit Split { get; init; }
    [JsonPropertyName("size")] public long? Size { get; init; }
    [JsonPropertyName("count")] public int? Count { get; init; }

    /// <summary>rar's -v floor. The core refuses a smaller volume with bad_spec.</summary>
    public const long MinSize = 64 * 1024;

    public static RarVolumes None() => new() { Split = RarSplit.None };
    public static RarVolumes BySize(long bytes) => new() { Split = RarSplit.Size, Size = bytes };
    public static RarVolumes ByCount(int count) => new() { Split = RarSplit.Count, Count = count };
}

/// <summary>The RAR half of a posting set (crates/parfast-ffi/API.md, posting_set).</summary>
/// <remarks>
/// THE PASSWORD IS A STRING ON THE WAY IN AND NEVER COMES BACK: the core
/// answers <c>{"withheld":true}</c> in every snapshot and in the persisted
/// queue. This record is the one place in the app that holds it, so its
/// generated ToString is overridden below. A record prints every property by
/// default, and a spec that reaches a log line, an exception message or a
/// debugger tooltip would otherwise carry the password with it.
/// </remarks>
public sealed record RarSpec
{
    [JsonPropertyName("volumes")] public RarVolumes Volumes { get; init; } = RarVolumes.None();

    /// <summary>0 stores (the posting default); 1 to 5 compress, fastest to smallest.</summary>
    [JsonPropertyName("compression")] public int Compression { get; init; }

    [JsonPropertyName("solid")] public bool Solid { get; init; }

    /// <summary>Null for no password. Never logged, never echoed back by the core.</summary>
    [JsonPropertyName("password")] public string? Password { get; init; }

    /// <summary>rar's -hp. Only read when there is a password; on by default.</summary>
    [JsonPropertyName("encrypt_headers")] public bool EncryptHeaders { get; init; } = true;

    [JsonPropertyName("recovery_percent")] public int RecoveryPercent { get; init; }

    /// <summary>
    /// Whether this archive can take the one-pass route: ONE archive, stored, no
    /// recovery record (API.md's route table). A prediction for the form only;
    /// result.posting.route is what actually happened.
    /// </summary>
    [JsonIgnore]
    public bool OnePassShaped =>
        Volumes.Split == RarSplit.None && Compression == 0 && RecoveryPercent == 0;

    private bool PrintMembers(System.Text.StringBuilder sb)
    {
        sb.Append($"Volumes = {Volumes}, Compression = {Compression}, Solid = {Solid}, ");
        sb.Append($"Password = {(Password is null ? "none" : "withheld")}, ");
        sb.Append($"EncryptHeaders = {EncryptHeaders}, RecoveryPercent = {RecoveryPercent}");
        return true;
    }
}

/// <summary>
/// The PAR2 half of a posting set. Every member left null takes the Settings
/// pane's Create default in the core, exactly as a fresh Create pane would.
/// </summary>
public sealed record PostingPar2Spec
{
    [JsonPropertyName("block")] public BlockSpec? Block { get; init; }
    [JsonPropertyName("recovery")] public RecoverySpec? Recovery { get; init; }
    [JsonPropertyName("volumes")] public VolumeSpec? Volumes { get; init; }
    [JsonPropertyName("first_recovery_block")] public int? FirstRecoveryBlock { get; init; }
    [JsonPropertyName("comment")] public string? Comment { get; init; }
    [JsonPropertyName("std_naming")] public bool? StdNaming { get; init; }
}

/// <summary>
/// A posting set: files in, a RAR 5 archive or volume set and a PAR2 set over it
/// out, as one job. Only <see cref="OutputDir"/> and <see cref="Name"/> are
/// required by the core.
/// </summary>
public sealed record PostingSetSpec
{
    [JsonPropertyName("sources")] public IReadOnlyList<SourceSpec> Sources { get; init; } = [];
    [JsonPropertyName("path_mode")] public PathMode PathMode { get; init; } = PathMode.Basename;
    [JsonPropertyName("base_path")] public string? BasePath { get; init; }
    [JsonPropertyName("output_dir")] public string OutputDir { get; init; } = string.Empty;

    /// <summary>One path component: the set is &lt;name&gt;.rar or &lt;name&gt;.partN.rar plus &lt;name&gt;.par2.</summary>
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;

    [JsonPropertyName("rar")] public RarSpec Rar { get; init; } = new();
    [JsonPropertyName("par2")] public PostingPar2Spec? Par2 { get; init; }

    /// <summary>True removes every file of an earlier set under the same name first.</summary>
    [JsonPropertyName("overwrite")] public bool Overwrite { get; init; }

    [JsonPropertyName("perf")] public PerfSpec? Perf { get; init; }
}
