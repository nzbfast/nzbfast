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

    public static JobSpec ForCreate(CreateSpec s) => new() { Kind = JobKind.Create, Create = s };
    public static JobSpec ForVerify(VerifySpec s) => new() { Kind = JobKind.Verify, Verify = s };
    public static JobSpec ForRepair(RepairSpec s) => new() { Kind = JobKind.Repair, Repair = s };
    public static JobSpec ForChecksumCreate(ChecksumCreateSpec s) =>
        new() { Kind = JobKind.ChecksumCreate, ChecksumCreate = s };
    public static JobSpec ForChecksumVerify(ChecksumVerifySpec s) =>
        new() { Kind = JobKind.ChecksumVerify, ChecksumVerify = s };

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
