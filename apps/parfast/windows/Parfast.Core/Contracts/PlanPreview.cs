using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

// pf_plan_preview of plan section 4.5: what Create's preview table draws,
// plus the equivalent parfast command line for the Copy command button.

public sealed record PlannedFile
{
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("size")] public long Size { get; init; }
    [JsonPropertyName("blocks")] public int Blocks { get; init; }
    [JsonPropertyName("efficiency_pct")] public double EfficiencyPct { get; init; }
}

public sealed record PlanPreview
{
    [JsonPropertyName("block_size")] public long BlockSize { get; init; }
    [JsonPropertyName("block_count")] public int BlockCount { get; init; }
    [JsonPropertyName("padding_bytes")] public long PaddingBytes { get; init; }
    [JsonPropertyName("padding_pct")] public double PaddingPct { get; init; }
    [JsonPropertyName("efficiency_pct")] public double EfficiencyPct { get; init; }
    [JsonPropertyName("recovery_blocks")] public int RecoveryBlocks { get; init; }
    [JsonPropertyName("recovery_percent")] public double RecoveryPercent { get; init; }
    [JsonPropertyName("recovery_bytes")] public long RecoveryBytes { get; init; }
    [JsonPropertyName("total_bytes")] public long TotalBytes { get; init; }

    // Added by the core (crates/parfast-ffi/API.md): the padding percentage is
    // unreadable without the source figures it is a percentage OF.
    [JsonPropertyName("source_bytes")] public long SourceBytes { get; init; }
    [JsonPropertyName("source_files")] public int SourceFiles { get; init; }
    [JsonPropertyName("files")] public IReadOnlyList<PlannedFile> Files { get; init; } = [];
    [JsonPropertyName("command")] public string Command { get; init; } = string.Empty;
    [JsonPropertyName("warnings")] public IReadOnlyList<string> Warnings { get; init; } = [];

    public static PlanPreview Empty { get; } = new();
}

/// <summary>
/// pf_capabilities. A UI hides any control whose capability is false, which
/// is how both app lanes stay correct whatever the engine turns out to
/// expose (plan section 4.5, last paragraph).
/// </summary>
public sealed record Capabilities
{
    [JsonPropertyName("version")] public string Version { get; init; } = string.Empty;
    [JsonPropertyName("engine")] public string Engine { get; init; } = string.Empty;
    [JsonPropertyName("cpu")] public string Cpu { get; init; } = string.Empty;
    [JsonPropertyName("kernel")] public string Kernel { get; init; } = string.Empty;
    [JsonPropertyName("std_naming")] public bool StdNaming { get; init; }
    [JsonPropertyName("unicode_policy")] public bool UnicodePolicy { get; init; }
    [JsonPropertyName("data_skipping")] public bool DataSkipping { get; init; }
    [JsonPropertyName("fast_solver")] public bool FastSolver { get; init; }
    [JsonPropertyName("pause")] public bool Pause { get; init; }
    [JsonPropertyName("low_priority")] public bool LowPriority { get; init; }

    // Added by the core (crates/parfast-ffi/API.md). Every one of them was false
    // against the engine of the day they were written and every one of them is
    // TRUE against a shipped engine now - all five flipped on 12 Sep 2026. They
    // are not decoration: each gates a control, so a stale reading here either
    // shows a switch that does nothing or hides one that works. What each says
    // when it is FALSE is written out below, because that is the arm a reader
    // can no longer see happen.

    /// <summary>
    /// The engine carries a PAR2 comment packet. False: it writes none, so the
    /// Comment field is hidden. True since 12 Sep 2026.
    /// </summary>
    [JsonPropertyName("comment")] public bool Comment { get; init; }

    /// <summary>
    /// A pow2 volume ceiling can be given explicitly. False: a create runs through
    /// the reference's dialect, which has exactly one ceiling, so only
    /// "largest_source" is real and a blocks or size limit would be ignored.
    /// True since 12 Sep 2026 - all three ceilings are carried.
    /// </summary>
    [JsonPropertyName("volume_limit_explicit")] public bool VolumeLimitExplicit { get; init; }

    /// <summary>
    /// Pause reaches inside the fold. False: a create pauses only before it starts.
    /// True since 12 Sep 2026, for a repair and a create alike, with one stated
    /// exception each - the repair's solve and a create's transform.
    /// </summary>
    [JsonPropertyName("pause_in_fold")] public bool PauseInFold { get; init; }

    /// <summary>
    /// Cancel reaches inside the fold. False: it is honoured between members.
    /// True since 12 Sep 2026, with no exception, and a cancelled CREATE leaves
    /// nothing on disk - the engine unlinks the index and every volume it wrote.
    /// </summary>
    [JsonPropertyName("cancel_in_fold")] public bool CancelInFold { get; init; }

    /// <summary>
    /// Progress is reported from inside the fold. False: the bar stops and the
    /// phase text speaks. True since 12 Sep 2026, so the bar keeps a real number
    /// through every phase of a repair and a create.
    /// </summary>
    [JsonPropertyName("progress_in_fold")] public bool ProgressInFold { get; init; }

    // Every capability false is the honest default for a session whose
    // pf_capabilities call failed: the UI then shows only controls it knows
    // the core supports, rather than offering a switch that does nothing.
    public static Capabilities Unknown { get; } = new();
}
