using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

/// <summary>
/// pf_settings_get / pf_settings_set.
/// </summary>
/// <remarks>
/// THE SHAPE IS GROUPED, AND A FLAT OBJECT IS REFUSED. Five groups plus three
/// top-level scalars, printed in full in <c>crates/parfast-ffi/API.md</c>.
/// <para>
/// This lane guessed FLAT and was wrong, and the way it failed is why the shape is
/// now printed rather than described: a flat <c>{"notifications": false,
/// "concurrency": 3}</c> had the concurrency land (it really is top-level) and the
/// notification silently ignored (it belongs to <c>general</c>), with
/// <c>PF_OK</c> returned. Half a write vanishing under a success code is
/// indistinguishable from the core dropping a field it was given, and a host
/// cannot tell at all. The core refuses a misplaced key outright now, naming the
/// group.
/// </para>
/// <para>
/// EVERY KEY IS OPTIONAL ON THE WAY IN, so a partial object is fine and anything
/// left out keeps its default. THE DEFAULTS BELONG TO THE CORE: a fresh session's
/// <c>pf_settings_get</c> is the defaults, which is why the initialisers here are
/// only what this type reads as before any core has answered.
/// </para>
/// </remarks>
public sealed record ParfastSettings
{
    [JsonPropertyName("general")] public GeneralSettings General { get; init; } = new();
    [JsonPropertyName("create")] public CreateSettings Create { get; init; } = new();
    [JsonPropertyName("performance")] public PerformanceSettings Performance { get; init; } = new();
    [JsonPropertyName("integration")] public IntegrationSettings Integration { get; init; } = new();
    [JsonPropertyName("advanced")] public AdvancedSettings Advanced { get; init; } = new();

    // The three top-level scalars.
    [JsonPropertyName("concurrency")] public int Concurrency { get; init; } = 1;
    [JsonPropertyName("post_queue_action")] public PostQueueAction PostQueueAction { get; init; }
    [JsonPropertyName("log_tail_lines")] public int LogTailLines { get; init; } = 500;

    /// <summary>
    /// Whether opening a PAR2 file should repair it as well as verify it.
    /// </summary>
    /// <remarks>
    /// Derived from <see cref="GeneralSettings.OpenPar2"/>, which API.md names as
    /// canonical, and MUST NOT be serialised: there is no <c>on_open</c> and no
    /// <c>auto_repair_on_open</c> in the contract, and an unattributed property
    /// here would invent one from a derived value. API.md says so explicitly
    /// because this lane did exactly that.
    /// </remarks>
    [JsonIgnore]
    public bool AutoRepairOnOpen => General.OpenPar2 == "verify_repair";
}

public sealed record GeneralSettings
{
    /// <summary>"verify" or "verify_repair". The canonical key for plan 5.6.</summary>
    [JsonPropertyName("open_par2")] public string OpenPar2 { get; init; } = "verify";

    [JsonPropertyName("purge_after_repair")] public bool PurgeAfterRepair { get; init; }
    [JsonPropertyName("keep_damaged_copies")] public bool KeepDamagedCopies { get; init; } = true;
    [JsonPropertyName("notifications")] public bool Notifications { get; init; } = true;
    [JsonPropertyName("auto_close_progress")] public bool AutoCloseProgress { get; init; }
    [JsonPropertyName("language")] public string Language { get; init; } = "en";
}

public sealed record CreateSettings
{
    [JsonPropertyName("block_allocation")] public string BlockAllocation { get; init; } = "count";
    [JsonPropertyName("block_count")] public int BlockCount { get; init; } = 2000;
    [JsonPropertyName("block_size")] public long BlockSize { get; init; }
    [JsonPropertyName("recovery_allocation")] public string RecoveryAllocation { get; init; } = "percent";
    [JsonPropertyName("recovery_percent")] public double RecoveryPercent { get; init; } = 5.0;
    [JsonPropertyName("recovery_count")] public int RecoveryCount { get; init; }
    [JsonPropertyName("recovery_size")] public long RecoverySize { get; init; }
    [JsonPropertyName("scheme")] public VolumeScheme Scheme { get; init; } = VolumeScheme.Pow2;
    [JsonPropertyName("std_naming")] public bool StdNaming { get; init; }
    [JsonPropertyName("unicode")] public UnicodePolicy Unicode { get; init; } = UnicodePolicy.Auto;
    [JsonPropertyName("overwrite")] public bool Overwrite { get; init; }
}

public sealed record PerformanceSettings
{
    [JsonPropertyName("threads")] public int? Threads { get; init; }
    [JsonPropertyName("memory_mb")] public int? MemoryMb { get; init; }
    [JsonPropertyName("fast_solver")] public bool FastSolver { get; init; }
    [JsonPropertyName("low_priority")] public bool LowPriority { get; init; }
}

public sealed record IntegrationSettings
{
    [JsonPropertyName("handle_par2")] public bool HandlePar2 { get; init; } = true;
    [JsonPropertyName("handle_sfv")] public bool HandleSfv { get; init; }
    [JsonPropertyName("handle_md5")] public bool HandleMd5 { get; init; }
    [JsonPropertyName("handle_sha256")] public bool HandleSha256 { get; init; }
    [JsonPropertyName("shell_menu")] public bool ShellMenu { get; init; } = true;
}

public sealed record AdvancedSettings
{
    [JsonPropertyName("show_command")] public bool ShowCommand { get; init; } = true;

    /// <summary>An integer, not a word: 0 is the default level.</summary>
    [JsonPropertyName("log_level")] public int LogLevel { get; init; }

    [JsonPropertyName("log_folder")] public string? LogFolder { get; init; }
}
