using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

// pf_job_snapshot / pf_queue_snapshot of plan section 4.5. These are read
// models: every member is init-only and the UI rebinds rather than mutates,
// which is what makes the 10 Hz poll safe to hand straight to the view
// models from a background thread.

public sealed record JobSnapshot
{
    [JsonPropertyName("id")] public long Id { get; init; }
    [JsonPropertyName("kind")] public JobKind Kind { get; init; }
    [JsonPropertyName("state")] public JobState State { get; init; }
    [JsonPropertyName("phase")] public JobPhase Phase { get; init; }
    [JsonPropertyName("phase_text")] public string PhaseText { get; init; } = string.Empty;
    [JsonPropertyName("progress")] public double Progress { get; init; }
    [JsonPropertyName("elapsed_ms")] public long ElapsedMs { get; init; }
    [JsonPropertyName("eta_ms")] public long? EtaMs { get; init; }
    [JsonPropertyName("rate_bytes_per_s")] public long RateBytesPerS { get; init; }
    [JsonPropertyName("low_priority")] public bool LowPriority { get; init; }
    [JsonPropertyName("added_at")] public DateTimeOffset? AddedAt { get; init; }
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("log_tail")] public IReadOnlyList<string> LogTail { get; init; } = [];

    /// <summary>
    /// The parfast command line equivalent to this job, from the core. Empty for
    /// the two checksum kinds, which have no CLI equivalent.
    /// </summary>
    /// <remarks>
    /// The core's line beats anything this app composes, and the log drawer
    /// prefers it: the CLI's dialect is the one thing a script user already knows,
    /// and a GUI whose "equivalent command" is its own guess is unreproducible
    /// from a terminal.
    /// </remarks>
    [JsonPropertyName("command")] public string Command { get; init; } = string.Empty;
    [JsonPropertyName("survey")] public Survey? Survey { get; init; }
    [JsonPropertyName("result")] public JobResult? Result { get; init; }
    [JsonPropertyName("error")] public JobError? Error { get; init; }

    public bool IsFinished =>
        State is JobState.Done or JobState.Failed or JobState.Cancelled or JobState.Interrupted;

    public bool IsActive => State is JobState.Running or JobState.Paused;
}

public sealed record JobError
{
    [JsonPropertyName("code")] public string Code { get; init; } = string.Empty;
    [JsonPropertyName("message")] public string Message { get; init; } = string.Empty;
}

public sealed record WrittenFile
{
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("size")] public long Size { get; init; }
}

public sealed record ChecksumResult
{
    [JsonPropertyName("ok")] public int Ok { get; init; }
    [JsonPropertyName("mismatch")] public int Mismatch { get; init; }
    [JsonPropertyName("missing")] public int Missing { get; init; }

    /// <summary>
    /// A row per checksum entry, in the file's own order. This is what plan 5.4's
    /// Name | Expected | Status table needs and the three counts cannot draw.
    /// </summary>
    /// <remarks>
    /// Requested by this lane and added by chip A at 7fdfcece16, NESTED INSIDE the
    /// checksum result rather than beside it: this lane had guessed
    /// <c>result.checksum_entries</c> at the result level, and it is
    /// <c>result.checksum.entries</c>. Empty until the core fills it, which the
    /// Checksums screen renders as a note rather than as an empty table.
    /// </remarks>
    [JsonPropertyName("entries")] public IReadOnlyList<ChecksumEntry> Entries { get; init; } = [];

    public int Total => Ok + Mismatch + Missing;
}

public sealed record ChecksumEntry
{
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("expected")] public string Expected { get; init; } = string.Empty;
    [JsonPropertyName("actual")] public string? Actual { get; init; }
    [JsonPropertyName("status")] public string Status { get; init; } = "pending";
}

public sealed record JobResult
{
    [JsonPropertyName("repaired_files")] public int RepairedFiles { get; init; }
    [JsonPropertyName("purged")] public bool Purged { get; init; }
    [JsonPropertyName("written")] public IReadOnlyList<WrittenFile> Written { get; init; } = [];
    [JsonPropertyName("checksum")] public ChecksumResult? Checksum { get; init; }

    /// <summary>The exit code the equivalent parfast line would have returned.</summary>
    [JsonPropertyName("exit_code")] public int? ExitCode { get; init; }
}

public sealed record SurveyFile
{
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("size")] public long Size { get; init; }
    [JsonPropertyName("status")] public FileStatus Status { get; init; }
    [JsonPropertyName("blocks_ok")] public int BlocksOk { get; init; }
    [JsonPropertyName("blocks_total")] public int BlocksTotal { get; init; }
    [JsonPropertyName("found_as")] public string? FoundAs { get; init; }
    [JsonPropertyName("progress")] public double Progress { get; init; }

    public bool NeedsAttention =>
        Status is FileStatus.Damaged or FileStatus.Missing or FileStatus.Misnamed or FileStatus.Extra;
}

public sealed record Survey
{
    [JsonPropertyName("set_name")] public string SetName { get; init; } = string.Empty;
    [JsonPropertyName("folder")] public string Folder { get; init; } = string.Empty;
    [JsonPropertyName("block_size")] public long BlockSize { get; init; }
    [JsonPropertyName("source_blocks")] public int SourceBlocks { get; init; }
    [JsonPropertyName("recovery_available")] public int RecoveryAvailable { get; init; }
    [JsonPropertyName("recovery_needed")] public int RecoveryNeeded { get; init; }
    [JsonPropertyName("verdict")] public Verdict Verdict { get; init; }
    [JsonPropertyName("files")] public IReadOnlyList<SurveyFile> Files { get; init; } = [];

    /// <summary>
    /// Run-length encoded block states over source blocks in set order:
    /// each inner array is [state, count] with the state codes of
    /// <see cref="BlockState"/>. The block map draws this and nothing else.
    /// </summary>
    [JsonPropertyName("block_runs")] public IReadOnlyList<int[]> BlockRuns { get; init; } = [];
}

public sealed record QueueSnapshot
{
    [JsonPropertyName("paused")] public bool Paused { get; init; }
    [JsonPropertyName("concurrency")] public int Concurrency { get; init; } = 1;
    [JsonPropertyName("post_action")] public PostQueueAction PostAction { get; init; }

    /// <summary>
    /// The queue has drained and the post action has not been carried out.
    /// </summary>
    /// <remarks>
    /// THE SESSION REPORTS IT, THE HOST PERFORMS IT. Sleeping or shutting down a
    /// machine is a platform call, and it is a decision a human has to be able to
    /// stop, so the core will not do it. The host acts and then calls
    /// pf_queue_clear_post_action; it does not fall due again until a new job is
    /// submitted.
    /// </remarks>
    [JsonPropertyName("post_action_due")] public bool PostActionDue { get; init; }

    [JsonPropertyName("jobs")] public IReadOnlyList<JobSnapshot> Jobs { get; init; } = [];

    public static QueueSnapshot Empty { get; } = new();

    public int RunningCount => Jobs.Count(j => j.State == JobState.Running);
    public int WaitingCount => Jobs.Count(j => j.State is JobState.Queued or JobState.Paused);
}
