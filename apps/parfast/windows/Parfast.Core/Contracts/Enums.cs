using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

// Every enum here mirrors a string in the JSON contract of
// research/PLAN-PARFAST-GUI-2026-09-12.md section 4.5. Chip A may ADD
// values and never rename one, so each enum carries an Unknown member
// mapped from anything this build does not recognise: a core that grows a
// new phase must not throw inside a UI poll at 10 Hz.
//
// SnakeCaseEnumConverter is what turns "checksum_create" into
// ChecksumCreate. It is declared per type rather than registered globally
// so a deserializer built anywhere in the app gets the same mapping, and
// its header says why it exists rather than the framework converter.

[JsonConverter(typeof(SnakeCaseEnumConverter<JobKind>))]
public enum JobKind
{
    Unknown = 0,
    Create,
    Verify,
    Repair,
    ChecksumCreate,
    ChecksumVerify,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<JobState>))]
public enum JobState
{
    Unknown = 0,
    Queued,
    Running,
    Paused,
    Done,
    Failed,
    Cancelled,
    // Not in the core's own list: section 5.5 asks the UI to show a job
    // that was running when the app quit as Interrupted. The core reports
    // it (a persisted queue entry with state running and no live worker)
    // and the session crate is expected to normalise it; until it does,
    // Parfast.ViewModels derives it. Kept here so both routes name it the
    // same thing.
    Interrupted,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<JobPhase>))]
public enum JobPhase
{
    Unknown = 0,
    Scanning,
    Hashing,
    Solving,
    Writing,
    Finishing,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<FileStatus>))]
public enum FileStatus
{
    Unknown = 0,
    Complete,
    Damaged,
    Missing,
    Misnamed,
    Extra,
    Hashing,
    Pending,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<Verdict>))]
public enum Verdict
{
    Unknown = 0,
    Verifying,
    Complete,
    Repairable,
    Unrepairable,
    Repaired,
    Failed,
}

// The state codes of Survey.BlockRuns, which is run-length encoded over
// source blocks in set order: [[state, count], ...]. The numbers are the
// wire values from section 4.5 and must not be reordered.
public enum BlockState
{
    Pending = 0,
    Present = 1,
    Damaged = 2,
    Missing = 3,
    Misnamed = 4,
    Hashing = 5,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<PathMode>))]
public enum PathMode
{
    Basename = 0,
    Relative,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<VolumeScheme>))]
public enum VolumeScheme
{
    None = 0,
    Uniform,
    Pow2,
    Pow2Limit,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<UnicodePolicy>))]
public enum UnicodePolicy
{
    Auto = 0,
    Never,
    Always,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<ChecksumFormat>))]
public enum ChecksumFormat
{
    Sfv = 0,
    Md5,
    Sha1,
    Sha256,
}

[JsonConverter(typeof(SnakeCaseEnumConverter<PostQueueAction>))]
public enum PostQueueAction
{
    None = 0,
    Notify,
    Sleep,
    Shutdown,
}
