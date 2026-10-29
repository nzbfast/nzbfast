using System.Text.Json;
using Parfast.Core.Contracts;

namespace Parfast.Core.Mock;

/// <summary>One recorded posting-set run: the spec it was given and the frames the core sent.</summary>
public sealed record PostingRecording(string Key, JobSpec Spec, IReadOnlyList<JobSnapshot> Snapshots)
{
    /// <summary>The set name the recording was made under, which a replay swaps for the user's.</summary>
    public string RecordedName => Spec.PostingSet?.Name ?? string.Empty;

    /// <summary>The output folder the recording was made in, rewritten to /abs/... by the recorder.</summary>
    public string RecordedOutputDir => Spec.PostingSet?.OutputDir ?? string.Empty;

    /// <summary>The recording's own clock at its last frame.</summary>
    public long DurationMs => Snapshots.Count == 0 ? 0 : Snapshots[^1].ElapsedMs;
}

/// <summary>
/// The posting set's recorded snapshots, read out of
/// <c>apps/parfast/shared/contract/posting-set-snapshots.json</c>.
/// </summary>
/// <remarks>
/// RECORDED, NOT SCRIPTED, unlike every other mock scenario. The frames are what
/// the parfast-session core sent on 25 Oct 2026 for one run of each route, so a
/// screen built against this mock cannot show a field, a phase sentence or a
/// result shape the contract does not carry. The mac app plays the same file.
/// </remarks>
public static class PostingRecordings
{
    public const string OnePassKey = "one_pass";
    public const string TwoPassKey = "two_pass_volumes";

    /// <summary>
    /// How much slower than the recording a replay runs at Speed 1. The recorded
    /// runs are one and a half seconds on a 32-core Mac, which is too quick to see
    /// a progress sheet in a demo; four times reads as a short real job.
    /// </summary>
    public const double ReplayStretch = 4.0;

    private static readonly Lazy<IReadOnlyDictionary<string, PostingRecording>> All = new(Load);

    public static PostingRecording OnePass => All.Value[OnePassKey];

    public static PostingRecording TwoPass => All.Value[TwoPassKey];

    /// <summary>
    /// The recording whose route this spec would take: one stored archive with no
    /// recovery record plays the one-pass run, anything else the two-pass one.
    /// </summary>
    public static PostingRecording For(PostingSetSpec? spec) =>
        (spec?.Rar ?? new RarSpec()).OnePassShaped ? OnePass : TwoPass;

    private static IReadOnlyDictionary<string, PostingRecording> Load()
    {
        var assembly = typeof(PostingRecordings).Assembly;
        using var stream = assembly.GetManifestResourceStream("Parfast.Core.Mock.posting-set-snapshots.json")
            ?? throw new InvalidOperationException(
                "posting-set-snapshots.json is not embedded in Parfast.Core; see Parfast.Core.csproj.");
        using var doc = JsonDocument.Parse(stream);
        var map = new Dictionary<string, PostingRecording>(StringComparer.Ordinal);
        foreach (var entry in doc.RootElement.EnumerateObject())
        {
            if (entry.Name.StartsWith('_'))
            {
                continue;
            }

            var spec = entry.Value.GetProperty("spec").Deserialize<JobSpec>(ParfastJson.Options) ?? new JobSpec();
            var frames = entry.Value.GetProperty("snapshots").Deserialize<List<JobSnapshot>>(ParfastJson.Options)
                ?? [];
            map[entry.Name] = new PostingRecording(entry.Name, spec, frames);
        }

        return map;
    }
}

/// <summary>
/// A posting-set job that plays back a <see cref="PostingRecording"/> on the
/// mock's clock. Every member is touched only under MockCore's lock.
/// </summary>
/// <remarks>
/// What the replay changes, and nothing else: the id, the added time, the state
/// (so pause and cancel work), and the recorded set name and folder, which are
/// swapped for the user's so the screen shows their files. Phases, sentences,
/// progress, sizes and the route are the core's.
/// <para>
/// THE PASSWORD NEVER REACHES A SNAPSHOT here either. The spec is held only to
/// pick the recording and the names; nothing of <see cref="RarSpec"/> is copied
/// into a frame, which is the same promise the core makes with its
/// <c>{"withheld":true}</c>.
/// </para>
/// </remarks>
internal sealed class MockPostingJob(long id, JobSpec spec, DateTimeOffset addedAt) : IMockJob
{
    private readonly PostingRecording _recording = PostingRecordings.For(spec.PostingSet);
    private readonly List<string> _extraLog = [];
    private double _clockMs;
    private int _frame;

    public JobState State { get; private set; } = JobState.Queued;

    public bool LowPriority { get; set; } = spec.PostingSet?.Perf?.LowPriority ?? false;

    public bool RunNext { get; set; }

    public bool PausedByQueue { get; private set; }

    public void Start()
    {
        if (State is not (JobState.Queued or JobState.Paused))
        {
            return;
        }

        State = JobState.Running;
        RunNext = false;
        PausedByQueue = false;
        if (_frame == 0 && _recording.Snapshots.Count > 1)
        {
            _frame = 1;
        }
    }

    public void Pause()
    {
        if (State == JobState.Running)
        {
            State = JobState.Paused;
            PausedByQueue = false;
        }
    }

    public void PauseForQueue()
    {
        if (State == JobState.Running)
        {
            State = JobState.Paused;
            PausedByQueue = true;
        }
    }

    public void Resume()
    {
        PausedByQueue = false;
        Start();
    }

    public void Cancel()
    {
        if (State is JobState.Done or JobState.Failed or JobState.Cancelled)
        {
            return;
        }

        // API.md: a cancelled posting set removes EVERY file it wrote, archive and
        // PAR2 alike, so there is nothing for a host to clean up.
        State = JobState.Cancelled;
        _extraLog.Add("Cancelled. Every file this posting set wrote was removed.");
    }

    public bool Advance(double ms)
    {
        if (State != JobState.Running)
        {
            return false;
        }

        _clockMs += ms;
        var frames = _recording.Snapshots;
        var before = _frame;
        while (_frame + 1 < frames.Count && frames[_frame + 1].ElapsedMs * PostingRecordings.ReplayStretch <= _clockMs)
        {
            _frame++;
        }

        if (_frame == frames.Count - 1 && frames[_frame].State is JobState.Done or JobState.Failed)
        {
            State = frames[_frame].State;
        }

        // A moved clock is a different elapsed_ms and so a different snapshot. A
        // zero step (a test's Speed 0 timer) changes nothing and must not wake.
        return ms > 0 || before != _frame;
    }

    public JobSnapshot ToSnapshot()
    {
        var frames = _recording.Snapshots;
        var frame = frames.Count == 0 ? new JobSnapshot() : frames[Math.Min(_frame, frames.Count - 1)];
        var log = frame.LogTail.Select(Rename).Concat(_extraLog).ToList();
        return frame with
        {
            Id = id,
            Kind = JobKind.PostingSet,
            State = State,
            AddedAt = addedAt,
            ElapsedMs = (long)_clockMs,
            LowPriority = LowPriority,
            Name = spec.PostingSet?.Name ?? frame.Name,
            Command = Rename(frame.Command),
            LogTail = log,
            Result = State == JobState.Done ? RenameResult(frame.Result) : null,
        };
    }

    private string Rename(string text)
    {
        if (string.IsNullOrEmpty(text) || spec.PostingSet is not { } ps)
        {
            return text;
        }

        var renamed = text;
        if (!string.IsNullOrEmpty(ps.OutputDir) && !string.IsNullOrEmpty(_recording.RecordedOutputDir))
        {
            renamed = renamed.Replace(_recording.RecordedOutputDir, ps.OutputDir, StringComparison.Ordinal);
        }

        if (!string.IsNullOrEmpty(ps.Name) && !string.IsNullOrEmpty(_recording.RecordedName))
        {
            renamed = renamed.Replace(_recording.RecordedName, ps.Name, StringComparison.Ordinal);
        }

        return renamed;
    }

    private JobResult? RenameResult(JobResult? result)
    {
        if (result is null)
        {
            return null;
        }

        List<WrittenFile> Files(IEnumerable<WrittenFile> files) =>
            files.Select(f => f with { Name = Rename(f.Name) }).ToList();

        return result with
        {
            Written = Files(result.Written),
            Posting = result.Posting is { } p
                ? p with { Rar = Files(p.Rar), Par2 = Files(p.Par2) }
                : null,
        };
    }
}
