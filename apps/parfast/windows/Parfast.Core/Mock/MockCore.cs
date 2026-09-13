using System.Diagnostics;
using Parfast.Core.Contracts;

namespace Parfast.Core.Mock;

/// <summary>
/// An <see cref="ICoreClient"/> that plays the scripted scenarios of
/// <see cref="MockScenarios"/> with no engine, no FFI and no disk.
/// </summary>
/// <remarks>
/// It exists so the whole UI is built, demoed and unit-tested before the core
/// lands (plan section 3.3), and it stays in the tree afterwards as the UI
/// test harness. Two properties make it useful rather than decorative:
/// <list type="bullet">
/// <item>it obeys the same THREADING CONTRACT as the real core. Progress is
/// advanced by a timer thread, <see cref="Wake"/> fires from that thread, and
/// every snapshot is rebuilt under the same lock, so a screen that is
/// thread-correct against the mock is thread-correct against the FFI.</item>
/// <item><see cref="Speed"/> scales the simulated clock, so a test drives a
/// thirty second create to completion in a few hundred milliseconds without
/// any test-only branch in the view models.</item>
/// </list>
/// </remarks>
public sealed class MockCore : ICoreClient
{
    private const int TickMs = 50;

    private readonly object _gate = new();
    private readonly Dictionary<long, MockJob> _jobs = [];
    private readonly List<long> _order = [];
    private readonly Timer _timer;
    private long _nextId = 1;
    private bool _queuePaused;
    private int _concurrency = 1;
    private PostQueueAction _postAction;
    private bool _postActionDue;
    private ParfastSettings _settings = new();
    private JobError? _lastError;
    private bool _disposed;

    public MockCore(double speed = 1.0)
    {
        Speed = speed;
        _timer = new Timer(_ => Tick(), null, TickMs, TickMs);
    }

    public event Action? Wake;

    /// <summary>Multiplier on the simulated clock. 1.0 is real time.</summary>
    public double Speed { get; set; }

    /// <summary>
    /// Which scenario a create job plays. Verify and repair pick theirs from
    /// the path, which is what makes the demo driveable from Explorer.
    /// </summary>
    public MockSet CreateScenario { get; set; } = MockScenarios.SlowCreate;

    /// <summary>
    /// What the mock claims it can do.
    /// </summary>
    /// <remarks>
    /// THESE MATCH THE REAL ENGINE'S ANSWERS as of 12 Sep 2026
    /// (crates/parfast-ffi/API.md's capability table), and that matters more than
    /// it looks. A mock that claims every capability is a mock whose screens show
    /// controls the engine does not have, so the demo and the screenshots would
    /// show an app nobody can ship. Where the engine says false, the mock says
    /// false, and the control is absent in both.
    /// </remarks>
    public Capabilities Capabilities { get; set; } = new()
    {
        Version = "1.5.0",
        Engine = "nzbkit 1.5.0 (mock)",
        Cpu = "mock CPU",
        Kernel = "mock",
        // THESE MIRROR THE ENGINE'S OWN ANSWERS AND HAVE TO BE RE-READ WHEN IT
        // MOVES. A mock that claims more than the engine demos controls nobody
        // can ship; a mock that claims LESS hides shipped ones, and the
        // screenshots then advertise an app that is missing features it has.
        // The second is what happened on 12 Sep 2026, TWICE. `par2-comment-packet`
        // and `parfast-create-capability-flips` landed within the hour and flipped
        // three of these true, and this block still said false, so the mock
        // screenshot set had no Comment field, no spec naming and no explicit
        // volume ceiling while the real engine offered all three. Then
        // `par2gen-create-control` flipped the three in-fold keys the same
        // afternoon and this block said false to those for the rest of the day:
        // the mock disabled Pause on a running create and drew an indeterminate
        // bar under a create's fold, both of which the engine had stopped doing.
        //
        // The source of truth is the capability table in
        // apps/parfast/crates/parfast-ffi/API.md.
        StdNaming = true,
        UnicodePolicy = false,
        Comment = true,
        VolumeLimitExplicit = true,
        DataSkipping = true,
        FastSolver = true,
        Pause = true,
        PauseInFold = true,
        CancelInFold = true,
        ProgressInFold = true,
        LowPriority = false,
    };

    public long Submit(JobSpec spec)
    {
        long id;
        lock (_gate)
        {
            id = _nextId++;
            var set = spec.Kind switch
            {
                JobKind.Create => CreateScenario,
                JobKind.Verify => MockScenarios.ForPath(spec.Verify?.Par2),
                JobKind.Repair => MockScenarios.ForPath(spec.Repair?.Par2),
                _ => MockScenarios.Clean,
            };

            var job = new MockJob(id, spec, set, DateTimeOffset.UtcNow);
            _jobs[id] = job;
            _order.Add(id);
            PumpLocked();
        }

        Wake?.Invoke();
        return id;
    }

    public JobSnapshot? Snapshot(long id)
    {
        lock (_gate)
        {
            return _jobs.TryGetValue(id, out var job) ? job.ToSnapshot() : null;
        }
    }

    public QueueSnapshot QueueSnapshot()
    {
        lock (_gate)
        {
            return new QueueSnapshot
            {
                Paused = _queuePaused,
                Concurrency = _concurrency,
                PostAction = _postAction,
                PostActionDue = _postActionDue,
                Jobs = _order.Select(id => _jobs[id].ToSnapshot()).ToList(),
            };
        }
    }

    public bool Cancel(long id) => Mutate(id, job => job.Cancel());

    public bool Pause(long id) => Mutate(id, job => job.Pause());

    public bool Resume(long id) => Mutate(id, job => job.Resume());

    public bool Remove(long id)
    {
        bool removed;
        lock (_gate)
        {
            if (!_jobs.TryGetValue(id, out var job))
            {
                _lastError = new JobError { Code = "no_such_job", Message = $"No job with id {id}." };
                return false;
            }

            if (!job.ToSnapshot().IsFinished)
            {
                _lastError = new JobError
                {
                    Code = "job_running",
                    Message = "Only a finished job can be removed from the queue.",
                };
                return false;
            }

            _jobs.Remove(id);
            removed = _order.Remove(id);
        }

        Wake?.Invoke();
        return removed;
    }

    public bool SetLowPriority(long id, bool on) => Mutate(id, job => job.LowPriority = on);

    public bool SetQueuePaused(bool paused)
    {
        lock (_gate)
        {
            _queuePaused = paused;
            if (paused)
            {
                foreach (var job in _order.Select(x => _jobs[x]).Where(j => j.State == JobState.Running))
                {
                    job.PauseForQueue();
                }
            }
            else
            {
                // Resume what the QUEUE paused, and nothing else. A job the user
                // paused by hand stays paused when the queue restarts, or
                // "pause queue, resume queue" would silently undo a deliberate
                // pause on one job.
                foreach (var job in _order.Select(x => _jobs[x]).Where(j => j.PausedByQueue))
                {
                    job.Resume();
                }
            }

            PumpLocked();
        }

        Wake?.Invoke();
        return true;
    }

    public bool SetConcurrency(uint n)
    {
        lock (_gate)
        {
            _concurrency = (int)Math.Clamp(n, 1u, 64u);
            PumpLocked();
        }

        Wake?.Invoke();
        return true;
    }

    public bool SetPostAction(PostQueueAction action)
    {
        lock (_gate)
        {
            _postAction = action;
            _postActionDue = false;
            return true;
        }
    }

    /// <summary>
    /// The mock's queue never falls due, because nothing in it drains a real
    /// machine to sleep. Present so a host written against the real core compiles
    /// and behaves the same way here.
    /// </summary>
    public bool ClearPostAction()
    {
        lock (_gate)
        {
            _postActionDue = false;
            return true;
        }
    }

    /// <summary>
    /// Marks a queued job as the one the scheduler takes next.
    /// </summary>
    /// <remarks>
    /// The mock keeps the same shape as the core: a FLAG, not a reordered list, so
    /// the Queue table still shows submission order while the pick changes.
    /// </remarks>
    public bool RunNext(long id) => Mutate(id, job => job.RunNext = true);

    /// <summary>The mock persists nothing and says so by answering zero jobs loaded.</summary>
    public int OpenQueueStore(string path)
    {
        LastQueueStorePath = path;
        return 0;
    }

    /// <summary>The path the host last asked the queue to persist to. Read by the tests.</summary>
    public string? LastQueueStorePath { get; private set; }

    /// <summary>
    /// Makes the post-queue action fall due, the way a drained real queue does.
    /// </summary>
    /// <remarks>
    /// Driven by hand rather than inferred from an empty queue: the real core falls
    /// due once and stays due until the host clears it, and reproducing that edge
    /// exactly is what the host's clear-once behaviour has to be tested against.
    /// </remarks>
    public void RaisePostActionDue()
    {
        lock (_gate)
        {
            _postActionDue = _postAction != PostQueueAction.None;
        }

        Wake?.Invoke();
    }

    public PlanPreview PlanPreview(CreateSpec spec)
    {
        // The mock has no disk, so a source is sized by the scenario when its
        // name matches one of the scenario's files and by a deterministic
        // hash of the path otherwise. Deterministic matters: the preview is
        // recomputed on every keystroke and a jittering total would read as a
        // bug in the planner.
        var sources = spec.Sources
            .Select(s => new PlannedSource(s.Path, MockSize(s.Path)))
            .ToList();
        return MockPlanner.Plan(spec, sources);
    }

    public ParfastSettings GetSettings()
    {
        lock (_gate)
        {
            return _settings;
        }
    }

    public bool SetSettings(ParfastSettings settings)
    {
        lock (_gate)
        {
            _settings = settings;
            _concurrency = Math.Max(1, settings.Concurrency);
            _postAction = settings.PostQueueAction;
            return true;
        }
    }

    public JobError? LastError()
    {
        lock (_gate)
        {
            return _lastError;
        }
    }

    /// <summary>
    /// The mock builds its snapshots rather than decoding them, so it has nothing
    /// to fail to read. Settable by a test that wants the shell's handling of one.
    /// </summary>
    public string? PendingDecodeError { get; set; }

    public string? TakeDecodeError()
    {
        var error = PendingDecodeError;
        PendingDecodeError = null;
        return error;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _timer.Dispose();
    }

    /// <summary>Advances the simulated clock by hand, for a test that wants no timer.</summary>
    public void Advance(TimeSpan by)
    {
        bool changed;
        lock (_gate)
        {
            changed = AdvanceLocked(by.TotalMilliseconds);
        }

        if (changed)
        {
            Wake?.Invoke();
        }
    }

    private long MockSize(string path)
    {
        var name = Path.GetFileName(path);
        foreach (var file in CreateScenario.Files)
        {
            if (string.Equals(file.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return file.Size;
            }
        }

        // A stable pseudo size in the 8 MiB to 520 MiB range.
        var hash = 17;
        foreach (var c in name)
        {
            hash = (hash * 31) + c;
        }

        return (8 + (Math.Abs(hash) % 512)) * 1048576L;
    }

    /// <summary>
    /// Applies a change to one job and wakes the host.
    /// </summary>
    /// <remarks>
    /// The wake is fired OUTSIDE the lock, and that is not tidiness. A handler
    /// answers a wake by polling, so a wake raised under the lock would have the
    /// handler re-enter it on the same thread; Monitor is re-entrant so it would
    /// work today, and it would deadlock the day a handler hands the poll to
    /// another thread and waits. Firing outside costs nothing and cannot.
    /// </remarks>
    private bool Mutate(long id, Action<MockJob> change)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(id, out var job))
            {
                _lastError = new JobError { Code = "no_such_job", Message = $"No job with id {id}." };
                return false;
            }

            change(job);
            PumpLocked();
        }

        Wake?.Invoke();
        return true;
    }

    private void Tick()
    {
        bool changed;
        lock (_gate)
        {
            changed = AdvanceLocked(TickMs * Speed);
        }

        if (changed)
        {
            Wake?.Invoke();
        }
    }

    private bool AdvanceLocked(double ms)
    {
        var changed = false;
        foreach (var id in _order)
        {
            if (_jobs[id].Advance(ms))
            {
                changed = true;
            }
        }

        return PumpLocked() || changed;
    }

    /// <summary>
    /// Starts as many queued jobs as the concurrency allows. This is the mock
    /// of the serial scheduler, and it is what makes the Queue screen show the
    /// truth even for a job the user started directly from Create: everything
    /// goes through the queue (plan section 5.3, progress sheet).
    /// </summary>
    private bool PumpLocked()
    {
        if (_queuePaused)
        {
            return false;
        }

        var changed = false;
        var running = _order.Count(id => _jobs[id].State == JobState.Running);

        // A job flagged Run next is taken before the rest, and the flag is cleared
        // by starting it. Submission order otherwise, which is what the Queue table
        // shows - the flag changes the PICK, never the list.
        var order = _order
            .OrderByDescending(id => _jobs[id].RunNext)
            .ToList();

        foreach (var id in order)
        {
            if (running >= _concurrency)
            {
                break;
            }

            var job = _jobs[id];
            if (job.State == JobState.Queued)
            {
                job.Start();
                running++;
                changed = true;
            }
        }

        return changed;
    }
}

/// <summary>One simulated job. Every member is touched only under MockCore's lock.</summary>
internal sealed class MockJob(long id, JobSpec spec, MockSet set, DateTimeOffset addedAt)
{
    private readonly List<string> _log = [];
    private double _elapsedMs;
    private double _pausedMs;
    private int _loggedTenths;

    public JobState State { get; private set; } = JobState.Queued;

    public bool LowPriority { get; set; } = spec.Create?.Perf?.LowPriority ?? false;

    /// <summary>Set by Run now. Cleared when the scheduler takes the job.</summary>
    public bool RunNext { get; set; }

    private int DurationMs => spec.Kind == JobKind.Repair ? set.RepairMs : set.VerifyMs;

    public void Start()
    {
        if (State != JobState.Queued && State != JobState.Paused)
        {
            return;
        }

        var wasPaused = State == JobState.Paused;
        State = JobState.Running;
        RunNext = false;
        if (!wasPaused)
        {
            _log.Add(Header());
        }
    }

    /// <summary>How long this job has spent paused. Read by the tests, and the
    /// reason a paused job's ETA is not inflated by the pause.</summary>
    public double PausedMs => _pausedMs;

    /// <summary>True when the QUEUE paused this job rather than the user.</summary>
    public bool PausedByQueue { get; private set; }

    public void Pause()
    {
        if (State != JobState.Running)
        {
            return;
        }

        State = JobState.Paused;
        PausedByQueue = false;
    }

    /// <summary>Pauses because the queue was paused, which is undone by resuming it.</summary>
    public void PauseForQueue()
    {
        if (State != JobState.Running)
        {
            return;
        }

        State = JobState.Paused;
        PausedByQueue = true;
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

        State = JobState.Cancelled;
        _log.Add("Cancelled. Nothing was written.");
    }

    public bool Advance(double ms)
    {
        if (State == JobState.Paused)
        {
            _pausedMs += ms;
            return false;
        }

        if (State != JobState.Running)
        {
            return false;
        }

        _elapsedMs += ms;
        LogProgress();

        if (_elapsedMs < DurationMs)
        {
            return true;
        }

        _elapsedMs = DurationMs;
        if (set.FailWith is { } reason)
        {
            State = JobState.Failed;
            _log.Add($"Error: {reason}");
            return true;
        }

        State = JobState.Done;
        _log.Add(Footer());
        return true;
    }

    public JobSnapshot ToSnapshot()
    {
        var fraction = DurationMs <= 0 ? 1.0 : Math.Clamp(_elapsedMs / DurationMs, 0, 1);
        var settled = State is JobState.Done or JobState.Failed;
        var survey = spec.Kind is JobKind.Verify or JobKind.Repair
            ? MockSurvey.Build(set, fraction, spec.Kind == JobKind.Repair, settled)
            : null;

        return new JobSnapshot
        {
            Id = id,
            Kind = spec.Kind,
            State = State,
            Phase = PhaseFor(fraction),
            PhaseText = PhaseTextFor(fraction),
            Progress = State == JobState.Queued ? 0 : fraction,
            ElapsedMs = (long)_elapsedMs,
            EtaMs = State == JobState.Running && fraction > 0.02
                ? (long)Math.Max(0, DurationMs - _elapsedMs)
                : null,
            RateBytesPerS = State == JobState.Running ? RateFor(fraction) : 0,
            LowPriority = LowPriority,
            AddedAt = addedAt,
            Name = string.IsNullOrEmpty(spec.DisplayName()) ? set.SetName : spec.DisplayName(),
            LogTail = _log.ToList(),
            Survey = survey,
            Result = State == JobState.Done ? ResultFor() : null,
            Error = State == JobState.Failed
                ? new JobError { Code = "read_failed", Message = set.FailWith ?? "The job failed." }
                : UnrepairableError(),
        };
    }

    private JobError? UnrepairableError()
    {
        if (spec.Kind != JobKind.Repair || State != JobState.Done || set.Repairable)
        {
            return null;
        }

        return new JobError
        {
            Code = "unrepairable",
            Message = $"needs {set.RecoveryNeeded - set.RecoveryAvailable} more blocks",
        };
    }

    private JobResult ResultFor()
    {
        if (spec.Kind == JobKind.Repair)
        {
            return new JobResult
            {
                RepairedFiles = set.Files.Count(f =>
                    f.Outcome is FileStatus.Damaged or FileStatus.Missing or FileStatus.Misnamed),
                Purged = spec.Repair?.Purge ?? false,
            };
        }

        if (spec.Kind == JobKind.Create)
        {
            var preview = MockPlanner.Plan(
                spec.Create ?? new CreateSpec(),
                set.Files.Select(f => new PlannedSource(f.Name, f.Size)).ToList());
            return new JobResult
            {
                Written = preview.Files.Select(f => new WrittenFile { Name = f.Name, Size = f.Size }).ToList(),
            };
        }

        if (spec.Kind is JobKind.ChecksumCreate or JobKind.ChecksumVerify)
        {
            return MockChecksums.Result(set, spec.Kind == JobKind.ChecksumVerify);
        }

        return new JobResult();
    }

    private long RateFor(double fraction)
    {
        // A plausible curve rather than a constant: fast while hashing cached
        // data, slower through the solve. A rate that never moves makes a
        // progress panel look fake, and the panel is the thing being judged.
        var baseRate = 480L * 1024 * 1024;
        var wobble = 0.85 + (0.3 * Math.Abs(Math.Sin(fraction * 11)));
        var phasePenalty = fraction is > 0.6 and < 0.85 ? 0.55 : 1.0;
        return (long)(baseRate * wobble * phasePenalty / (LowPriority ? 3.0 : 1.0));
    }

    private JobPhase PhaseFor(double fraction) => spec.Kind switch
    {
        JobKind.Create => fraction switch
        {
            < 0.04 => JobPhase.Scanning,
            < 0.55 => JobPhase.Hashing,
            < 0.95 => JobPhase.Writing,
            _ => JobPhase.Finishing,
        },
        JobKind.Repair => fraction switch
        {
            < 0.05 => JobPhase.Scanning,
            < 0.5 => JobPhase.Hashing,
            < 0.7 => JobPhase.Solving,
            < 0.97 => JobPhase.Writing,
            _ => JobPhase.Finishing,
        },
        _ => fraction switch
        {
            < 0.06 => JobPhase.Scanning,
            < 0.96 => JobPhase.Hashing,
            _ => JobPhase.Finishing,
        },
    };

    private string PhaseTextFor(double fraction)
    {
        var phase = PhaseFor(fraction);
        var total = set.Files.Count;
        var current = Math.Clamp((int)Math.Ceiling(fraction * total), 1, Math.Max(1, total));
        return phase switch
        {
            JobPhase.Scanning => "Reading the set",
            JobPhase.Hashing => $"Hashing {current:N0} of {total:N0} files",
            JobPhase.Solving => "Working out the repair",
            JobPhase.Writing => spec.Kind == JobKind.Create
                ? $"Computing recovery blocks {(int)(fraction * set.RecoveryAvailable):N0} of {set.RecoveryAvailable:N0}"
                : "Writing repaired data",
            JobPhase.Finishing => "Finishing",
            _ => string.Empty,
        };
    }

    private string Header() => spec.Kind switch
    {
        JobKind.Create => $"parfast: creating \"{set.SetName}\" from {set.Files.Count} files",
        JobKind.Repair => $"parfast: repairing \"{set.SetName}\"",
        JobKind.Verify => $"parfast: loading \"{set.SetName}\"",
        _ => "parfast: working",
    };

    private string Footer() => spec.Kind switch
    {
        JobKind.Create => $"Wrote {set.RecoveryAvailable} recovery blocks. Done.",
        JobKind.Repair => set.Repairable
            ? "Repair complete."
            : $"Repair failed: needs {set.RecoveryNeeded - set.RecoveryAvailable} more blocks.",
        JobKind.Verify => set.RecoveryNeeded == 0
            ? "All files are correct. No repair needed."
            : $"{set.RecoveryNeeded} blocks are missing; {set.RecoveryAvailable} recovery blocks are available.",
        _ => "Done.",
    };

    private void LogProgress()
    {
        // One line per tenth, so the log drawer has something to scroll
        // without the mock writing thousands of lines into a snapshot that is
        // copied on every poll.
        var tenth = (int)(Math.Clamp(_elapsedMs / Math.Max(1, DurationMs), 0, 1) * 10);
        while (_loggedTenths <= tenth && _loggedTenths <= 10)
        {
            var pct = _loggedTenths * 10;
            _log.Add($"{pct,3}%  {PhaseTextFor(pct / 100.0)}");
            _loggedTenths++;
        }
    }
}
