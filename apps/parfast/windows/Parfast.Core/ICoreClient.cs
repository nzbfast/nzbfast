using Parfast.Core.Contracts;

namespace Parfast.Core;

/// <summary>
/// One method per C function of <c>crates/parfast-ffi/include/parfast_ffi.h</c>
/// (plan section 4.5), with the JSON already decoded.
/// </summary>
/// <remarks>
/// Two implementations: <see cref="Mock.MockCore"/>, which plays the scripted
/// scenarios of plan section 3.3 and needs no engine, and <c>FfiCore</c>,
/// which P/Invokes the cdylib. Every screen is built and demoable on the
/// mock, and the mock stays in the tree afterwards as the UI test harness.
/// <para>
/// THREADING, which is the one rule the whole design rests on: the session
/// is thread-safe and calls may come from any thread. <see cref="Wake"/> may
/// fire from any thread and carries no data; the host marshals to its UI
/// thread and then polls. Nothing here may be assumed to run on the UI
/// thread.
/// </para>
/// </remarks>
public interface ICoreClient : IDisposable
{
    /// <summary>
    /// Fires whenever a snapshot would differ from the last one handed out,
    /// at most about twenty times a second, FROM ANY THREAD. Subscribers
    /// must marshal before touching UI state.
    /// </summary>
    event Action? Wake;

    Capabilities Capabilities { get; }

    /// <returns>The new job id, or a negative value on failure.</returns>
    long Submit(JobSpec spec);

    JobSnapshot? Snapshot(long id);

    QueueSnapshot QueueSnapshot();

    bool Cancel(long id);
    bool Pause(long id);
    bool Resume(long id);
    bool Remove(long id);
    bool SetLowPriority(long id, bool on);

    bool SetQueuePaused(bool paused);
    bool SetConcurrency(uint n);
    bool SetPostAction(PostQueueAction action);

    /// <summary>
    /// Says the host has carried out the due post action. It does not fall due
    /// again until a new job is submitted.
    /// </summary>
    bool ClearPostAction();

    /// <summary>
    /// Persists the queue to a path the HOST names, and returns how many jobs were
    /// loaded, or a negative value on failure.
    /// </summary>
    /// <remarks>
    /// The host names the path because it knows where an app's data directory is
    /// on its own platform and the core does not. A store that cannot be parsed is
    /// reported and never deleted. A job that was running when the file was written
    /// comes back <see cref="JobState.Interrupted"/>.
    /// </remarks>
    int OpenQueueStore(string path);

    /// <summary>
    /// Marks one queued job as the next the scheduler should take. Section 5.5's
    /// "Run now".
    /// </summary>
    /// <remarks>
    /// A FLAG ON THE ENTRY, not a reordered table: the queue stays keyed on the id
    /// so iteration IS submission order and the display and the scheduler read one
    /// rule. Neither of the two things a host can do without it is "run this now" -
    /// raising the concurrency starts everything queued AHEAD of the chosen job as
    /// well, and resuming it only lets the scheduler reach it in its turn.
    /// </remarks>
    bool RunNext(long id);

    /// <summary>No I/O beyond stat. Called on every keystroke in Create.</summary>
    PlanPreview PlanPreview(CreateSpec spec);

    ParfastSettings GetSettings();
    bool SetSettings(ParfastSettings settings);

    /// <summary>
    /// "Clear remembered checksums": deletes every record in the per-user digest
    /// store, and returns how many went, or a negative value on failure.
    /// </summary>
    /// <remarks>Safe while a job runs, and leaves the setting alone.</remarks>
    int ClearDigestCache();

    /// <summary>The detail behind the last false or negative return.</summary>
    JobError? LastError();

    /// <summary>
    /// The last answer this client could not decode, or null.
    /// </summary>
    /// <remarks>
    /// A CORE THAT OUTGROWS THIS BUILD IS THE CASE THIS EXISTS FOR. The contract
    /// lets the core add fields and enum values, and the decoder is deliberately
    /// forgiving so a 10 Hz poll cannot be turned into an exception per tick. The
    /// cost of that forgiveness is that a shape this build genuinely cannot read
    /// degrades to a STALE SCREEN - the last good snapshot, redrawn for ever, with
    /// nothing on it saying so. That is the worst failure this app can have,
    /// because it looks exactly like a job that stopped making progress.
    /// <para>
    /// So the decoder records it and the log drawer shows it. Reading it clears
    /// it, so a transient garble does not stick to the screen after the next good
    /// poll.
    /// </para>
    /// </remarks>
    string? TakeDecodeError();
}
