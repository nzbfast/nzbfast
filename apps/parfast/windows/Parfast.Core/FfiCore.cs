using System.Runtime.InteropServices;
using Parfast.Core.Contracts;

namespace Parfast.Core;

/// <summary>
/// <see cref="ICoreClient"/> over <c>parfast_ffi.dll</c>, the cdylib built from
/// <c>crates/parfast-ffi</c>.
/// </summary>
/// <remarks>
/// Written against the contract in plan section 4.5 BEFORE the header existed, so
/// the switch from the mock was one line at startup rather than a rewrite. The
/// header landed on 12 Sep 2026 at
/// <c>apps/parfast/crates/parfast-ffi/include/parfast_ffi.h</c> and every
/// signature below matched it unchanged; the two functions the core added beyond
/// the plan (<c>pf_queue_clear_post_action</c> and <c>pf_queue_open_store</c>)
/// are here too.
/// <para>
/// When the library is absent this type still compiles and
/// <see cref="TryCreate"/> answers null, so the app falls back to the mock with a
/// visible banner rather than failing to start.
/// </para>
/// <para>
/// THREE RULES THIS TYPE EXISTS TO HONOUR, each of which is a leak or a crash
/// if broken:
/// </para>
/// <list type="number">
/// <item>Every <c>char *</c> the library returns is owned by the caller and
/// freed with <c>pf_string_free</c>. <see cref="TakeString"/> is the only path
/// that reads one, and it frees in a finally.</item>
/// <item>The wake callback may fire FROM ANY THREAD and carries no data. The
/// delegate must be PINNED for the life of the session, or the GC collects it
/// and the first wake from Rust jumps into freed memory. The field
/// <c>_wakeDelegate</c> is that pin, and it is why the callback is not a
/// lambda passed inline.</item>
/// <item>The session is thread-safe on the Rust side, so no lock is taken
/// here. What is not thread-safe is disposal, so <see cref="Dispose"/> and
/// every call check the handle.</item>
/// </list>
/// </remarks>
public sealed class FfiCore : ICoreClient
{
    private const string Library = "parfast_ffi";

    private readonly nint _session;

    /// <summary>
    /// The pin. Assigned once in the constructor and never reassigned: this
    /// field is the only thing keeping the marshalled thunk alive while Rust
    /// holds a function pointer to it.
    /// </summary>
    private readonly WakeFn _wakeDelegate;

    private bool _disposed;

    private FfiCore(nint session)
    {
        _session = session;
        _wakeDelegate = OnWake;
        pf_session_set_wake(_session, _wakeDelegate, nint.Zero);
        Capabilities = ReadJson<Capabilities>(pf_capabilities(_session)) ?? Capabilities.Unknown;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void WakeFn(nint ctx);

    public event Action? Wake;

    public Capabilities Capabilities { get; }

    /// <summary>
    /// Opens a session, or returns null when the library is not present or
    /// refuses to start. The caller falls back to <see cref="Mock.MockCore"/>.
    /// </summary>
    public static FfiCore? TryCreate(ParfastSettings? settings, out string? error)
    {
        error = null;
        try
        {
            var json = settings is null ? null : ParfastJson.Write(settings);
            var session = pf_session_new(json);
            if (session == nint.Zero)
            {
                error = "pf_session_new returned null.";
                return null;
            }

            return new FfiCore(session);
        }
        catch (DllNotFoundException e)
        {
            error = $"{Library} was not found beside the app: {e.Message}";
            return null;
        }
        catch (EntryPointNotFoundException e)
        {
            // A cdylib that is present but older than this build. Naming the
            // missing symbol is the whole diagnosis, so it is not swallowed.
            error = $"{Library} is missing a function this build needs: {e.Message}";
            return null;
        }
        catch (BadImageFormatException e)
        {
            error = $"{Library} is built for a different architecture: {e.Message}";
            return null;
        }
    }

    public long Submit(JobSpec spec) => pf_job_submit(Live(), ParfastJson.Write(spec));

    public JobSnapshot? Snapshot(long id) => ReadJson<JobSnapshot>(pf_job_snapshot(Live(), id));

    public QueueSnapshot QueueSnapshot() =>
        ReadJson<QueueSnapshot>(pf_queue_snapshot(Live())) ?? Contracts.QueueSnapshot.Empty;

    public bool Cancel(long id) => pf_job_cancel(Live(), id) == 0;

    public bool Pause(long id) => pf_job_pause(Live(), id) == 0;

    public bool Resume(long id) => pf_job_resume(Live(), id) == 0;

    public bool Remove(long id) => pf_job_remove(Live(), id) == 0;

    public bool SetLowPriority(long id, bool on) => pf_job_set_low_priority(Live(), id, on) == 0;

    public bool SetQueuePaused(bool paused) => pf_queue_set_paused(Live(), paused) == 0;

    public bool SetConcurrency(uint n) => pf_queue_set_concurrency(Live(), n) == 0;

    public bool SetPostAction(PostQueueAction action) =>
        pf_queue_set_post_action(Live(), SnakeCaseEnumConverter<PostQueueAction>.WireName(action)) == 0;

    public bool ClearPostAction() => pf_queue_clear_post_action(Live()) == 0;

    public bool RunNext(long id) => pf_job_run_next(Live(), id) == 0;

    public int OpenQueueStore(string path) => pf_queue_open_store(Live(), path);

    public int ClearDigestCache() => pf_digest_cache_clear(Live());

    public PlanPreview PlanPreview(CreateSpec spec) =>
        ReadJson<PlanPreview>(pf_plan_preview(Live(), ParfastJson.Write(spec))) ?? Contracts.PlanPreview.Empty;

    public ParfastSettings GetSettings() => ReadJson<ParfastSettings>(pf_settings_get(Live())) ?? new ParfastSettings();

    public bool SetSettings(ParfastSettings settings) =>
        pf_settings_set(Live(), ParfastJson.Write(settings)) == 0;

    public JobError? LastError() => ReadJson<JobError>(pf_last_error(Live()));

    public string? TakeDecodeError()
    {
        var error = LastJsonError;
        LastJsonError = null;
        return error;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Clear the callback BEFORE freeing the session: a wake in flight on
        // another thread must not find a half-freed session, and Rust drops its
        // function pointer here while the delegate is still pinned by this
        // object, which stays alive until this method returns.
        pf_session_set_wake(_session, null, nint.Zero);
        pf_session_free(_session);
    }

    private void OnWake(nint ctx) => Wake?.Invoke();

    private nint Live() =>
        _disposed ? throw new ObjectDisposedException(nameof(FfiCore)) : _session;

    /// <summary>
    /// Reads a library-owned string and frees it. Every <c>char *</c> return
    /// goes through here; a second path would be a second place to forget the
    /// free.
    /// </summary>
    private static string? TakeString(nint ptr)
    {
        if (ptr == nint.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            pf_string_free(ptr);
        }
    }

    private static T? ReadJson<T>(nint ptr)
    {
        var json = TakeString(ptr);
        if (json is null)
        {
            return default;
        }

        var value = ParfastJson.TryRead<T>(json, out var error);
        if (error is not null)
        {
            // Not thrown: this runs inside a 10 Hz poll, so a shape this build
            // cannot read must not become an exception per tick. It is RECORDED
            // instead, and the shell surfaces it in the log drawer - a stale screen
            // that says nothing is the worst outcome here, because it looks exactly
            // like a job that stopped making progress.
            LastJsonError = $"{typeof(T).Name}: {error}";
        }

        return value;
    }

    /// <summary>The last JSON the poll could not read, for the log drawer.</summary>
    public static string? LastJsonError { get; private set; }

    // The header of plan section 4.5, one DllImport per function, in the same
    // order. StringMarshalling.Utf8 is what makes "every string is UTF-8" true
    // on the C# side; a default marshal would send UTF-16 for the in-parameters.

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern nint pf_session_new([MarshalAs(UnmanagedType.LPUTF8Str)] string? settingsJson);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pf_session_free(nint session);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pf_session_set_wake(nint session, WakeFn? wake, nint ctx);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern long pf_job_submit(nint session, [MarshalAs(UnmanagedType.LPUTF8Str)] string specJson);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint pf_job_snapshot(nint session, long id);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint pf_queue_snapshot(nint session);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_job_cancel(nint session, long id);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_job_pause(nint session, long id);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_job_resume(nint session, long id);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_job_remove(nint session, long id);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_job_set_low_priority(nint session, long id, [MarshalAs(UnmanagedType.I1)] bool on);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_queue_set_paused(nint session, [MarshalAs(UnmanagedType.I1)] bool paused);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_queue_set_concurrency(nint session, uint n);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int pf_queue_set_post_action(
        nint session, [MarshalAs(UnmanagedType.LPUTF8Str)] string action);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_queue_clear_post_action(nint session);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_job_run_next(nint session, long id);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int pf_queue_open_store(
        nint session, [MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pf_digest_cache_clear(nint session);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern nint pf_plan_preview(
        nint session, [MarshalAs(UnmanagedType.LPUTF8Str)] string createSpecJson);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint pf_capabilities(nint session);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint pf_settings_get(nint session);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int pf_settings_set(
        nint session, [MarshalAs(UnmanagedType.LPUTF8Str)] string settingsJson);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint pf_last_error(nint session);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pf_string_free(nint s);
}
