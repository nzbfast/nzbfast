using System.Runtime.InteropServices;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;

namespace Parfast.App;

/// <summary>
/// One parfast window per user session: a second launch hands its command line
/// to the first and exits.
/// </summary>
/// <remarks>
/// WHY, and it is not tidiness: both processes open the same
/// <c>%LOCALAPPDATA%\parfast\queue.json</c>. The second shows the first one's
/// running job as Interrupted, and whichever writes last wins, so jobs and
/// settings vanish (sweep 2026-11-09 A41). Double-clicking a second .par2 while
/// the app is open is the ordinary way to get there.
/// <para>
/// THE KEY IS THE WINDOWS APP SDK'S <see cref="AppInstance.FindOrRegisterForKey"/>,
/// which is the named-object lock and the hand-off channel in one: the first
/// process to register the key owns it for its lifetime (the OS drops it when
/// the process dies, so a crash cannot strand it), and
/// <see cref="AppInstance.RedirectActivationToAsync"/> delivers the second
/// launch's arguments to the owner's <see cref="AppInstance.Activated"/> event.
/// A bare named mutex would give the lock and no way to pass the path along,
/// which turns "open this file" into a launch that silently does nothing.
/// </para>
/// <para>
/// A launch that cannot be handed over faithfully gets a window of its own that
/// never opens the queue store (<see cref="LaunchRoute.Separate"/>), so the file
/// is opened and the first instance's queue is still never written twice.
/// </para>
/// <para>
/// The screenshot harness is exempt (<see cref="CommandLineOptions.IsScreenshot"/>):
/// it starts one process per picture and must not have its staging forwarded
/// into a window left over from the previous one.
/// </para>
/// </remarks>
/// <summary>What this process should do after <see cref="SingleInstance.Claim"/>.</summary>
internal enum LaunchRoute
{
    /// <summary>This process is THE instance: open the window and the queue store.</summary>
    First,

    /// <summary>The launch was handed to the instance already running; exit.</summary>
    Forwarded,

    /// <summary>
    /// The launch could not be handed over faithfully: open a window that does
    /// NOT open the queue store, so the first instance's queue is never touched.
    /// </summary>
    Separate,
}

internal static class SingleInstance
{
    private const string Key = "parfast-gui";

    private static readonly object Gate = new();
    private static readonly List<IReadOnlyList<string>> Pending = [];
    private static Action<IReadOnlyList<string>>? _sink;

    /// <summary>
    /// Registers this process as THE instance, or forwards its activation to the
    /// one that already is.
    /// </summary>
    /// <param name="forwardable">
    /// False when the launch names a RELATIVE path. The redirect delivers the
    /// command line exactly as typed - the activation arguments cannot be
    /// rewritten - and the first instance would resolve the path against ITS
    /// working directory, which is a different file or none. So such a launch is
    /// never forwarded; it gets a <see cref="LaunchRoute.Separate"/> window that
    /// resolves the path against its own directory. Explorer, the association
    /// and the verbs always pass full paths; this is the terminal case.
    /// </param>
    public static LaunchRoute Claim(bool forwardable)
    {
        AppInstance owner;
        try
        {
            owner = AppInstance.FindOrRegisterForKey(Key);
            if (owner.IsCurrent)
            {
                // Subscribed NOW, before the core and the window exist: a burst of
                // launches (several .par2 selected in Explorer, Enter) arrives
                // while this process is still starting, and an activation raised
                // with nobody subscribed is lost. Held in Pending until Deliver.
                AppInstance.GetCurrent().Activated += OnActivated;
                return LaunchRoute.First;
            }
        }
        catch (Exception e) when (e is COMException or InvalidOperationException)
        {
            // The platform cannot say whether another instance exists. Run as the
            // app always did rather than refuse to start.
            return LaunchRoute.First;
        }

        if (!forwardable)
        {
            return LaunchRoute.Separate;
        }

        try
        {
            var activation = AppInstance.GetCurrent().GetActivatedEventArgs();

            // On a worker thread and WAITED for: the redirect must finish before
            // this process exits or the owner never hears of it, and blocking the
            // UI thread on a WinRT async it is not running is the documented
            // deadlock shape.
            //
            // A TIMEOUT STILL EXITS, and the launch may be lost: that is a choice,
            // stated here because it is not silent by accident. The redirect may
            // yet be delivered, and opening the same set in a second window as
            // well could run two repairs over one set's files at once, which is
            // worse than a double-click that has to be repeated. Ten seconds is
            // far past any healthy hand-off; an owner that slow is wedged.
            Task.Run(async () => await owner.RedirectActivationToAsync(activation)).Wait(TimeSpan.FromSeconds(10));
            return LaunchRoute.Forwarded;
        }
        catch (Exception e) when (e is COMException or InvalidOperationException or AggregateException)
        {
            // The hand-off FAILED rather than ran slow, so the owner did not get
            // it: open the file here, away from the owner's queue store.
            return LaunchRoute.Separate;
        }
    }

    /// <summary>
    /// Starts handing forwarded launches to <paramref name="sink"/>, first every
    /// one that arrived before the window existed, in arrival order. The sink may
    /// be called from any thread.
    /// </summary>
    public static void Deliver(Action<IReadOnlyList<string>> sink)
    {
        List<IReadOnlyList<string>> early;
        lock (Gate)
        {
            _sink = sink;
            early = [.. Pending];
            Pending.Clear();
        }

        foreach (var argv in early)
        {
            sink(argv);
        }
    }

    private static void OnActivated(object? sender, AppActivationArguments args)
    {
        var argv = ArgumentsOf(args);
        Action<IReadOnlyList<string>>? sink;
        lock (Gate)
        {
            sink = _sink;
            if (sink is null)
            {
                Pending.Add(argv);
                return;
            }
        }

        sink(argv);
    }

    /// <summary>
    /// The command line a forwarded launch carried, split as Windows splits one,
    /// with the executable dropped when the platform includes it.
    /// </summary>
    /// <remarks>
    /// For an UNPACKAGED app <see cref="ILaunchActivatedEventArgs.Arguments"/> can
    /// carry the whole command line, executable first; a packaged one carries only
    /// the arguments. Both are handled: the first token is dropped only when it
    /// names this executable, which no path a user opens with parfast can.
    /// </remarks>
    private static IReadOnlyList<string> ArgumentsOf(AppActivationArguments activation)
    {
        if (activation.Kind != ExtendedActivationKind.Launch
            || activation.Data is not ILaunchActivatedEventArgs launch
            || string.IsNullOrWhiteSpace(launch.Arguments))
        {
            return [];
        }

        var argv = Split(launch.Arguments);
        var self = Path.GetFileName(Environment.ProcessPath ?? "parfast-gui.exe");
        if (argv.Count > 0 && string.Equals(Path.GetFileName(argv[0]), self, StringComparison.OrdinalIgnoreCase))
        {
            argv.RemoveAt(0);
        }

        return argv;
    }

    /// <summary>Windows' own argv rules (quotes, backslashes), via the shell's splitter.</summary>
    private static List<string> Split(string commandLine)
    {
        var argv = CommandLineToArgvW(commandLine, out var count);
        if (argv == nint.Zero)
        {
            return [];
        }

        try
        {
            var result = new List<string>(count);
            for (var i = 0; i < count; i++)
            {
                result.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * nint.Size)) ?? string.Empty);
            }

            return result;
        }
        finally
        {
            LocalFree(argv);
        }
    }

    [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

    [DllImport("kernel32.dll")]
    private static extern nint LocalFree(nint hMem);
}
