using Microsoft.UI.Xaml;
using Parfast.Core;
using Parfast.Core.Mock;

namespace Parfast.App;

/// <summary>
/// The application object: it chooses the core, opens the window, and hands over
/// whatever was on the command line.
/// </summary>
/// <remarks>
/// THE MOCK-OR-REAL DECISION IS HERE AND NOWHERE ELSE, which is what plan section
/// 3.3 buys: <see cref="FfiCore.TryCreate"/> is asked first and the mock is the
/// fallback, so the app runs today on scripted scenarios and switches to the
/// engine the moment <c>parfast_ffi.dll</c> is beside the exe, with no build flag
/// and no second code path. When it falls back it SAYS SO in the window
/// (<see cref="ViewModels.ShellViewModel.IsMock"/>), because a demo that looks
/// like the real thing and is not is the one outcome worth refusing.
/// <para>
/// <c>--mock</c> forces the mock even when the library is there, which is how the
/// screenshot pass gets the same pictures on a box that has the engine.
/// </para>
/// </remarks>
public partial class App : Application
{
    private MainWindow? _window;

    public App() => InitializeComponent();

    /// <summary>The core this process is using. Null until OnLaunched has run.</summary>
    public ICoreClient? Core { get; private set; }

    /// <summary>Why the FFI core was not used, if it was not.</summary>
    public string? CoreFallbackReason { get; private set; }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var options = CommandLineOptions.Parse(Environment.GetCommandLineArgs().Skip(1).ToList());

        // ONE INSTANCE (see SingleInstance): a second launch hands its path to
        // the window already open and exits BEFORE it opens a core, so it never
        // touches the queue store the first one owns. Asked with the path AS
        // TYPED, because that is what a redirect forwards.
        var route = options.IsScreenshot
            ? LaunchRoute.First
            : SingleInstance.Claim(options.Path is null || Path.IsPathFullyQualified(options.Path));
        if (route == LaunchRoute.Forwarded)
        {
            Exit();
            return;
        }

        // A relative path is resolved HERE, against this process's own working
        // directory, which is the one the user typed it in; the core would
        // otherwise resolve it against whatever directory it happens to have.
        options = options with
        {
            Path = Absolute(options.Path),
            NoQueueStore = route == LaunchRoute.Separate,
        };

        if (!options.ForceMock)
        {
            Core = FfiCore.TryCreate(null, out var error);
            CoreFallbackReason = error;
        }

        if (Core is null)
        {
            var mock = new MockCore();
            if (options.ScenarioSet is { } set)
            {
                mock.CreateScenario = set;
            }

            Core = mock;
        }

        _window = new MainWindow(Core, CoreFallbackReason, options);
        _window.Activate();

        // A path on the command line is what the file association and the shell
        // verbs hand over (plan 6.2). Routed through the same drop router as a
        // drag, so a .par2 lands in Verify and a folder lands in Create whichever
        // way it arrived, unless a verb overrides it.
        if (options.Path is not null)
        {
            _window.OpenPath(options.Path, options.Verb);
        }

        // Launches forwarded by later processes, including any that arrived while
        // this one was still starting (SingleInstance buffered them). The sink is
        // called from any thread, so the work is marshalled to the window's.
        if (route == LaunchRoute.First && !options.IsScreenshot)
        {
            var window = _window;
            SingleInstance.Deliver(argv =>
            {
                var forwarded = CommandLineOptions.Parse(argv);
                window.DispatcherQueue.TryEnqueue(() =>
                {
                    window.Activate();

                    // Only a FULL path is acted on: a relative one would resolve
                    // against this process's directory, not the sender's.
                    // SingleInstance never forwards one, so this is defence only.
                    if (forwarded.Path is { } path && Path.IsPathFullyQualified(path))
                    {
                        window.OpenPath(path, forwarded.Verb);
                    }
                });
            });
        }
    }

    private static string? Absolute(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return path;
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException
                                     or System.Security.SecurityException)
        {
            return path;
        }
    }
}
