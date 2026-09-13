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
    }
}
