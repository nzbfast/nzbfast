using Parfast.Core.Mock;

namespace Parfast.App;

/// <summary>What the app was asked to do on startup.</summary>
/// <remarks>
/// Four sources hand this app a command line and each has its own shape:
/// a user double-clicking a .par2 (a bare path), the Explorer verbs
/// (<c>--verify</c> or <c>--create</c> plus a path, written by
/// <see cref="RegistryIntegration"/> and by packaging/windows/parfast-gui.iss),
/// a developer forcing the mock (<c>--mock</c>), and the screenshot harness
/// (<c>--shot</c>). Parsing them in one place, in a type the tests could reach,
/// is what keeps the association from breaking the day a switch is added.
/// </remarks>
public sealed record CommandLineOptions
{
    /// <summary>The file or folder to open, or null.</summary>
    public string? Path { get; init; }

    /// <summary>Set by the Explorer verbs to say which mode the path is for.</summary>
    public string? Verb { get; init; }

    /// <summary>Use the mock even when the engine library is present.</summary>
    public bool ForceMock { get; init; }

    /// <summary>The screen the screenshot harness wants, or null for normal startup.</summary>
    public string? Shot { get; init; }

    /// <summary>Which mock scenario the shot should play.</summary>
    public string? Scenario { get; init; }

    /// <summary>"light" or "dark", forced for a screenshot. Null follows the system.</summary>
    public string? Theme { get; init; }

    public bool IsScreenshot => Shot is not null;

    public MockSet? ScenarioSet => Scenario is null ? null : MockScenarios.ByKey(Scenario);

    public static CommandLineOptions Parse(IReadOnlyList<string> argv)
    {
        string? path = null, verb = null, shot = null, scenario = null, theme = null;
        var forceMock = false;

        for (var i = 0; i < argv.Count; i++)
        {
            var arg = argv[i];
            string? Next() => i + 1 < argv.Count ? argv[++i] : null;

            switch (arg.ToLowerInvariant())
            {
                case "--mock":
                    forceMock = true;
                    break;
                case "--verify":
                case "--create":
                    verb = arg.TrimStart('-').ToLowerInvariant();
                    break;
                case "--shot":
                    shot = Next();
                    // A shot always uses the mock: the pictures have to be the same
                    // on a box with the engine and a box without, or two rounds of
                    // screenshots are not comparable.
                    forceMock = true;
                    break;
                case "--scenario":
                    scenario = Next();
                    break;
                case "--theme":
                    theme = Next()?.ToLowerInvariant();
                    break;
                default:
                    if (!arg.StartsWith('-') && path is null)
                    {
                        path = arg;
                    }

                    break;
            }
        }

        return new CommandLineOptions
        {
            Path = path,
            Verb = verb,
            ForceMock = forceMock,
            Shot = shot,
            Scenario = scenario,
            Theme = theme,
        };
    }
}
