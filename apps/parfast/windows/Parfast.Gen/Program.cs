using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Parfast.Gen;

/// <summary>
/// Generates the C# copy table and the design tokens from the SHARED JSON that
/// both app lanes read (plan section 5.7: "both apps read the file at build
/// time, a tiny generator each, so a palette change is one edit").
/// </summary>
/// <remarks>
/// WHY A C# CONSOLE AND NOT A SCRIPT. The mac lane's generator can be anything;
/// this one has to run on the Windows build box, and that box has no Python and
/// no WSL on the Windows build box. A PowerShell twin plus a shell
/// twin would be two copies of one rule, which this repo refuses on principle
/// and which would drift. One net8.0 console runs on both hosts with the SDK
/// the solution already needs.
/// <para>
/// WHICH JSON IT READS, and why there are two candidates. The shared files are
/// <c>apps/parfast/shared/strings/en.json</c> and
/// <c>apps/parfast/shared/design/tokens.json</c>, and chip B (the mac lane)
/// OWNS them: this lane reads them and never edits them. They were not on
/// origin/main when this lane started, so the tree carries a bootstrap copy
/// under <c>apps/parfast/windows/shared-bootstrap/</c> taken from plan section
/// 5. The generator prefers the shared path whenever it exists on disk, so the
/// day chip B lands its files this build switches to them with no edit here and
/// the difference shows up as a diff in the generated sources, which is exactly
/// where it should show up.
/// </para>
/// <para>
/// The generated files ARE COMMITTED, like every other generated artefact in
/// this repo, and <c>--check</c> is what a gate or a build script runs to
/// refuse a tree where they are stale. Fix a stale file by rerunning the
/// generator, never by hand-patching it.
/// </para>
/// </remarks>
public static class Program
{
    public static int Main(string[] args)
    {
        var check = args.Contains("--check");
        var root = FindWindowsRoot();
        if (root is null)
        {
            Console.Error.WriteLine(
                "parfast-gen: could not find apps/parfast/windows above the working directory. "
                + "Run it from inside the repo.");
            return 2;
        }

        var strings = PickSource(root, "strings/en.json", out var stringsFrom);
        var overrides = ReadOverrides(root);
        var tokens = PickSource(root, "design/tokens.json", out var tokensFrom);
        if (strings is null || tokens is null)
        {
            Console.Error.WriteLine(
                "parfast-gen: neither apps/parfast/shared nor shared-bootstrap carries the input files. "
                + "One of them must, or there is nothing to generate from.");
            return 2;
        }

        Console.WriteLine($"parfast-gen: strings from {stringsFrom}");
        Console.WriteLine($"parfast-gen: tokens  from {tokensFrom}");
        // Two kinds of local entry, reported apart because they mean different
        // things. A REWORDING replaces a shared string that names macOS; it is a
        // platform split the mac lane should eventually own. A PENDING one is copy
        // the shared table does not carry yet, so it is visible only on Windows
        // and is a request for chip B, not a decision. Neither may grow quietly:
        // both lists are printed on every run and both are in this lane's handoff.
        if (overrides.Count > 0)
        {
            var shared = Pairs(strings).Select(p => p.Key).ToHashSet(StringComparer.Ordinal);
            var reworded = overrides.Keys.Where(shared.Contains).Order().ToList();
            var pending = overrides.Keys.Where(k => !shared.Contains(k)).Order().ToList();
            if (reworded.Count > 0)
            {
                Console.WriteLine($"parfast-gen: {reworded.Count} reworded for Windows: "
                                  + string.Join(", ", reworded));
            }

            if (pending.Count > 0)
            {
                Console.WriteLine($"parfast-gen: {pending.Count} PENDING adoption by the shared table: "
                                  + string.Join(", ", pending));
            }
        }

        List<(string Path, string Text)> outputs;
        try
        {
            outputs = BuildOutputs(root, strings, stringsFrom, tokens, tokensFrom, overrides);
        }
        catch (InvalidOperationException e)
        {
            // FAILING TO FIND IS FAILING, and it has to SAY SO. The first version
            // let a KeyNotFoundException out with a stack trace when the shared
            // tokens file arrived in a different shape, which named no key and
            // read like a crash rather than like a contract change.
            Console.Error.WriteLine($"parfast-gen: {e.Message}");
            return 2;
        }


        var stale = new List<string>();
        foreach (var (path, text) in outputs)
        {
            var existing = File.Exists(path) ? File.ReadAllText(path) : null;
            if (Normalise(existing) == Normalise(text))
            {
                Console.WriteLine($"  current  {Rel(root, path)}");
                continue;
            }

            if (check)
            {
                stale.Add(Rel(root, path));
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text, new UTF8Encoding(false));
            Console.WriteLine($"  written  {Rel(root, path)}");
        }

        if (stale.Count == 0)
        {
            return 0;
        }

        Console.Error.WriteLine(
            "parfast-gen --check: these generated files are stale. Rerun the generator "
            + "(dotnet run --project Parfast.Gen) and commit the result. Never hand-patch them:");
        foreach (var s in stale)
        {
            Console.Error.WriteLine($"  {s}");
        }

        return 1;
    }

    private static List<(string Path, string Text)> BuildOutputs(
        string root, JsonDocument strings, string stringsFrom, JsonDocument tokens, string tokensFrom,
        IReadOnlyDictionary<string, string> overrides)
    {
        var table = Pairs(strings).ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        foreach (var (key, value) in overrides)
        {
            table[key] = value;
        }

        return
        [
            (Path.Combine(root, "Parfast.ViewModels", "Generated", "Strings.g.cs"),
                StringsGenerator.CSharp(table, stringsFrom, overrides.Keys.ToHashSet(StringComparer.Ordinal))),
            (Path.Combine(root, "Parfast.ViewModels", "Generated", "Tokens.g.cs"),
                TokensGenerator.CSharp(tokens, tokensFrom)),
            (Path.Combine(root, "Parfast.App", "Strings", "en-US", "Resources.resw"),
                StringsGenerator.Resw(table, stringsFrom)),
        ];
    }

    /// <summary>
    /// Windows-local copy, if any is still needed.
    /// </summary>
    /// <remarks>
    /// THIS FILE IS NORMALLY ABSENT AND THAT IS THE GOAL. It existed for one day,
    /// while five shared strings said "Finder", "this Mac" and "the Finder menu"
    /// and chip B's file was not this lane's to edit. Those are PLATFORM SPLITS in
    /// the shared table now - a value is either a string or an object of platform
    /// keys - so the generator takes the windows arm out of the shared file and
    /// there is nothing left to override.
    /// <para>
    /// The hook stays because the next disagreement will arrive the same way, and
    /// a layer that prints itself on every run is a better answer than a lane
    /// quietly editing a file it does not own. If it comes back, it should leave
    /// again.
    /// </para>
    /// </remarks>
    private static IReadOnlyDictionary<string, string> ReadOverrides(string windowsRoot)
    {
        var path = Path.Combine(windowsRoot, "shared-bootstrap", "strings", "en-windows.json");
        if (!File.Exists(path))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        using var doc = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        });
        return Pairs(doc).ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
    }

    /// <summary>
    /// The shared file if chip B has landed it, else this lane's bootstrap copy.
    /// </summary>
    private static JsonDocument? PickSource(string windowsRoot, string relative, out string from)
    {
        var shared = Path.GetFullPath(Path.Combine(windowsRoot, "..", "shared", relative));
        var bootstrap = Path.Combine(windowsRoot, "shared-bootstrap", relative.Replace('/', Path.DirectorySeparatorChar));

        foreach (var candidate in new[] { shared, bootstrap })
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            from = candidate.Contains($"{Path.DirectorySeparatorChar}shared{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal)
                ? "apps/parfast/shared (chip B)"
                : "apps/parfast/windows/shared-bootstrap (this lane, until chip B lands)";
            return JsonDocument.Parse(File.ReadAllText(candidate), new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
        }

        from = string.Empty;
        return null;
    }

    private static string? FindWindowsRoot()
    {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir is not null)
        {
            if (dir.Name == "windows" && dir.Parent?.Name == "parfast")
            {
                return dir.FullName;
            }

            var nested = Path.Combine(dir.FullName, "apps", "parfast", "windows");
            if (Directory.Exists(nested))
            {
                return nested;
            }

            dir = dir.Parent;
        }

        return null;
    }

    private static string Rel(string root, string path) =>
        Path.GetRelativePath(root, path).Replace('\\', '/');

    /// <summary>
    /// Line-ending insensitive compare. The generator writes the host's endings
    /// and the box is Windows, so a byte compare would call every file stale on
    /// whichever host did not write it last.
    /// </summary>
    private static string Normalise(string? text) =>
        text?.Replace("\r\n", "\n", StringComparison.Ordinal).TrimEnd() ?? string.Empty;

    internal static string Pascal(string key)
    {
        var sb = new StringBuilder(key.Length);
        var upper = true;
        foreach (var c in key)
        {
            if (c is '.' or '_' or '-')
            {
                upper = true;
                continue;
            }

            sb.Append(upper ? char.ToUpperInvariant(c) : c);
            upper = false;
        }

        var name = sb.ToString();
        return name.Length > 0 && char.IsDigit(name[0]) ? "N" + name : name;
    }

    internal static string Literal(string value) =>
        "\"" + value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal)
        + "\"";

    internal static string Header(string from, string tool) => $"""
// <auto-generated>
// GENERATED by apps/parfast/windows/Parfast.Gen ({tool}). DO NOT EDIT.
// Source: {from}
// Regenerate:  dotnet run --project Parfast.Gen
// Verify:      dotnet run --project Parfast.Gen -- --check
// A hand edit here is undone by the next regeneration, in silence.
// </auto-generated>

""";

    /// <summary>
    /// The copy table's key and value pairs, from either shape of the file.
    /// </summary>
    /// <remarks>
    /// TWO SHAPES, and reading only one of them is a silent failure rather than a
    /// loud one. This lane's bootstrap copy is a flat top-level map; chip B's real
    /// file nests the table under a <c>"strings"</c> object beside its
    /// <c>_about</c> and <c>_version</c> metadata. A reader that knows only the
    /// flat shape finds ZERO string properties in the nested one and emits an
    /// empty class, so the failure arrives as forty "Strings does not contain a
    /// definition for" errors rather than as anything naming the file. So: the
    /// nested object wins when it is there, and an EMPTY result is refused
    /// outright, because a copy table with no copy in it is never what anyone
    /// meant.
    /// </remarks>
    internal static IEnumerable<KeyValuePair<string, string>> Pairs(JsonDocument doc)
    {
        var root = doc.RootElement;
        if (root.TryGetProperty("strings", out var nested) && nested.ValueKind == JsonValueKind.Object)
        {
            root = nested;
        }

        var found = 0;
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var property in root.EnumerateObject())
        {
            if (property.Name.StartsWith('_'))
            {
                continue;
            }

            switch (property.Value.ValueKind)
            {
                case JsonValueKind.String:
                    found++;
                    pairs.Add(new KeyValuePair<string, string>(
                        property.Name, property.Value.GetString() ?? string.Empty));
                    break;

                case JsonValueKind.Object:
                    // A PLATFORM SPLIT: {"mac": "Reveal in Finder", "windows":
                    // "Show in File Explorer"}. Five strings in the shared table
                    // name one platform's shell by name, and a split is how the
                    // table says so rather than leaving each app to reword it
                    // locally.
                    //
                    // A split that does not carry THIS platform's key is a
                    // REFUSAL, never a fallback to the other one's wording: the
                    // whole point of splitting the key was that the other
                    // platform's words are wrong here, so quietly using them
                    // would reintroduce the defect the split exists to fix, in
                    // silence. Same rule as the empty-table refusal below.
                    if (!property.Value.TryGetProperty(Platform, out var mine)
                        || mine.ValueKind != JsonValueKind.String)
                    {
                        var carried = string.Join(", ", property.Value.EnumerateObject()
                            .Where(p => !p.Name.StartsWith('_'))
                            .Select(p => p.Name));
                        throw new InvalidOperationException(
                            $"\"{property.Name}\" is a platform split carrying [{carried}] and not "
                            + $"\"{Platform}\". A split is refused rather than falling back to "
                            + "another platform's wording: the reason the key was split is that "
                            + "the other platform's words are wrong here.");
                    }

                    found++;
                    pairs.Add(new KeyValuePair<string, string>(
                        property.Name, mine.GetString() ?? string.Empty));
                    break;
            }
        }

        if (found == 0)
        {
            throw new InvalidOperationException(
                "the strings file carries no string values, at the top level or under a "
                + "\"strings\" object. Failing to find is failing: an empty copy table would "
                + "compile into an empty class and surface as errors that name no file.");
        }

        return pairs;
    }

    internal static string Invariant(double value) => value.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Which side of a platform split this generator takes.
    /// </summary>
    /// <remarks>
    /// A constant and not a switch: this generator only ever builds the Windows
    /// app, and a flag would invite somebody to generate the mac lane's copy into
    /// this tree by accident.
    /// </remarks>
    internal const string Platform = "windows";
}
