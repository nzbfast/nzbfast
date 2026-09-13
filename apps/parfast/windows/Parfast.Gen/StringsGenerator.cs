using System.Text;
using System.Text.Json;

namespace Parfast.Gen;

/// <summary>
/// Writes the copy table twice: a C# class the view models and the tests use,
/// and a .resw the XAML uses through <c>x:Uid</c>.
/// </summary>
/// <remarks>
/// TWO OUTPUTS, ONE SOURCE, which is the point. A .resw alone cannot be read by
/// the view models (they are a plain net8.0 library with no WinRT resource
/// loader, deliberately, so they test on any host), and a C# class alone throws
/// away x:Uid, which is the only localisation mechanism XAML has. Generating
/// both from one JSON means the two can never disagree, which is what a
/// hand-written pair would eventually do.
/// </remarks>
public static class StringsGenerator
{
    /// <summary>
    /// The two members the generated class carries besides its constants: the
    /// named-placeholder filler, and the whole table for the parity tests.
    /// </summary>
    /// <remarks>
    /// THE PLACEHOLDERS ARE NAMED, NOT POSITIONAL. The shared table spells them
    /// {first}, {ok}, {reason}, which is the right choice for a table two apps and
    /// sixteen locales share - a translator can reorder a sentence without
    /// renumbering it. It is also why string.Format cannot be used: it reads
    /// {first} as a malformed index and throws at runtime, on the one screen that
    /// string appears on.
    /// </remarks>
    private const string HelperSource = """
        /// <summary>
        /// Fills the named placeholders of a copy string:
        /// <c>Fill(template, "first", 1, "last", 9)</c>.
        /// </summary>
        /// <remarks>
        /// An unfilled placeholder is LEFT IN PLACE rather than blanked, so a
        /// caller that forgot an argument shows "{reason}" on screen: visible,
        /// greppable and obviously a bug, rather than a sentence with a hole in it
        /// that reads like intended copy.
        /// <para>
        /// Invariant culture, because the arguments arrive already formatted by
        /// <c>Fmt</c>, which has decided the separators and the units. A second
        /// culture pass here would reformat a number somebody already formatted.
        /// </para>
        /// </remarks>
        public static string Fill(string template, params object[] pairs)
        {
            if (pairs.Length % 2 != 0)
            {
                throw new System.ArgumentException("Fill takes name and value pairs", nameof(pairs));
            }

            var text = template;
            for (var i = 0; i + 1 < pairs.Length; i += 2)
            {
                var value = System.Convert.ToString(
                    pairs[i + 1], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
                text = text.Replace("{" + pairs[i] + "}", value, System.StringComparison.Ordinal);
            }

            return text;
        }

        /// <summary>Every key and value, for the parity tests in Parfast.Tests.</summary>
        public static System.Collections.Generic.IReadOnlyDictionary<string, string> All { get; } =
            new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.Ordinal)
            {
        """;

    public static string CSharp(
        IReadOnlyDictionary<string, string> table, string from, IReadOnlySet<string> overridden)
    {
        var sb = new StringBuilder(Program.Header(from, "strings"));
        sb.AppendLine("namespace Parfast.ViewModels;");
        sb.AppendLine();
        sb.AppendLine("/// <summary>The copy table. Every user-visible string in the app is here.</summary>");
        sb.AppendLine("public static class Strings");
        sb.AppendLine("{");

        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in table.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            var name = Program.Pascal(key);
            if (names.TryGetValue(name, out var clash))
            {
                throw new InvalidOperationException(
                    $"Keys \"{clash}\" and \"{key}\" both become the C# name {name}. "
                    + "Rename one in the shared strings file.");
            }

            names[name] = key;
            sb.AppendLine($"    /// <summary>{System.Security.SecurityElement.Escape(value)}</summary>");
            if (overridden.Contains(key))
            {
                sb.AppendLine("    /// <remarks>Reworded for Windows; see "
                              + "shared-bootstrap/strings/en-windows.json.</remarks>");
            }

            sb.AppendLine($"    public const string {name} = {Program.Literal(value)};");
            sb.AppendLine();
        }

        sb.AppendLine(HelperSource);

        foreach (var (key, value) in table.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            sb.AppendLine($"            [{Program.Literal(key)}] = {Program.Literal(value)},");
        }

        sb.AppendLine("        };");
        sb.AppendLine();
        sb.AppendLine("""
                          /// <summary>
                          /// True when a copy string is deliberately blank on this platform.
                          /// </summary>
                          /// <remarks>
                          /// A platform split may carry an EMPTY arm, which means "this line does
                          /// not apply here" - settings.integration.win11_note has one on mac,
                          /// because there is no Show more options menu there. A caller omits the
                          /// row rather than rendering a blank one, and the copy test allows an
                          /// empty value only for a key this answers true for, so an ACCIDENTAL
                          /// blank is still caught.
                          /// </remarks>
                          public static bool IsBlankHere(string key) =>
                              All.TryGetValue(key, out var value) && value.Length == 0;
                      """);
        sb.AppendLine("}");
        return sb.ToString();
    }

    public static string Resw(IReadOnlyDictionary<string, string> table, string from)
    {
        var sb = new StringBuilder();
        sb.AppendLine("""<?xml version="1.0" encoding="utf-8"?>""");
        sb.AppendLine($"<!-- GENERATED by apps/parfast/windows/Parfast.Gen. DO NOT EDIT. Source: {from} -->");
        sb.AppendLine("<root>");

        // The resheader block a .resw must carry. WinUI reads the values, not
        // the schema, but the ResW compiler refuses a file without them.
        sb.AppendLine("""  <resheader name="resmimetype"><value>text/microsoft-resx</value></resheader>""");
        sb.AppendLine("""  <resheader name="version"><value>2.0</value></resheader>""");
        sb.AppendLine("""  <resheader name="reader"><value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value></resheader>""");
        sb.AppendLine("""  <resheader name="writer"><value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value></resheader>""");

        // UNDERSCORES, NOT SLASHES, AND THE REASON IS A BUILD FAILURE RATHER THAN
        // A PREFERENCE. A dot cannot stay in a resw name (x:Uid reads the part
        // after the last dot as a PROPERTY), so the separator has to change to
        // something. It was a slash until 12 Sep 2026, which reads better and is
        // what WinUI's own resource paths look like - and a slash is MRT's SCOPE
        // separator, so a key that is also the prefix of another key declares one
        // name as both a resource and a scope, which makepri refuses outright:
        //
        //   PRI175: An entity was defined as both resource and scope
        //   PRI278: 'Resources/settings/integration' or one of its parents is
        //           defined as both resource and scope
        //
        // The shared table has four such pairs today (create.sources,
        // mock.banner, settings.integration and their children), every one of
        // them a perfectly reasonable key, and more will arrive - so the
        // encoding has to be the thing that cannot clash rather than the table
        // having to avoid a shape nobody would think to avoid. An underscore is
        // not a separator to MRT, so no hierarchy is declared and no pair can
        // collide structurally. This was invisible until the app was built on
        // Windows for the first time, because makepri is the only thing that
        // reads this file.
        //
        // THE ONE REMAINING WAY TO COLLIDE is two distinct keys whose encodings
        // are equal (`a.b_c` and `a_b.c`), so that is checked rather than
        // assumed: a silent overwrite here would drop a string from the app with
        // nothing to see.
        var seen = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in table.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            var name = key.Replace('.', '_');
            if (seen.TryGetValue(name, out var first))
            {
                throw new InvalidOperationException(
                    $"parfast-gen: the keys '{first}' and '{key}' both encode to the resw name "
                    + $"'{name}', so one would silently replace the other. Rename one in the "
                    + "shared strings file.");
            }

            seen[name] = key;
            sb.AppendLine($"""  <data name="{System.Security.SecurityElement.Escape(name)}" xml:space="preserve">""");
            sb.AppendLine($"    <value>{System.Security.SecurityElement.Escape(value)}</value>");
            sb.AppendLine("  </data>");
        }

        sb.AppendLine("</root>");
        return sb.ToString();
    }
}
