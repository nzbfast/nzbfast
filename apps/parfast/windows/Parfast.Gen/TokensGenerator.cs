using System.Text;
using System.Text.Json;

namespace Parfast.Gen;

/// <summary>
/// Generates the design tokens as C#: the block-state palette in both themes
/// with its wire codes and legend labels, the recovery band, the status pill,
/// the surfaces and text, and the spacing, radius, size and motion scales.
/// </summary>
/// <remarks>
/// THE SHAPE IS CHIP B'S, and it is better than the one this lane started with.
/// Each block state carries not only its two colours but its WIRE CODE and its
/// LEGEND LABEL, which means the mapping from `survey.block_runs`'s integers to a
/// colour and to a word is stated once, in the shared file, for both apps. This
/// generator therefore also emits the legend and the code table, and the
/// hand-written copies of both on the Windows side were deleted: a legend that
/// can disagree with the strip it explains is worse than no legend.
/// <para>
/// Colours come out as ARGB unsigned integers rather than strings, so the XAML
/// side constructs a Color with no runtime parse and a malformed hex in the
/// shared file fails HERE, at generation time, with the key that is wrong named.
/// FAILING TO FIND IS FAILING: a group this generator cannot locate is a
/// SystemExit naming the group and the file, never a quietly smaller palette.
/// The first version threw a bare KeyNotFoundException with a stack trace when
/// chip B's real file arrived, which said nothing about which key was missing.
/// </para>
/// </remarks>
public static class TokensGenerator
{
    public static string CSharp(JsonDocument doc, string from)
    {
        var root = doc.RootElement;
        var color = Group(root, "color", from);

        var sb = new StringBuilder(Program.Header(from, "tokens"));
        sb.AppendLine("namespace Parfast.ViewModels;");
        sb.AppendLine();
        sb.AppendLine("/// <summary>One drawn colour, as an unpremultiplied ARGB value.</summary>");
        sb.AppendLine("public readonly record struct TokenColor(byte A, byte R, byte G, byte B)");
        sb.AppendLine("{");
        sb.AppendLine("    public uint Argb => ((uint)A << 24) | ((uint)R << 16) | ((uint)G << 8) | B;");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("/// <summary>One block state: its two colours, its wire code and its legend word.</summary>");
        sb.AppendLine("public sealed record BlockToken(int Code, string Label, TokenColor Light, TokenColor Dark)");
        sb.AppendLine("{");
        sb.AppendLine("    public TokenColor For(bool dark) => dark ? Dark : Light;");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("/// <summary>The design tokens of apps/parfast/shared/design/tokens.json.</summary>");
        sb.AppendLine("public static class Tokens");
        sb.AppendLine("{");

        EmitBlocks(sb, Group(color, "block", from));
        EmitPairGroup(sb, Group(color, "recovery", from), "Recovery",
            "The band under the block map: what is available, the spare, and the needed marker.");
        EmitPairGroup(sb, Group(color, "map", from), "Map",
            "How the block map grounds a run, as opposed to what names its state.");
        EmitPairGroup(sb, Group(color, "status", from), "Status",
            "Status-pill grounds and the text that goes on them.");
        EmitPairGroup(sb, Group(color, "surface", from), "Surface", "Cards, wells, borders and the drop zone.");
        EmitPairGroup(sb, Group(color, "text", from), "Text", "The three text levels.");
        EmitPairGroup(sb, Group(color, "accent", from), "Accent", "The accent colour.");

        EmitNumbers(sb, root, "spacing", "Spacing", "The spacing scale.");
        EmitNumbers(sb, root, "radius", "Radius", "Corner radii.");
        EmitNumbers(sb, root, "size", "Size", "Fixed sizes both apps must agree on.");
        EmitNumbers(sb, root, "motion", "Motion", "Animation durations, in milliseconds.");

        sb.AppendLine("}");
        return sb.ToString();
    }

    private static JsonElement Group(JsonElement parent, string name, string from)
    {
        if (parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var group))
        {
            return group;
        }

        throw new InvalidOperationException(
            $"the tokens file from {from} has no \"{name}\" group. This generator does not "
            + "emit a smaller palette when a group goes missing, because a screen drawn from "
            + "half a palette looks like a design decision. Add the group, or teach this "
            + "generator that it moved.");
    }

    private static void EmitBlocks(StringBuilder sb, JsonElement blocks)
    {
        sb.AppendLine("    /// <summary>");
        sb.AppendLine("    /// The block-state palette. Each entry carries the wire code from");
        sb.AppendLine("    /// <c>survey.block_runs</c> and the word the legend shows, so the strip, the");
        sb.AppendLine("    /// legend and the hover text cannot disagree.");
        sb.AppendLine("    /// </summary>");
        sb.AppendLine("    public static class Block");
        sb.AppendLine("    {");

        var emitted = new List<(int Code, string Name)>();
        foreach (var state in blocks.EnumerateObject())
        {
            if (state.Name.StartsWith('_') || state.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var name = Program.Pascal(state.Name);
            var code = state.Value.GetProperty("code").GetInt32();
            var label = state.Value.GetProperty("label").GetString() ?? name;
            var (la, lr, lg, lb) = ParseHex(state.Value.GetProperty("light").GetString(), state.Name);
            var (da, dr, dg, db) = ParseHex(state.Value.GetProperty("dark").GetString(), state.Name);

            sb.AppendLine($"        public static BlockToken {name} {{ get; }} = new(");
            sb.AppendLine($"            {code}, {Program.Literal(label)}, "
                          + $"new({la}, {lr}, {lg}, {lb}), new({da}, {dr}, {dg}, {db}));");
            sb.AppendLine();
            emitted.Add((code, name));
        }

        sb.AppendLine("        /// <summary>Every state, in wire-code order. The legend draws this.</summary>");
        sb.AppendLine("        public static System.Collections.Generic.IReadOnlyList<BlockToken> All { get; } =");
        sb.AppendLine("        [");
        foreach (var (_, name) in emitted.OrderBy(e => e.Code))
        {
            sb.AppendLine($"            {name},");
        }

        sb.AppendLine("        ];");
        sb.AppendLine();
        sb.AppendLine("        /// <summary>The token for a wire code, or Pending for one this build does not know.</summary>");
        sb.AppendLine("        public static BlockToken ForCode(int code)");
        sb.AppendLine("        {");
        sb.AppendLine("            foreach (var token in All)");
        sb.AppendLine("            {");
        sb.AppendLine("                if (token.Code == code)");
        sb.AppendLine("                {");
        sb.AppendLine("                    return token;");
        sb.AppendLine("                }");
        sb.AppendLine("            }");
        sb.AppendLine();
        sb.AppendLine("            return Pending;");
        sb.AppendLine("        }");
        sb.AppendLine("    }");
        sb.AppendLine();
    }

    private static void EmitPairGroup(StringBuilder sb, JsonElement group, string className, string summary)
    {
        sb.AppendLine($"    /// <summary>{summary}</summary>");
        sb.AppendLine($"    public static class {className}");
        sb.AppendLine("    {");
        foreach (var entry in group.EnumerateObject())
        {
            if (entry.Name.StartsWith('_') || entry.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var name = Program.Pascal(entry.Name);
            var (la, lr, lg, lb) = ParseHex(entry.Value.GetProperty("light").GetString(), entry.Name);
            var (da, dr, dg, db) = ParseHex(entry.Value.GetProperty("dark").GetString(), entry.Name);
            sb.AppendLine($"        public static TokenColor {name}(bool dark) => dark");
            sb.AppendLine($"            ? new({da}, {dr}, {dg}, {db})");
            sb.AppendLine($"            : new({la}, {lr}, {lg}, {lb});");
            sb.AppendLine();
        }

        sb.AppendLine("    }");
        sb.AppendLine();
    }

    private static void EmitNumbers(StringBuilder sb, JsonElement root, string key, string className, string summary)
    {
        if (!root.TryGetProperty(key, out var scale))
        {
            return;
        }

        sb.AppendLine($"    /// <summary>{summary}</summary>");
        sb.AppendLine($"    public static class {className}");
        sb.AppendLine("    {");
        foreach (var p in scale.EnumerateObject())
        {
            if (p.Name.StartsWith('_'))
            {
                continue;
            }

            switch (p.Value.ValueKind)
            {
                case JsonValueKind.Number:
                    sb.AppendLine($"        public const double {Program.Pascal(p.Name)} = "
                                  + $"{Program.Invariant(p.Value.GetDouble())};");
                    break;
                case JsonValueKind.True:
                case JsonValueKind.False:
                    sb.AppendLine($"        public const bool {Program.Pascal(p.Name)} = "
                                  + $"{(p.Value.GetBoolean() ? "true" : "false")};");
                    break;
            }
        }

        sb.AppendLine("    }");
        sb.AppendLine();
    }

    /// <summary>
    /// #RRGGBB or #RRGGBBAA. The trailing-alpha spelling is the CSS order and not
    /// WinUI's #AARRGGBB, which is exactly the sort of thing that silently draws
    /// the wrong colour, so the order is asserted here in one place and nowhere
    /// else. Chip B's file uses it for the translucent borders and drop fills.
    /// </summary>
    private static (byte A, byte R, byte G, byte B) ParseHex(string? hex, string key)
    {
        if (hex is null || !hex.StartsWith('#') || (hex.Length != 7 && hex.Length != 9))
        {
            throw new InvalidOperationException(
                $"token \"{key}\" is {(hex is null ? "absent" : $"\"{hex}\"")}, which is not "
                + "#RRGGBB or #RRGGBBAA.");
        }

        byte Part(int at) => Convert.ToByte(hex.Substring(at, 2), 16);

        return (hex.Length == 9 ? Part(7) : (byte)255, Part(1), Part(3), Part(5));
    }
}
