using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

/// <summary>
/// Maps the snake_case enum strings of the FFI JSON contract
/// (research/PLAN-PARFAST-GUI-2026-09-12.md section 4.5) to C# enum
/// members, and back.
/// </summary>
/// <remarks>
/// Written rather than taken from the framework for one reason that
/// matters: the built-in converter THROWS on a value it does not know, and
/// the contract says chip A may add enum values without renaming any. The
/// UI polls a snapshot up to ten times a second, so a core that grows a
/// new phase would turn every poll into an exception. Here an unrecognised
/// value becomes the enum's <c>Unknown</c> member when it has one, and the
/// screens treat Unknown as "no opinion" rather than as an error.
/// <para>
/// .NET 8 has no attribute form of the framework converter that takes a
/// naming policy, and <c>JsonStringEnumMemberName</c> is .NET 9, so the
/// mapping is done here from the member name itself: PascalCase to
/// snake_case on write, and a case-and-underscore-insensitive compare on
/// read. That keeps the C# names and the wire names in one place, which is
/// the enum declaration.
/// </para>
/// </remarks>
public sealed class SnakeCaseEnumConverter<T> : JsonConverter<T> where T : struct, Enum
{
    private static readonly Dictionary<string, T> ByWireName = BuildReadMap();
    private static readonly Dictionary<T, string> ToWireName = BuildWriteMap();
    private static readonly T? UnknownMember = FindUnknown();

    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return UnknownMember ?? default;
        }

        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"{typeof(T).Name} must be a JSON string, saw {reader.TokenType}.");
        }

        var raw = reader.GetString() ?? string.Empty;
        if (ByWireName.TryGetValue(Normalise(raw), out var value))
        {
            return value;
        }

        if (UnknownMember is { } unknown)
        {
            return unknown;
        }

        throw new JsonException(
            $"{typeof(T).Name} has no member for \"{raw}\" and no Unknown member to fall back to.");
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(ToWireName.TryGetValue(value, out var name) ? name : value.ToString());
    }

    /// <summary>The wire spelling of one member, for callers that build a query by hand.</summary>
    public static string WireName(T value) =>
        ToWireName.TryGetValue(value, out var name) ? name : value.ToString();

    private static string Normalise(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c is '_' or '-' or ' ')
            {
                continue;
            }

            sb.Append(char.ToLowerInvariant(c));
        }

        return sb.ToString();
    }

    private static string SnakeCase(string pascal)
    {
        var sb = new StringBuilder(pascal.Length + 4);
        for (var i = 0; i < pascal.Length; i++)
        {
            var c = pascal[i];
            if (char.IsUpper(c) && i > 0)
            {
                sb.Append('_');
            }

            sb.Append(char.ToLowerInvariant(c));
        }

        return sb.ToString();
    }

    private static Dictionary<string, T> BuildReadMap()
    {
        var map = new Dictionary<string, T>(StringComparer.Ordinal);
        foreach (var name in Enum.GetNames<T>())
        {
            map[Normalise(name)] = Enum.Parse<T>(name);
        }

        return map;
    }

    private static Dictionary<T, string> BuildWriteMap()
    {
        var map = new Dictionary<T, string>();
        foreach (var name in Enum.GetNames<T>())
        {
            map[Enum.Parse<T>(name)] = SnakeCase(name);
        }

        return map;
    }

    private static T? FindUnknown() =>
        typeof(T).GetField("Unknown", BindingFlags.Public | BindingFlags.Static) is null
            ? null
            : Enum.Parse<T>("Unknown");
}
