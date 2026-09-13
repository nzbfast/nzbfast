using System.Text.Json;
using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

/// <summary>
/// The one serializer configuration for the FFI boundary.
/// </summary>
/// <remarks>
/// Snake_case property naming is set here as well as spelled out in a
/// <c>JsonPropertyName</c> on every member. The attributes are the contract
/// (they survive a rename refactor of a C# property, which the policy alone
/// would silently change into a different wire name), and the policy catches
/// a member somebody adds without one.
/// <para>
/// <c>WhenWritingNull</c> matters to the contract rather than to byte count:
/// several fields are "one of" arms, and an explicit <c>"size": null</c>
/// beside a <c>"count": 2000</c> is a different document from one carrying
/// only the count.
/// </para>
/// </remarks>
public static class ParfastJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static JsonSerializerOptions Indented { get; } = new(Options) { WriteIndented = true };

    public static string Write<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static T? Read<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);

    /// <summary>
    /// Reads a snapshot the way a UI poll must: a malformed or truncated
    /// document returns null rather than throwing into the timer tick.
    /// </summary>
    public static T? TryRead<T>(string? json, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            error = "empty response";
            return default;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(json, Options);
        }
        catch (JsonException e)
        {
            error = e.Message;
            return default;
        }
    }
}
