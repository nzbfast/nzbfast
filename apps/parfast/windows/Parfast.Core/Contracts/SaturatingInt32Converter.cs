using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Parfast.Core.Contracts;

/// <summary>
/// Reads every <c>int</c> on the FFI boundary SATURATING: a number past
/// <see cref="int.MaxValue"/> reads as <see cref="int.MaxValue"/> (and below
/// <see cref="int.MinValue"/> as that) instead of throwing.
/// </summary>
/// <remarks>
/// WHY A CONVERTER AND NOT WIDER FIELDS. The core sends block counts, recovery
/// counts, per-file block tallies and the block map's run lengths as u64 and
/// usize; this contract reads them as <c>int</c>, and one value past the range
/// made System.Text.Json throw, which failed the WHOLE snapshot or preview - a
/// stale screen for every job, from one field of one job. Widening each field
/// to <c>long</c> ripples through the planner, the block map and every screen
/// that does arithmetic on them; PAR2 itself caps blocks at 32,768 source and
/// 65,535 recovery, so a value this large is a damaged set or a core bug, and a
/// clamped figure on one row is the right blast radius for it.
/// <para>
/// Registered once in <see cref="ParfastJson.Options"/>, so it reaches every
/// <c>int</c>, <c>int?</c> and <c>int[]</c> element, including fields added
/// later. Writing is unchanged. Strings holding a number are read too, which
/// is what <see cref="JsonNumberHandling.AllowReadingFromString"/> gave before a
/// custom converter took the type over.
/// </para>
/// </remarks>
public sealed class SaturatingInt32Converter : JsonConverter<int>
{
    public override int Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            var text = reader.GetString();
            return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)
                ? Saturate(parsed)
                : throw new JsonException($"\"{text}\" is not a number.");
        }

        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException($"Expected a number, found {reader.TokenType}.");
        }

        if (reader.TryGetInt32(out var value))
        {
            return value;
        }

        if (reader.TryGetInt64(out var wide))
        {
            return wide > int.MaxValue ? int.MaxValue : int.MinValue;
        }

        // Past even a long (a u64 above 2^63), or a fraction.
        return Saturate(reader.GetDouble());
    }

    public override void Write(Utf8JsonWriter writer, int value, JsonSerializerOptions options) =>
        writer.WriteNumberValue(value);

    private static int Saturate(double value) =>
        double.IsNaN(value) ? 0
        : value >= int.MaxValue ? int.MaxValue
        : value <= int.MinValue ? int.MinValue
        : (int)value;
}
