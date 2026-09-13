using System.Globalization;

namespace Parfast.ViewModels;

/// <summary>
/// Every number the app puts on screen goes through here.
/// </summary>
/// <remarks>
/// Plan section 5.7: sizes in BINARY units with thousands separators, figures
/// with tabular digits (the font side of that is in the XAML).
/// <para>
/// ON THE RATE FORMATTER, because this repo holds three copies of one under a
/// gate (tools/rate-format-gate.py, memory topic nzbfast-unit-convention):
/// this is a DIFFERENT PRODUCT. parfast has no dashboard to call into, no
/// daemon, and no unit_bits setting, so there is no bits arm here and never
/// will be. The thresholds are deliberately the canonical ones (whole MB/s
/// below 1000, two decimals of GB/s at or above it) so the two products never
/// disagree where a user could compare them, and this file carries only the
/// byte arm's unit strings, which is what keeps it from looking like a fourth
/// copy of that rule if apps/ is ever added to the gate's roster. Say so in a
/// handoff before adding a bits arm here; do not just add one.
/// </para>
/// </remarks>
public static class Fmt
{
    private static readonly string[] ByteUnits = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB"];

    /// <summary>A size in binary units: 4.31 GiB, 512 KiB, 900 bytes.</summary>
    public static string Bytes(long bytes)
    {
        if (bytes < 0)
        {
            return "0 bytes";
        }

        if (bytes < 1024)
        {
            return $"{bytes:N0} {ByteUnits[0]}";
        }

        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < ByteUnits.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        // Two decimals below ten, one below a hundred, none above: three
        // significant figures throughout, so a column of sizes has the same
        // width and the eye can compare them.
        var decimals = value < 10 ? 2 : value < 100 ? 1 : 0;
        var rounded = Math.Round(value, decimals).ToString("N" + decimals, CultureInfo.InvariantCulture);
        return $"{rounded} {ByteUnits[unit]}";
    }

    /// <summary>A byte count with separators and no unit scaling, for block counts.</summary>
    public static string Count(long n) => n.ToString("N0", CultureInfo.InvariantCulture);

    /// <summary>
    /// A file count with its noun, singular or plural.
    /// </summary>
    /// <remarks>
    /// The shared table carries BOTH forms - common.one_file and
    /// common.files_count - and using only the plural renders "1 files", which is
    /// the sort of wrongness a reader notices and a test does not. Returned with
    /// the noun attached rather than as a bare number, because which noun to use
    /// is the decision being made.
    /// </remarks>
    public static string FileCount(int files) =>
        files == 1 ? Strings.CommonOneFile : Strings.Fill(Strings.CommonFilesCount, "files", Count(files));

    /// <summary>A transfer rate. See the note in this class's remarks.</summary>
    public static string Rate(long bytesPerSecond)
    {
        if (bytesPerSecond <= 0)
        {
            return "0 MB/s";
        }

        var mb = bytesPerSecond / 1_000_000.0;
        return mb >= 1000
            ? string.Create(CultureInfo.InvariantCulture, $"{mb / 1000:N2} GB/s")
            : string.Create(CultureInfo.InvariantCulture, $"{Math.Round(mb):N0} MB/s");
    }

    /// <summary>A duration: 4.2 s, 1:23, 2:05:41.</summary>
    public static string Duration(long ms)
    {
        if (ms < 0)
        {
            return "0.0 s";
        }

        var t = TimeSpan.FromMilliseconds(ms);
        if (t.TotalSeconds < 60)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{t.TotalSeconds:0.0} s");
        }

        return t.TotalHours >= 1
            ? string.Create(CultureInfo.InvariantCulture,
                $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}")
            : string.Create(CultureInfo.InvariantCulture, $"{t.Minutes}:{t.Seconds:00}");
    }

    /// <summary>A percentage for a pill or a label: 43%, 99.98%.</summary>
    public static string Percent(double fraction0To1, int decimals = 0) =>
        (Math.Clamp(fraction0To1, 0, 1) * 100).ToString("F" + decimals, CultureInfo.InvariantCulture) + "%";

    /// <summary>A percentage already expressed 0..100.</summary>
    public static string Pct(double pct, int decimals = 2) =>
        pct.ToString("N" + decimals, CultureInfo.InvariantCulture) + "%";

    /// <summary>A wall clock time for the queue's Added column.</summary>
    public static string When(DateTimeOffset? when)
    {
        if (when is null)
        {
            return string.Empty;
        }

        var local = when.Value.ToLocalTime();
        return local.Date == DateTimeOffset.Now.Date
            ? local.ToString("HH:mm", CultureInfo.CurrentCulture)
            : local.ToString("d MMM HH:mm", CultureInfo.CurrentCulture);
    }

    /// <summary>
    /// Parses a size a user typed, accepting a unit suffix: 1M, 1 MiB, 768000,
    /// 4k. Returns null when it cannot be read, so the field can show the
    /// error rather than silently substituting a number.
    /// </summary>
    public static long? ParseSize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var s = text.Trim().Replace(",", string.Empty, StringComparison.Ordinal);
        var multiplier = 1L;
        var digits = s;

        foreach (var (suffix, scale) in Suffixes)
        {
            if (s.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                multiplier = scale;
                digits = s[..^suffix.Length].Trim();
                break;
            }
        }

        return double.TryParse(digits, NumberStyles.Float, CultureInfo.InvariantCulture, out var value)
               && value >= 0
            ? (long)(value * multiplier)
            : null;
    }

    // Longest suffix first: "MiB" must be tried before "M", or "1MiB" parses as
    // "1Mi" times a mega and fails on the leftover.
    private static readonly (string Suffix, long Scale)[] Suffixes =
    [
        ("bytes", 1),
        ("KiB", 1024), ("MiB", 1024L * 1024), ("GiB", 1024L * 1024 * 1024),
        ("KB", 1024), ("MB", 1024L * 1024), ("GB", 1024L * 1024 * 1024),
        ("K", 1024), ("M", 1024L * 1024), ("G", 1024L * 1024 * 1024),
        ("B", 1),
    ];
}
