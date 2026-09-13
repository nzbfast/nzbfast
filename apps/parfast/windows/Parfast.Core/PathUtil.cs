namespace Parfast.Core;

/// <summary>
/// Path splitting that understands WINDOWS separators whatever host it runs on.
/// </summary>
/// <remarks>
/// WHY THIS EXISTS, because <see cref="Path.GetFileName(string?)"/> looks like it
/// would do. Every path in the FFI contract is an absolute path on the machine
/// the core runs on, and in production that machine is Windows. But
/// Parfast.Core, Parfast.ViewModels and Parfast.Tests are plain net8.0 and their
/// tests run on the dev Mac, where <c>Path.DirectorySeparatorChar</c> is '/' and
/// <c>Path.GetFileName(@"C:\set\set.par2")</c> returns the WHOLE STRING. The
/// planner then names its volume file <c>C:\set\set.vol000+001.par2</c>, which is
/// wrong on the Mac and right on Windows, so the defect is invisible on the box
/// that ships and visible only in the tests. That is the worst shape a bug can
/// have, and it is why path handling on the FFI's strings goes through here and
/// not through <c>Path</c>.
/// </remarks>
public static class PathUtil
{
    private static readonly char[] Separators = ['\\', '/'];

    /// <summary>The last component, whichever separator the path uses.</summary>
    public static string FileName(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        var trimmed = path.TrimEnd(Separators);
        var at = trimmed.LastIndexOfAny(Separators);
        return at < 0 ? trimmed : trimmed[(at + 1)..];
    }

    /// <summary>Everything before the last component, or an empty string.</summary>
    public static string DirectoryName(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        var trimmed = path.TrimEnd(Separators);
        var at = trimmed.LastIndexOfAny(Separators);
        return at <= 0 ? string.Empty : trimmed[..at];
    }

    /// <summary>The last extension including the dot, lowercased, or an empty string.</summary>
    public static string Extension(string? path)
    {
        var name = FileName(path);
        var dot = name.LastIndexOf('.');
        return dot <= 0 ? string.Empty : name[dot..];
    }

    public static string FileNameWithoutExtension(string? path)
    {
        var name = FileName(path);
        var dot = name.LastIndexOf('.');
        return dot <= 0 ? name : name[..dot];
    }

    /// <summary>Joins with the separator the left side already uses, defaulting to backslash.</summary>
    public static string Combine(string directory, string name)
    {
        if (string.IsNullOrEmpty(directory))
        {
            return name;
        }

        var separator = directory.Contains('\\', StringComparison.Ordinal) ? '\\'
            : directory.Contains('/', StringComparison.Ordinal) ? '/'
            : '\\';
        return directory.TrimEnd(Separators) + separator + name;
    }

    /// <summary>Splits a path into its components, dropping empties.</summary>
    public static string[] Split(string path) =>
        path.Split(Separators, StringSplitOptions.RemoveEmptyEntries);
}
