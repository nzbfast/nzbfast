using System.Text.Json;
using System.Text.Json.Serialization;

namespace Parfast.App;

/// <summary>The window geometry as it is written to disk.</summary>
/// <remarks>
/// The bounds are the RESTORED (un-maximised) outer bounds in device pixels,
/// so un-maximising a window that reopened maximised gives back the size the
/// user actually had. <see cref="Maximised"/> carries the state separately.
/// </remarks>
public sealed record SavedWindowFrame
{
    [JsonPropertyName("x")] public int X { get; init; }

    [JsonPropertyName("y")] public int Y { get; init; }

    [JsonPropertyName("width")] public int Width { get; init; }

    [JsonPropertyName("height")] public int Height { get; init; }

    [JsonPropertyName("maximised")] public bool Maximised { get; init; }

    /// <summary>A frame with no size is not a frame. Guards a truncated write.</summary>
    [JsonIgnore] public bool IsUsable => Width > 0 && Height > 0;
}

/// <summary>
/// Where the remembered window lives: <c>%LOCALAPPDATA%\parfast\window.json</c>.
/// </summary>
/// <remarks>
/// NOT <c>ApplicationData.Current.LocalSettings</c>, which is the shape a WinUI
/// app reaches for first. This app is <c>WindowsPackageType=None</c> - unpackaged
/// and self-contained - so it has no package identity, and
/// <c>ApplicationData.Current</c> is documented to need one. Choosing the file
/// makes that question moot rather than load-bearing: the directory is the one
/// <see cref="MainWindow.QueueStorePath"/> already creates and writes, it works
/// with or without identity, and it can be deleted by hand to test the first-run
/// path - which <c>LocalSettings</c>, buried in a registry-backed store, cannot.
/// <para>
/// EVERY FAILURE HERE IS SILENT AND HARMLESS, deliberately. A window that does
/// not remember its size is a small disappointment; an app that will not start
/// because a roaming profile made its state directory unwritable is not. So a
/// load returns null and a save does nothing.
/// </para>
/// </remarks>
public static class WindowFrameStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    /// <summary>The file, or null when the state directory cannot be reached.</summary>
    public static string? Path()
    {
        try
        {
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "parfast");
            Directory.CreateDirectory(dir);
            return System.IO.Path.Combine(dir, "window.json");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    public static SavedWindowFrame? Load()
    {
        try
        {
            if (Path() is not { } path || !File.Exists(path))
            {
                return null;
            }

            var saved = JsonSerializer.Deserialize<SavedWindowFrame>(File.ReadAllText(path));
            return saved is { IsUsable: true } ? saved : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public static void Save(SavedWindowFrame frame)
    {
        if (!frame.IsUsable)
        {
            return;
        }

        try
        {
            if (Path() is { } path)
            {
                File.WriteAllText(path, JsonSerializer.Serialize(frame, Options));
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // See the class remarks: a forgotten window is not worth a crash.
        }
    }
}
