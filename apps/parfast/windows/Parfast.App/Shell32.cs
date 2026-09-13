using System.Diagnostics;

namespace Parfast.App;

/// <summary>Opening a folder or selecting a file in Explorer.</summary>
public static class Shell32
{
    /// <summary>
    /// Opens Explorer on a path, selecting it when it is a file.
    /// </summary>
    /// <remarks>
    /// <c>explorer.exe /select,"path"</c> is the documented way to open a window
    /// with one item selected, and the comma with NO SPACE after /select is
    /// load-bearing: with a space Explorer treats the path as a second argument
    /// and opens the user's Documents folder instead, which looks like the button
    /// doing something random.
    /// <para>
    /// UseShellExecute is left true and the exit code is not read. Explorer
    /// returns before the window exists and its code says nothing about whether
    /// the window appeared, so there is nothing to check; a path that no longer
    /// exists simply opens its parent, which is the behaviour a user expects from
    /// Show in folder.
    /// </para>
    /// </remarks>
    public static void Reveal(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            var isFile = File.Exists(path);
            var arguments = isFile ? $"/select,\"{path}\"" : $"\"{path}\"";
            Process.Start(new ProcessStartInfo("explorer.exe", arguments) { UseShellExecute = true });
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // Nothing useful to do or say: the user asked for a window and did not
            // get one, and there is no second way to open Explorer.
        }
    }
}
