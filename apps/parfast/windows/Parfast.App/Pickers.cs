using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Parfast.ViewModels;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Parfast.App;

/// <summary>File and folder pickers, and the two dialogs the app shows.</summary>
/// <remarks>
/// AN UNPACKAGED APP MUST GIVE A PICKER AN OWNER WINDOW. Without
/// <c>InitializeWithWindow</c> the picker throws COMException 0x80070005 at
/// ShowAsync, because there is no package identity for the shell to hang the
/// dialog on. That is the single most common way a WinUI 3 desktop app fails at
/// its first file open, and it is why every picker in this app goes through here.
/// <para>
/// A PICKER THAT THROWS ANSWERS "NOTHING PICKED". Every caller is an
/// <c>async void</c> click handler, where an exception escaping the await is
/// unhandled and takes the process down - and the process is the one running the
/// user's jobs. The shell refusing a dialog (policy, a broken shell extension, a
/// stale owner) is a cancelled pick, not a crash.
/// </para>
/// </remarks>
public static class Pickers
{
    /// <summary>The failures a WinRT dialog can raise at ShowAsync.</summary>
    internal static bool IsDialogFailure(Exception e) =>
        e is COMException or InvalidOperationException or ArgumentException or UnauthorizedAccessException;

    public static async Task<string?> PickFileAsync(UIElement owner, IReadOnlyList<string> extensions)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
        foreach (var extension in extensions)
        {
            picker.FileTypeFilter.Add(extension);
        }

        if (extensions.Count == 0)
        {
            picker.FileTypeFilter.Add("*");
        }

        Own(owner, picker);
        try
        {
            var file = await picker.PickSingleFileAsync();
            return file?.Path;
        }
        catch (Exception e) when (IsDialogFailure(e))
        {
            return null;
        }
    }

    public static async Task<IReadOnlyList<string>> PickFilesAsync(UIElement owner)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
        picker.FileTypeFilter.Add("*");
        Own(owner, picker);
        try
        {
            var files = await picker.PickMultipleFilesAsync();
            return files.Select(f => f.Path).ToList();
        }
        catch (Exception e) when (IsDialogFailure(e))
        {
            return [];
        }
    }

    public static async Task<string?> PickFolderAsync(UIElement owner)
    {
        var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
        picker.FileTypeFilter.Add("*");
        Own(owner, picker);
        try
        {
            var folder = await picker.PickSingleFolderAsync();
            return folder?.Path;
        }
        catch (Exception e) when (IsDialogFailure(e))
        {
            return null;
        }
    }

    public static async Task<string?> SaveFileAsync(
        UIElement owner, string suggestedName, string typeLabel, IReadOnlyList<string> extensions)
    {
        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.ComputerFolder,
            SuggestedFileName = suggestedName,
        };
        picker.FileTypeChoices.Add(typeLabel, extensions.ToList());
        Own(owner, picker);
        try
        {
            var file = await picker.PickSaveFileAsync();
            return file?.Path;
        }
        catch (Exception e) when (IsDialogFailure(e))
        {
            return null;
        }
    }

    private static void Own(UIElement owner, object picker)
    {
        var window = owner.XamlRoot?.ContentIslandEnvironment?.AppWindowId;
        var handle = window is { } id
            ? Win32Interop.GetWindowFromWindowId(id)
            : nint.Zero;
        if (handle != nint.Zero)
        {
            InitializeWithWindow.Initialize(picker, handle);
        }
    }
}

/// <summary>The two dialogs: a message, and a confirmation.</summary>
/// <remarks>
/// NEITHER THROWS, for the reason <see cref="Pickers"/> gives: their callers are
/// <c>async void</c> handlers. WinUI allows ONE ContentDialog open at a time and
/// raises a COMException for a second (the progress sheet is a ContentDialog, so
/// this is reachable by a job finishing under a confirmation), and a dialog with
/// no XamlRoot throws too. A message that could not be shown is dropped; a
/// confirmation that could not be asked answers NO, which is the safe reading
/// for every caller - nothing destructive happens without a yes.
/// </remarks>
public static class Dialogs
{
    public static async Task ShowAsync(UIElement owner, string title, string body)
    {
        try
        {
            await Build(owner, title, body, Strings.CommonClose, null).ShowAsync();
        }
        catch (Exception e) when (Pickers.IsDialogFailure(e))
        {
        }
    }

    /// <summary>True when the user chose the primary action; false if the dialog could not be shown.</summary>
    public static async Task<bool> ConfirmAsync(
        UIElement owner, string title, string body, string primary, string secondary) =>
        await TryConfirmAsync(owner, title, body, primary, secondary) == true;

    /// <summary>
    /// The user's answer, or NULL when the dialog could not be shown at all - for
    /// the one caller (closing the window) whose safe answer to "could not ask"
    /// is not simply no.
    /// </summary>
    public static async Task<bool?> TryConfirmAsync(
        UIElement owner, string title, string body, string primary, string secondary)
    {
        try
        {
            var dialog = Build(owner, title, body, secondary, primary);
            return await dialog.ShowAsync() == ContentDialogResult.Primary;
        }
        catch (Exception e) when (Pickers.IsDialogFailure(e))
        {
            return null;
        }
    }

    private static ContentDialog Build(
        UIElement owner, string title, string body, string close, string? primary)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new TextBlock { Text = body, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = close,
        };

        // XamlRoot is REQUIRED for a dialog in a desktop app: without it ShowAsync
        // throws "This element is not associated with a XamlRoot", which is the
        // dialog equivalent of the picker's owner-window rule above. It is null
        // until the owner has been loaded, so it is assigned only when it is
        // there - an unconditional assignment is also a nullable warning, which
        // this solution promotes to an error.
        if (owner.XamlRoot is { } root)
        {
            dialog.XamlRoot = root;
        }

        if (primary is not null)
        {
            dialog.PrimaryButtonText = primary;
            dialog.DefaultButton = ContentDialogButton.Primary;
        }

        return dialog;
    }
}
