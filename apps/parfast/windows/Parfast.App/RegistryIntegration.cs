using Microsoft.Win32;
using Parfast.ViewModels;

namespace Parfast.App;

/// <summary>
/// The file associations and the Explorer context-menu verbs of plan section 6.2,
/// written as HKCU registry entries.
/// </summary>
/// <remarks>
/// HKCU ONLY, NEVER HKLM, and that is a decision rather than a convenience. HKLM
/// changes the association for every account on the machine and needs elevation,
/// so the app would have to run elevated, and an elevated GUI writing "per user"
/// settings writes them into the elevating administrator's hive instead of the
/// user's. The installer writes the same keys in the same hive (see
/// packaging/windows/parfast-gui.iss) so the two cannot disagree, and uninstall
/// removes them.
/// <para>
/// WINDOWS 11 PUTS THESE VERBS UNDER "Show more options". The modern menu needs a
/// sparse-package IExplorerCommand handler, which the plan names as a v1.1 item
/// and this lane does NOT build. The Settings page says so in words
/// (settings.integration.win11_note) rather than leaving a user to wonder why the
/// item is not in the first menu - a separate line from the per-user note, because
/// they are two different facts and only one of them stops a bug report.
/// </para>
/// <para>
/// Every write is wrapped: a locked-down machine can deny HKCU\Software\Classes
/// through policy, and a toggle that throws would take the Settings page down with
/// it. A refused write leaves the switch reading the registry's answer, which is
/// off, so the UI tells the truth.
/// </para>
/// </remarks>
public sealed class RegistryIntegration : IShellIntegration
{
    private const string ProgId = "parfast.par2";
    private const string VerbVerify = "parfast.verify";
    private const string VerbCreate = "parfast.create";

    private static readonly string[] ContextTargets = ["*", "Directory"];

    public bool CanWrite => OperatingSystem.IsWindows();

    public bool IsAssociated(string extension)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey($@"Software\Classes\{extension}");
            return key?.GetValue(null) as string == ProgIdFor(extension);
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public bool IsContextMenuRegistered
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    $@"Software\Classes\*\shell\{VerbCreate}");
                return key is not null;
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    public void SetAssociation(string extension, bool on)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var progId = ProgIdFor(extension);
        try
        {
            if (!on)
            {
                // Only the POINTER is removed, not the ProgID: another extension
                // may still point at it, and deleting a live ProgID would break
                // that association instead of this one. A ProgID with nothing
                // pointing at it is inert.
                using var classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", writable: true);
                using var key = classes?.OpenSubKey(extension, writable: true);
                if (key?.GetValue(null) as string == progId)
                {
                    key.SetValue(null, string.Empty);
                }

                return;
            }

            WriteProgId(progId, DescriptionFor(extension));
            using var target = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{extension}");
            target?.SetValue(null, progId);
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException
                                     or IOException)
        {
            // Deliberately swallowed: see the remarks. The getter reads the
            // registry, so the switch falls back to off and says so.
        }
    }

    public void SetContextMenu(bool on)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            foreach (var target in ContextTargets)
            {
                var root = $@"Software\Classes\{target}\shell";
                if (!on)
                {
                    using var shell = Registry.CurrentUser.OpenSubKey(root, writable: true);
                    shell?.DeleteSubKeyTree(VerbVerify, throwOnMissingSubKey: false);
                    shell?.DeleteSubKeyTree(VerbCreate, throwOnMissingSubKey: false);
                    continue;
                }

                // Verify is offered on a FILE only. "Verify with parfast" on a
                // folder would have to guess which set in it was meant, and
                // guessing wrong on a right-click is worse than not offering it.
                if (target == "*")
                {
                    WriteVerb($@"{root}\{VerbVerify}", Strings.SettingsVerbVerify, "verify");
                }

                WriteVerb($@"{root}\{VerbCreate}", Strings.SettingsVerbCreate, "create");
            }
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException
                                     or IOException)
        {
        }
    }

    private static void WriteProgId(string progId, string description)
    {
        var exe = ExePath();
        using var key = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{progId}");
        key?.SetValue(null, description);
        using var icon = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{progId}\DefaultIcon");
        icon?.SetValue(null, $"\"{exe}\",0");
        using var command = Registry.CurrentUser.CreateSubKey(
            $@"Software\Classes\{progId}\shell\open\command");
        command?.SetValue(null, $"\"{exe}\" \"%1\"");
    }

    private static void WriteVerb(string path, string label, string mode)
    {
        var exe = ExePath();
        using var key = Registry.CurrentUser.CreateSubKey(path);
        key?.SetValue(null, label);
        key?.SetValue("Icon", $"\"{exe}\",0");
        using var command = Registry.CurrentUser.CreateSubKey($@"{path}\command");
        // The mode is passed as a switch so one exe serves both verbs. "%1" is
        // QUOTED in the stored value: an unquoted %1 loses everything after the
        // first space in a path, which is most of the Windows filesystem.
        command?.SetValue(null, $"\"{exe}\" --{mode} \"%1\"");
    }

    private static string ProgIdFor(string extension) => extension switch
    {
        ".par2" => ProgId,
        _ => "parfast" + extension.Replace(".", string.Empty, StringComparison.Ordinal),
    };

    private static string DescriptionFor(string extension) => extension switch
    {
        ".par2" => "PAR2 recovery set",
        ".sfv" => "Checksum file",
        ".md5" => "MD5 checksum file",
        ".sha1" => "SHA-1 checksum file",
        ".sha256" => "SHA-256 checksum file",
        _ => "parfast file",
    };

    private static string ExePath() =>
        Environment.ProcessPath ?? System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "parfast-gui.exe";
}
