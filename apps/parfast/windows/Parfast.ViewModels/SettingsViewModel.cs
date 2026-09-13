using Parfast.Core;
using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>What the app can register itself for. Windows writes HKCU keys.</summary>
public interface IShellIntegration
{
    bool CanWrite { get; }

    bool IsAssociated(string extension);

    bool IsContextMenuRegistered { get; }

    void SetAssociation(string extension, bool on);

    void SetContextMenu(bool on);
}

/// <summary>Integration that does nothing, for the tests and for a non-Windows host.</summary>
public sealed class NoShellIntegration : IShellIntegration
{
    public bool CanWrite => false;

    public bool IsAssociated(string extension) => false;

    public bool IsContextMenuRegistered => false;

    public void SetAssociation(string extension, bool on)
    {
    }

    public void SetContextMenu(bool on)
    {
    }
}

/// <summary>
/// Settings (plan section 5.6). The DEFAULTS ARE THE CORE'S, so this class reads
/// them from pf_settings_get and writes the whole object back on any change.
/// </summary>
/// <remarks>
/// Writing the whole object rather than a key at a time is deliberate: the
/// contract has one setter, the object is small, and a per-key setter would have
/// to be kept in step with the record's members in three languages.
/// <para>
/// Integration is the one group that is NOT stored only in the core: registry
/// keys are the actual state, so the toggles read the registry and write both.
/// A settings file that says "associated" while the registry says otherwise is
/// the state that makes a user think the app is lying, so the registry wins on
/// read.
/// </para>
/// </remarks>
public sealed class SettingsViewModel : Observable
{
    private readonly ICoreClient _core;
    private readonly IShellIntegration _shell;
    private ParfastSettings _settings;
    private bool _loading;

    public SettingsViewModel(ICoreClient core, IShellIntegration? shell = null)
    {
        _core = core;
        _shell = shell ?? new NoShellIntegration();
        _settings = core.GetSettings();
        ResetCommand = new Command(Reset);
    }

    public Command ResetCommand { get; }

    public ParfastSettings Current => _settings;

    public bool CanIntegrate => _shell.CanWrite;

    // ---- General ----

    public bool VerifyThenRepair
    {
        get => _settings.General.OpenPar2 == "verify_repair";
        set => Update(_settings with
        {
            General = _settings.General with { OpenPar2 = value ? "verify_repair" : "verify" },
        });
    }

    public bool PurgeAfterRepair
    {
        get => _settings.General.PurgeAfterRepair;
        set => Update(_settings with
        {
            General = _settings.General with { PurgeAfterRepair = value },
        });
    }

    public bool KeepDamaged
    {
        get => _settings.General.KeepDamagedCopies;
        set => Update(_settings with
        {
            General = _settings.General with { KeepDamagedCopies = value },
        });
    }

    public bool Notifications
    {
        get => _settings.General.Notifications;
        set => Update(_settings with
        {
            General = _settings.General with { Notifications = value },
        });
    }

    public bool AutoCloseProgress
    {
        get => _settings.General.AutoCloseProgress;
        set => Update(_settings with
        {
            General = _settings.General with { AutoCloseProgress = value },
        });
    }

    // ---- Create defaults ----

    public string BlockAllocation
    {
        get => _settings.Create.BlockAllocation;
        set => Update(_settings with
        {
            Create = _settings.Create with { BlockAllocation = value },
        });
    }

    public string RecoveryAllocation
    {
        get => _settings.Create.RecoveryAllocation;
        set => Update(_settings with
        {
            Create = _settings.Create with { RecoveryAllocation = value },
        });
    }

    public VolumeScheme DefaultScheme
    {
        get => _settings.Create.Scheme;
        set => Update(_settings with { Create = _settings.Create with { Scheme = value } });
    }

    public bool StdNaming
    {
        get => _settings.Create.StdNaming;
        set => Update(_settings with { Create = _settings.Create with { StdNaming = value } });
    }

    public UnicodePolicy Unicode
    {
        get => _settings.Create.Unicode;
        set => Update(_settings with { Create = _settings.Create with { Unicode = value } });
    }

    public bool Overwrite
    {
        get => _settings.Create.Overwrite;
        set => Update(_settings with { Create = _settings.Create with { Overwrite = value } });
    }

    public bool ShowStdNaming => _core.Capabilities.StdNaming;

    public bool ShowUnicodePolicy => _core.Capabilities.UnicodePolicy;

    // ---- Performance ----

    public int ThreadCount
    {
        get => _settings.Performance.Threads ?? 0;
        set => Update(_settings with
        {
            Performance = _settings.Performance with { Threads = value <= 0 ? null : value },
        });
    }

    public bool AutomaticThreads
    {
        get => _settings.Performance.Threads is null;
        set => Update(_settings with
        {
            Performance = _settings.Performance with
            {
                Threads = value ? null : Environment.ProcessorCount,
            },
        });
    }

    public int MemoryMb
    {
        get => _settings.Performance.MemoryMb ?? 0;
        set => Update(_settings with
        {
            Performance = _settings.Performance with { MemoryMb = value <= 0 ? null : value },
        });
    }

    public bool FastSolver
    {
        get => _settings.Performance.FastSolver;
        set => Update(_settings with
        {
            Performance = _settings.Performance with { FastSolver = value },
        });
    }

    public bool LowPriority
    {
        get => _settings.Performance.LowPriority;
        set => Update(_settings with
        {
            Performance = _settings.Performance with { LowPriority = value },
        });
    }

    public bool ShowFastSolver => _core.Capabilities.FastSolver;

    public bool ShowLowPriority => _core.Capabilities.LowPriority;

    // ---- Integration. The registry is the truth; see the remarks. ----

    public bool AssocPar2
    {
        get => _shell.CanWrite ? _shell.IsAssociated(".par2") : _settings.Integration.HandlePar2;
        set => SetAssoc(".par2", value, s => s with
        {
            Integration = s.Integration with { HandlePar2 = value },
        });
    }

    public bool AssocSfv
    {
        get => _shell.CanWrite ? _shell.IsAssociated(".sfv") : _settings.Integration.HandleSfv;
        set => SetAssoc(".sfv", value, s => s with
        {
            Integration = s.Integration with { HandleSfv = value },
        });
    }

    public bool AssocMd5
    {
        get => _shell.CanWrite ? _shell.IsAssociated(".md5") : _settings.Integration.HandleMd5;
        set => SetAssoc(".md5", value, s => s with
        {
            Integration = s.Integration with { HandleMd5 = value },
        });
    }

    public bool AssocSha256
    {
        get => _shell.CanWrite ? _shell.IsAssociated(".sha256") : _settings.Integration.HandleSha256;
        set => SetAssoc(".sha256", value, s => s with
        {
            Integration = s.Integration with { HandleSha256 = value },
        });
    }

    public bool ContextMenu
    {
        get => _shell.CanWrite ? _shell.IsContextMenuRegistered : _settings.Integration.ShellMenu;
        set
        {
            _shell.SetContextMenu(value);
            Update(_settings with
            {
                Integration = _settings.Integration with { ShellMenu = value },
            });
        }
    }

    // ---- Advanced ----

    public bool ShowCommand
    {
        get => _settings.Advanced.ShowCommand;
        set => Update(_settings with
        {
            Advanced = _settings.Advanced with { ShowCommand = value },
        });
    }

    public int LogLevel
    {
        get => _settings.Advanced.LogLevel;
        set => Update(_settings with
        {
            Advanced = _settings.Advanced with { LogLevel = value },
        });
    }

    /// <summary>Rereads from the core, for instance after another window changed something.</summary>
    public void Reload()
    {
        _loading = true;
        _settings = _core.GetSettings();
        _loading = false;
        Raise(string.Empty);
    }

    private void Reset()
    {
        // A fresh session's settings ARE the defaults, by contract, so resetting
        // is writing an untouched record and reading back what the core makes of
        // it. No default is written here, which is the whole point of the core
        // owning them.
        _core.SetSettings(new ParfastSettings());
        Reload();
    }

    private void SetAssoc(string extension, bool on, Func<ParfastSettings, ParfastSettings> also)
    {
        _shell.SetAssociation(extension, on);
        Update(also(_settings));
    }

    private void Update(ParfastSettings next)
    {
        if (_loading)
        {
            return;
        }

        _settings = next;
        _core.SetSettings(next);

        // One empty-name notification rather than a name per property: a
        // settings page rebinds in a millisecond and the alternative is a
        // hand-maintained list of thirty names that goes stale the first time
        // somebody adds a setting.
        Raise(string.Empty);
    }
}
