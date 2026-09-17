using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Parfast.Core.Contracts;
using Parfast.ViewModels;

namespace Parfast.App.Views;

/// <summary>Settings (plan section 5.6). The defaults belong to the core, not to this page.</summary>
public sealed partial class SettingsPage : UserControl
{
    /// <summary>
    /// The log levels, in the order the core numbers them.
    /// </summary>
    /// <remarks>
    /// `advanced.log_level` is an INTEGER in the contract, not a word, and the
    /// index into this array IS that integer. It read as a string until the
    /// settings object was regrouped on 12 Sep 2026; the words stayed on screen
    /// and the value underneath changed type, which is exactly the shape a
    /// non-compiling project hides.
    /// </remarks>
    private static readonly string[] LogLevels = ["Quiet", "Normal", "Verbose", "Debug"];

    private ShellViewModel? _shell;
    private bool _syncing;

    public SettingsPage() => InitializeComponent();

    private SettingsViewModel Vm => _shell!.Settings;

    public void Bind(ShellViewModel shell)
    {
        _shell = shell;
        Localise();
        shell.Settings.PropertyChanged += (_, _) => Sync();
        Sync();
    }

    private void Localise()
    {
        PageTitle.Text = Strings.ModeSettings;
        GeneralHeader.Text = Strings.SettingsGeneral;
        OnOpenLabel.Text = Strings.SettingsOnOpen;
        OnOpenVerify.Content = Strings.SettingsOnOpenVerify;
        OnOpenRepair.Content = Strings.SettingsOnOpenRepair;
        PurgeDefault.Content = Strings.SettingsPurgeDefault;
        KeepDamagedDefault.Content = Strings.SettingsKeepDamagedDefault;
        NotificationsBox.Content = Strings.SettingsNotifications;
        AutoCloseBox.Content = Strings.SettingsAutoClose;
        LanguageLabel.Text = Strings.SettingsLanguage;

        CreateHeader.Text = Strings.SettingsCreate;
        BlockAllocLabel.Text = Strings.SettingsBlockAllocation;
        RecoveryAllocLabel.Text = Strings.SettingsRecoveryAllocation;
        SchemeLabel.Text = Strings.SettingsDefaultScheme;
        StdNamingBox.Content = Strings.CreateOutputStdNaming;
        UnicodeLabel.Text = Strings.CreateOutputUnicode;
        OverwriteBox.Content = Strings.CreateOutputOverwrite;

        PerfHeader.Text = Strings.SettingsPerformance;
        AutoThreadsBox.Content = Strings.CommonAuto;
        MemoryLabel.Text = Strings.SettingsMemoryLimit;
        FastSolverBox.Content = Strings.VerifyOptionsFastSolver;
        LowPriorityBox.Content = Strings.SettingsLowPriority;
        DigestCacheBox.Content = Strings.SettingsDigestCache;
        DigestCacheNote.Text = Strings.SettingsDigestCacheNote;
        PairLargeCreatesBox.Content = Strings.SettingsPairLargeCreates;
        PairLargeCreatesNote.Text = Strings.SettingsPairLargeCreatesNote;
        ClearDigestCacheButton.Content = Strings.SettingsDigestCacheClear;
        DigestCacheClearedText.Text = Strings.SettingsDigestCacheCleared;

        IntegrationHeader.Text = Strings.SettingsIntegration;
        AssocLabel.Text = Strings.SettingsRegisterTypes;
        ContextMenuBox.Content = Strings.SettingsQuickActions;
        ContextNote.Text = Strings.SettingsIntegrationContextNote;

        // A platform split may carry an EMPTY arm, meaning the line does not apply
        // here. Omit the row rather than leaving a blank one with its margin still
        // taking space, which reads as a rendering fault.
        Win11Note.Text = Strings.SettingsIntegrationWin11Note;
        Win11Note.Visibility = string.IsNullOrEmpty(Strings.SettingsIntegrationWin11Note)
            ? Visibility.Collapsed
            : Visibility.Visible;

        AdvancedHeader.Text = Strings.SettingsAdvanced;
        ShowCommandBox.Content = Strings.SettingsShowCommand;
        LogLevelLabel.Text = Strings.SettingsLogLevel;
        ResetButton.Content = Strings.SettingsReset;

        LanguageBox.Items.Add("English");
        LanguageBox.SelectedIndex = 0;

        Fill(BlockAllocBox, [Strings.CreateBlocksBySize, Strings.CreateBlocksByCount]);
        Fill(RecoveryAllocBox, [
            Strings.CreateRecoveryPercent, Strings.CreateRecoveryCount, Strings.CreateRecoverySize,
        ]);
        Fill(SchemeBox, [
            Strings.CreateOutputSchemeNone, Strings.CreateOutputSchemeUniform,
            Strings.CreateOutputSchemePow2, Strings.CreateOutputSchemePow2Limit,
        ]);
        Fill(UnicodeBox, [Strings.CreateOutputUnicodeAuto, Strings.CreateOutputUnicodeNever, Strings.CreateOutputUnicodeAlways]);
        Fill(LogLevelBox, LogLevels);
    }

    private static void Fill(ComboBox box, IEnumerable<string> items)
    {
        box.Items.Clear();
        foreach (var item in items)
        {
            box.Items.Add(item);
        }
    }

    private void Sync()
    {
        if (_shell is null || _syncing)
        {
            return;
        }

        _syncing = true;
        try
        {
            OnOpenVerify.IsChecked = !Vm.VerifyThenRepair;
            OnOpenRepair.IsChecked = Vm.VerifyThenRepair;
            PurgeDefault.IsChecked = Vm.PurgeAfterRepair;
            KeepDamagedDefault.IsChecked = Vm.KeepDamaged;
            NotificationsBox.IsChecked = Vm.Notifications;
            AutoCloseBox.IsChecked = Vm.AutoCloseProgress;

            BlockAllocBox.SelectedIndex = Vm.BlockAllocation == "size" ? 0 : 1;
            RecoveryAllocBox.SelectedIndex = Vm.RecoveryAllocation switch
            {
                "count" => 1,
                "size" => 2,
                _ => 0,
            };
            SchemeBox.SelectedIndex = (int)Vm.DefaultScheme;
            StdNamingBox.IsChecked = Vm.StdNaming;
            UnicodeBox.SelectedIndex = (int)Vm.Unicode;
            OverwriteBox.IsChecked = Vm.Overwrite;
            StdNamingBox.Visibility = Vm.ShowStdNaming ? Visibility.Visible : Visibility.Collapsed;
            UnicodeRow.Visibility = Vm.ShowUnicodePolicy ? Visibility.Visible : Visibility.Collapsed;

            AutoThreadsBox.IsChecked = Vm.AutomaticThreads;
            ThreadsBox.IsEnabled = !Vm.AutomaticThreads;
            ThreadsBox.Value = Vm.ThreadCount == 0 ? Environment.ProcessorCount : Vm.ThreadCount;
            MemoryBox.Value = Vm.MemoryMb;
            FastSolverBox.IsChecked = Vm.FastSolver;
            LowPriorityBox.IsChecked = Vm.LowPriority;
            DigestCacheBox.IsChecked = Vm.DigestCache;
            PairLargeCreatesBox.IsChecked = Vm.PairLargeCreates;
            FastSolverBox.Visibility = Vm.ShowFastSolver ? Visibility.Visible : Visibility.Collapsed;
            LowPriorityBox.Visibility = Vm.ShowLowPriority ? Visibility.Visible : Visibility.Collapsed;

            // The engine line is the capability report, put where somebody
            // reporting a problem can read it out. It is the only place in the UI
            // the kernel the engine picked is visible.
            var caps = _shell.Capabilities;
            EngineLine.Text = string.IsNullOrEmpty(caps.Engine)
                ? string.Empty
                : $"{caps.Engine} on {caps.Cpu}, {caps.Kernel} kernel";

            AssocPar2.IsChecked = Vm.AssocPar2;
            AssocSfv.IsChecked = Vm.AssocSfv;
            AssocMd5.IsChecked = Vm.AssocMd5;
            AssocSha256.IsChecked = Vm.AssocSha256;
            ContextMenuBox.IsChecked = Vm.ContextMenu;

            var canIntegrate = Vm.CanIntegrate;
            foreach (var box in new[] { AssocPar2, AssocSfv, AssocMd5, AssocSha256, ContextMenuBox })
            {
                box.IsEnabled = canIntegrate;
            }

            IntegrationBar.IsOpen = !canIntegrate;
            IntegrationBar.Message = canIntegrate
                ? string.Empty
                : "File associations can only be set on Windows.";

            ShowCommandBox.IsChecked = Vm.ShowCommand;
            LogLevelBox.SelectedIndex = Math.Clamp(Vm.LogLevel, 0, LogLevels.Length - 1);
        }
        finally
        {
            _syncing = false;
        }
    }

    private void OnOnOpenChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.VerifyThenRepair = OnOpenRepair.IsChecked == true;
        }
    }

    private void OnGeneralChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.PurgeAfterRepair = PurgeDefault.IsChecked == true;
        Vm.KeepDamaged = KeepDamagedDefault.IsChecked == true;
        Vm.Notifications = NotificationsBox.IsChecked == true;
        Vm.AutoCloseProgress = AutoCloseBox.IsChecked == true;
    }

    private void OnCreateChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.BlockAllocation = BlockAllocBox.SelectedIndex == 0 ? "size" : "count";
        Vm.RecoveryAllocation = RecoveryAllocBox.SelectedIndex switch
        {
            1 => "count",
            2 => "size",
            _ => "percent",
        };
        if (SchemeBox.SelectedIndex >= 0)
        {
            Vm.DefaultScheme = (VolumeScheme)SchemeBox.SelectedIndex;
        }

        if (UnicodeBox.SelectedIndex >= 0)
        {
            Vm.Unicode = (UnicodePolicy)UnicodeBox.SelectedIndex;
        }
    }

    private void OnCreateFlagChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.StdNaming = StdNamingBox.IsChecked == true;
        Vm.Overwrite = OverwriteBox.IsChecked == true;
    }

    private void OnPerfChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.AutomaticThreads = AutoThreadsBox.IsChecked == true;
        Vm.FastSolver = FastSolverBox.IsChecked == true;
        Vm.LowPriority = LowPriorityBox.IsChecked == true;
        Vm.DigestCache = DigestCacheBox.IsChecked == true;
        Vm.PairLargeCreates = PairLargeCreatesBox.IsChecked == true;
    }

    private void OnThreadsChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.ThreadCount = (int)args.NewValue;
        }
    }

    private void OnMemoryChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.MemoryMb = (int)args.NewValue;
        }
    }

    private void OnAssocChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.AssocPar2 = AssocPar2.IsChecked == true;
        Vm.AssocSfv = AssocSfv.IsChecked == true;
        Vm.AssocMd5 = AssocMd5.IsChecked == true;
        Vm.AssocSha256 = AssocSha256.IsChecked == true;
    }

    private void OnContextChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.ContextMenu = ContextMenuBox.IsChecked == true;
        }
    }

    private void OnAdvancedChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.ShowCommand = ShowCommandBox.IsChecked == true;
        if (LogLevelBox.SelectedIndex >= 0)
        {
            Vm.LogLevel = LogLevelBox.SelectedIndex;
        }
    }

    /// <summary>
    /// The log-level picker. A separate name from the checkbox handler on
    /// purpose: two methods differing only in their EventArgs type are legal C#
    /// and an ambiguity the XAML compiler resolves by signature, which is a
    /// thing to find out on a build box rather than to rely on.
    /// </summary>
    private void OnAdvancedSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        OnAdvancedChanged(sender, e);

    private void OnReset(object sender, RoutedEventArgs e) => Vm.ResetCommand.Execute(null);

    private async void OnClearDigestCache(object sender, RoutedEventArgs e)
    {
        // Title is the question and the body is the consequence, matching the
        // mac dialog and QueuePage's. The title used to repeat the button's
        // own label while the question sat in the body.
        var confirmed = await Dialogs.ConfirmAsync(
            this,
            Strings.SettingsDigestCacheClearConfirm,
            Strings.SettingsDigestCacheClearConfirmBody,
            Strings.SettingsDigestCacheClear,
            Strings.CommonCancel);
        if (!confirmed)
        {
            return;
        }

        if (Vm.ClearDigestCache() is { } error)
        {
            DigestCacheClearedText.Visibility = Visibility.Collapsed;
            await Dialogs.ShowAsync(this, Strings.ErrorTitle, error);
            return;
        }

        DigestCacheClearedText.Visibility = Visibility.Visible;
    }
}
