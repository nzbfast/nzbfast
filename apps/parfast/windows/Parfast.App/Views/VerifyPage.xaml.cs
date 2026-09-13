using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Parfast.Core.Contracts;
using Parfast.ViewModels;
using Windows.Storage.Pickers;

namespace Parfast.App.Views;

/// <summary>
/// Verify &amp; repair (plan section 5.2).
/// </summary>
/// <remarks>
/// The page owns no state. <see cref="Bind"/> attaches it to the shell and every
/// repaint is <see cref="Sync"/> reading the view model, which is what lets the
/// scenario tests in Parfast.Tests assert the same values this page draws without
/// a window existing.
/// </remarks>
public sealed partial class VerifyPage : UserControl
{
    private ShellViewModel? _shell;

    public VerifyPage() => InitializeComponent();

    private VerifyViewModel Vm => _shell!.Verify;

    public void Bind(ShellViewModel shell)
    {
        _shell = shell;
        Localise();

        shell.Verify.PropertyChanged += (_, _) => Sync();
        shell.Verify.Options.PropertyChanged += (_, _) => SyncOptions();

        // The map tells the shell how many cells it has room for, and the shell
        // tells the model. That way the block map's resolution follows the window
        // rather than being a constant somebody has to keep in step with it.
        Map.WidthInCellsChanged += cells => shell.SetMapWidth(cells);

        SyncOptions();
        Sync();
    }

    private void Localise()
    {
        EmptyTitle.Text = Strings.EmptyVerifyTitle;
        EmptyBody.Text = Strings.EmptyVerifyBody;
        OpenFileButton.Content = Strings.EmptyVerifyOpen;
        OpenFolderButton.Content = Strings.EmptyVerifyOpenFolder;

        FilesLabel.Text = Strings.VerifyHeaderFiles;
        BlockSizeLabel.Text = Strings.VerifyHeaderBlockSize;
        SourceBlocksLabel.Text = Strings.VerifyHeaderSourceBlocks;
        RecoveryLabel.Text = Strings.VerifyHeaderRecoveryBlocks;

        MapLabel.Text = Strings.VerifyMapTitle;
        FilesHeader.Text = Strings.VerifyHeaderFiles;
        ColName.Text = Strings.CommonName;
        ColSize.Text = Strings.CommonSize;
        ColStatus.Text = Strings.CommonStatus;
        ColBlocks.Text = Strings.CommonBlocks;
        ToolTipService.SetToolTip(ProblemsOnly, Strings.VerifyFilterProblems);

        VerifyAgain.Content = Strings.VerifyActionVerifyAgain;
        ScanOther.Content = Strings.VerifyActionScanOther;
        OptionsButton.Content = Strings.CommonOptions;
        LogButton.Content = Strings.CommonLog;
        CancelButton.Content = Strings.CommonCancel;
        RepairButton.Content = Strings.VerifyActionRepair;

        OptPurge.Content = Strings.VerifyOptionsPurge;
        OptKeepDamaged.Content = Strings.VerifyOptionsKeepDamaged;
        OptRenameOnly.Content = Strings.VerifyOptionsRenameOnly;
        OptDataSkipping.Content = Strings.VerifyOptionsDataSkipping;
        OptFastSolver.Content = Strings.VerifyOptionsFastSolver;
        OptThreadsLabel.Text = Strings.VerifyOptionsThreads;

        SummaryReveal.Content = Strings.CommonReveal;
        SummaryPurge.Content = Strings.VerifySummaryPurge;
        SummaryLog.Content = Strings.CommonLog;
    }

    private void Sync()
    {
        if (_shell is null)
        {
            return;
        }

        var has = Vm.HasSet;
        EmptyState.Visibility = has ? Visibility.Collapsed : Visibility.Visible;
        SetView.Visibility = has ? Visibility.Visible : Visibility.Collapsed;
        if (!has)
        {
            return;
        }

        SetName.Text = Vm.SetName;
        FolderText.Text = Vm.Folder;
        FilesValue.Text = Vm.FileCountText;
        BlockSizeValue.Text = Vm.BlockSizeText;
        SourceBlocksValue.Text = Vm.SourceBlocksText;
        RecoveryValue.Text = Vm.RecoveryBlocksText;

        Verdict.Text = Vm.StatusText;
        Verdict.Tone = Vm.StatusTone;
        Verdict.IsBusy = Vm.IsBusy;

        Map.Model = Vm.Map;
        Map.RecoveryAvailable = Vm.Survey?.RecoveryAvailable ?? 0;
        Map.RecoveryNeeded = Vm.Survey?.RecoveryNeeded ?? 0;
        // AND THEN SAY SO. The three lines above are dependency property
        // assignments and the view model hands out the SAME BlockMapModel every
        // time, mutated in place, so none of them is a change and none of them
        // repaints. Everything else on this screen is a plain assignment and
        // updated correctly, which is exactly why a frozen map went unnoticed.
        // See BlockMap.Refresh.
        Map.Refresh();
        MapLegend.Model = Vm.Map;
        MapLegend.Refresh();
        // THE MERGED NOTE, NOT THE CENSUS. The census moved onto the legend's
        // swatches on 12 Sep 2026, where each number sits beside the colour it
        // counts; restating all five here as a grey sentence made the reader match
        // word to word instead. Losing it costs nothing for a screen reader - the
        // strip's own automation name IS AccessibleSummary(), set in BlockMap.
        //
        // What goes here instead is the one thing the legend cannot say: whether a
        // cell is a block or a bundle of them. BlockMapModel has computed
        // MergedNote since it was written and nothing had ever shown it, so above
        // four thousand blocks this app drew merged cells and never said so - the
        // same omission the mac lane hit, where the note existed and was wrong.
        MapCounts.Text = Vm.Map.MergedNote;
        RecoveryNeededText.Text = Vm.Survey is { RecoveryNeeded: > 0 } survey
            ? Strings.Fill(Strings.VerifyMapNeededMarker, "needed", Fmt.Count(survey.RecoveryNeeded))
            : string.Empty;

        FileList.ItemsSource = Vm.Files;
        // ITS OWN KEYS, not the filter label lowercased and given a number. That
        // spelling put "1 problems" on the verify screen for a set with one
        // damaged file - seen on the first real-engine screenshot, 12 Sep 2026 -
        // and it could not say otherwise: `verify.filter.problems` is the label
        // on a filter control, one fact, and a count sentence is another. It is
        // the same shape as common.one_file / common.files_count, which the
        // shared table already carries for this app alone.
        ProblemCount.Text = Vm.ProblemCount switch
        {
            <= 0 => string.Empty,
            1 => Strings.VerifyProblemsOne,
            var n => Strings.Fill(Strings.VerifyProblemsCount, "count", Fmt.Count(n)),
        };

        SummaryCard.Visibility = Vm.SummaryText is null ? Visibility.Collapsed : Visibility.Visible;
        SummaryText.Text = Vm.SummaryText ?? string.Empty;
        SummaryPurge.Visibility = Vm.Purged ? Visibility.Collapsed : Visibility.Visible;

        CancelButton.Visibility = Vm.IsBusy ? Visibility.Visible : Visibility.Collapsed;
        RepairButton.IsEnabled = Vm.CanRepair;
        VerifyAgain.IsEnabled = Vm.VerifyAgainCommand.CanExecute(null);

        // The repair button is the DEFAULT button when it is the thing to do, so
        // Return does the obvious thing (plan 5.2 says the mac default button;
        // the Windows equivalent is the accent style plus this).
        RepairButton.IsTabStop = true;
    }

    private void SyncOptions()
    {
        var options = Vm.Options;
        OptPurge.IsChecked = options.Purge;
        OptKeepDamaged.IsChecked = options.KeepDamaged;
        OptRenameOnly.IsChecked = options.RenameOnly;
        OptDataSkipping.IsChecked = options.DataSkipping;
        OptSkipLeaway.Value = options.SkipLeaway;
        OptFastSolver.IsChecked = options.FastSolver;
        OptThreads.Value = options.Threads ?? 0;

        // A control whose capability the core says is false is HIDDEN, not
        // disabled (plan 4.5). A greyed switch invites the user to wonder what
        // would enable it; an absent one says the engine does not do that.
        OptSkipRow.Visibility = options.ShowDataSkipping ? Visibility.Visible : Visibility.Collapsed;
        OptFastSolver.Visibility = options.ShowFastSolver ? Visibility.Visible : Visibility.Collapsed;

        ExtraDirList.ItemsSource = Vm.ExtraDirs;
    }

    private void OnProblemsOnlyToggled(object sender, RoutedEventArgs e) =>
        Vm.ShowProblemsOnly = ProblemsOnly.IsOn;

    private void OnOptionChanged(object sender, RoutedEventArgs e)
    {
        var options = Vm.Options;
        options.Purge = OptPurge.IsChecked == true;
        options.KeepDamaged = OptKeepDamaged.IsChecked == true;
        options.RenameOnly = OptRenameOnly.IsChecked == true;
        options.DataSkipping = OptDataSkipping.IsChecked == true;
        options.FastSolver = OptFastSolver.IsChecked == true;
        Sync();
    }

    private void OnLeawayChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!double.IsNaN(args.NewValue))
        {
            Vm.Options.SkipLeaway = (int)args.NewValue;
        }
    }

    private void OnThreadsChanged(NumberBox sender, NumberBoxValueChangedEventArgs args) =>
        Vm.Options.Threads = double.IsNaN(args.NewValue) || args.NewValue <= 0 ? null : (int)args.NewValue;

    private void OnVerifyAgain(object sender, RoutedEventArgs e) => Vm.VerifyAgainCommand.Execute(null);

    private void OnRepair(object sender, RoutedEventArgs e)
    {
        Vm.RepairCommand.Execute(null);
        _shell!.Progress.Open(Vm.JobId);
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Vm.CancelCommand.Execute(null);

    private void OnPurge(object sender, RoutedEventArgs e) => Vm.PurgeCommand.Execute(null);

    private void OnToggleLog(object sender, RoutedEventArgs e) => _shell!.ToggleLog();

    private void OnRevealFolder(object sender, RoutedEventArgs e) => _shell!.RevealCommand.Execute(null);

    private async void OnOpenFile(object sender, RoutedEventArgs e)
    {
        var path = await Pickers.PickFileAsync(this, [".par2"]);
        if (path is not null)
        {
            _shell!.Drop([path]);
        }
    }

    private async void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        var folder = await Pickers.PickFolderAsync(this);
        if (folder is null)
        {
            return;
        }

        // A folder in Verify means "find the set in it". The index file is the one
        // .par2 without a .vol in its name, which is the same rule the drop router
        // uses, so opening a folder and dropping its contents land on the same set.
        var par2 = Directory.EnumerateFiles(folder, "*.par2").ToList();
        var index = DropRouter.Par2Of(par2);
        if (index is not null)
        {
            _shell!.Drop([index]);
        }
        else
        {
            await Dialogs.ShowAsync(this, Strings.ErrorTitle, Strings.ErrorNoPar2);
        }
    }

    private async void OnScanOther(object sender, RoutedEventArgs e)
    {
        var folder = await Pickers.PickFolderAsync(this);
        if (folder is not null)
        {
            Vm.AddExtraDir(folder);
            Vm.VerifyAgainCommand.Execute(null);
        }
    }
}
