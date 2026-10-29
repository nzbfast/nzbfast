using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Parfast.Core.Contracts;
using Parfast.ViewModels;

namespace Parfast.App.Views;

/// <summary>
/// Create a posting set (plan B1). Every rule lives in
/// <see cref="PostingSetViewModel"/>; this page only copies state both ways.
/// </summary>
/// <remarks>
/// THE PASSWORD GOES ONE WAY. The box writes into the view model on every change
/// and Sync never writes it back: assigning PasswordBox.Password would move the
/// caret under a user who is typing, and there is nothing to show anyway, since
/// the reveal mode is Hidden and the core never sends the password back.
/// </remarks>
public sealed partial class PostingPage : UserControl
{
    private ShellViewModel? _shell;
    private bool _syncing;
    private bool _scrollToResult;

    public PostingPage() => InitializeComponent();

    private PostingSetViewModel Vm => _shell!.Posting;

    public void Bind(ShellViewModel shell)
    {
        _shell = shell;
        Localise();
        BuildChips();
        shell.Posting.PropertyChanged += (_, _) => Sync();
        shell.Posting.Sources.CollectionChanged += (_, _) => Sync();
        shell.Posting.OutputFiles.CollectionChanged += (_, _) => Sync();
        SourceList.ItemsSource = shell.Posting.Sources;
        OutputList.ItemsSource = shell.Posting.OutputFiles;
        Sync();
    }

    private void Localise()
    {
        EmptyTitle.Text = Strings.PostingEmptyTitle;
        EmptyBody.Text = Strings.PostingEmptyBody;
        EmptyAddFiles.Content = Strings.EmptyCreateAddFiles;
        EmptyAddFolder.Content = Strings.EmptyCreateAddFolder;

        PageTitle.Text = Strings.PostingTitle;
        Intro.Text = Strings.PostingIntro;

        SourcesHeader.Text = Strings.CreateSources;
        AddFiles.Content = Strings.EmptyCreateAddFiles;
        AddFolder.Content = Strings.EmptyCreateAddFolder;
        RemoveSources.Content = Strings.CommonRemove;

        NameBox.Header = Strings.PostingName;
        FolderBox.Header = Strings.PostingOutputFolder;
        BrowseFolder.Content = Strings.CommonBrowse;

        VolumesHeader.Text = Strings.PostingVolumesTitle;
        SplitNone.Content = Strings.PostingVolumesNone;
        SplitSize.Content = Strings.PostingVolumesSize;
        SplitCount.Content = Strings.PostingVolumesCount;
        VolumeSizeBox.Header = Strings.PostingVolumesSizeLabel;
        VolumeCountBox.Header = Strings.PostingVolumesCountLabel;

        CompressionBox.Header = Strings.PostingCompressionTitle;
        CompressionBox.Items.Clear();
        foreach (var level in PostingSetViewModel.CompressionLevels)
        {
            CompressionBox.Items.Add(level.Label);
        }

        CompressionNote.Text = Strings.PostingCompressionNote;
        SolidBox.Content = Strings.PostingSolid;
        ToolTipService.SetToolTip(SolidBox, Strings.PostingSolidTip);

        PasswordField.Header = Strings.PostingPasswordTitle;
        PasswordField.PlaceholderText = Strings.PostingPasswordPlaceholder;
        EncryptHeadersBox.Content = Strings.PostingPasswordEncryptHeaders;
        RecoveryRecordBox.Header = Strings.PostingRecoveryRecord;

        Par2Header.Text = Strings.PostingPar2Title;
        RecByPercent.Content = Strings.CreateRecoveryPercent;
        RecByCount.Content = Strings.CreateRecoveryCount;
        RecBySize.Content = Strings.CreateRecoverySize;

        RouteHeader.Text = Strings.PostingRouteTitle;
        CancelNote.Text = Strings.PostingCancelNote;
        OutputHeader.Text = Strings.PostingOutputTitle;

        OverwriteBox.Content = Strings.PostingOverwrite;
        ToolTipService.SetToolTip(OverwriteBox, Strings.PostingOverwriteTip);
        LogButton.Content = Strings.CommonLog;
        CancelButton.Content = Strings.CommonCancel;
        QueueButton.Content = Strings.CreateActionQueue;
        CreateButton.Content = Strings.PostingActionCreate;
    }

    /// <summary>The same chips as Create, from the one list both screens read.</summary>
    private void BuildChips()
    {
        PercentChips.Children.Clear();
        foreach (var percent in PostingSetViewModel.PercentChips)
        {
            var button = new Button
            {
                Content = Fmt.Pct(percent, 0),
                Padding = new Thickness(8, 2, 8, 2),
                FontSize = 12,
            };
            button.Click += (_, _) => Vm.ApplyChip(percent);
            PercentChips.Children.Add(button);
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
            var vm = Vm;
            EmptyState.Visibility = vm.HasSources ? Visibility.Collapsed : Visibility.Visible;
            FormView.Visibility = vm.HasSources ? Visibility.Visible : Visibility.Collapsed;
            SourcesFooter.Text = vm.SourcesFooter;
            RemoveSources.IsEnabled = vm.RemoveCommand.CanExecute(null);

            NameBox.Text = vm.Name;
            NameTip.Text = vm.NameTip;
            FolderBox.Text = vm.OutputDir;

            SplitNone.IsChecked = vm.SplitNone;
            SplitSize.IsChecked = vm.SplitBySize;
            SplitCount.IsChecked = vm.SplitByCount;
            VolumeSizeBox.Text = vm.VolumeSizeText;
            VolumeSizeBox.IsEnabled = vm.SplitBySize;
            VolumeCountBox.Value = vm.VolumeCount;
            VolumeCountBox.IsEnabled = vm.SplitByCount;

            CompressionBox.SelectedIndex = vm.Compression;
            SolidBox.IsChecked = vm.Solid;
            EncryptHeadersBox.Visibility = vm.HasPassword ? Visibility.Visible : Visibility.Collapsed;
            EncryptHeadersBox.IsChecked = vm.EncryptHeaders;
            RecoveryRecordBox.Value = vm.RecoveryRecordPercent;
            RecoveryRecordValue.Text = vm.RecoveryRecordPercent > 0
                ? Strings.Fill(Strings.PostingRecoveryRecordValue, "percent", Fmt.Pct(vm.RecoveryRecordPercent, 0))
                : string.Empty;

            RecByPercent.IsChecked = vm.ByPercent;
            RecByCount.IsChecked = vm.ByRecoveryCount;
            RecBySize.IsChecked = vm.ByRecoverySize;
            PercentBox.Value = vm.RecoveryPercent;
            PercentBox.IsEnabled = vm.ByPercent;
            RecCountBox.Value = vm.RecoveryCount;
            RecCountBox.IsEnabled = vm.ByRecoveryCount;
            RecSizeBox.Text = vm.RecoverySizeText;
            RecSizeBox.IsEnabled = vm.ByRecoverySize;

            RouteText.Text = vm.RouteText;
            var running = vm.IsBusy;
            Bar.Visibility = vm.Job is null ? Visibility.Collapsed : Visibility.Visible;
            Bar.Value = vm.Progress;
            PhaseText.Text = vm.PhaseText;
            Status.Visibility = vm.State is null ? Visibility.Collapsed : Visibility.Visible;
            Status.Tone = vm.Tone;
            Status.IsBusy = running;
            Status.Text = vm.State is { } state ? StateWord(state) : string.Empty;

            var problem = vm.ErrorText ?? vm.ValidationText;
            Problem.IsOpen = problem is not null;
            Problem.Message = problem ?? string.Empty;
            Problem.Severity = vm.State == JobState.Failed ? InfoBarSeverity.Error : InfoBarSeverity.Warning;
            CancelNote.Visibility = running ? Visibility.Visible : Visibility.Collapsed;

            OutputPanel.Visibility = vm.OutputFiles.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            OutputTotal.Text = vm.OutputTotalText;
            if (_scrollToResult && vm.OutputFiles.Count > 0)
            {
                _scrollToResult = false;
                ScrollToBottom();
            }

            OverwriteBox.IsChecked = vm.Overwrite;
            CancelButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
            CreateButton.IsEnabled = vm.CreateCommand.CanExecute(null);
            QueueButton.IsEnabled = vm.AddToQueueCommand.CanExecute(null);
        }
        finally
        {
            _syncing = false;
        }
    }

    private static string StateWord(JobState state) => state switch
    {
        JobState.Queued => Strings.QueueStateQueued,
        JobState.Running => Strings.QueueStateRunning,
        JobState.Paused => Strings.QueueStatePaused,
        JobState.Done => Strings.QueueStateDone,
        JobState.Failed => Strings.QueueStateFailed,
        JobState.Cancelled => Strings.QueueStateCancelled,
        JobState.Interrupted => Strings.QueueStateInterrupted,
        _ => string.Empty,
    };

    // ---- sources ----

    private async void OnAddFiles(object sender, RoutedEventArgs e)
    {
        var paths = await Pickers.PickFilesAsync(this);
        if (paths.Count > 0)
        {
            Vm.Add(paths);
        }
    }

    private async void OnAddFolder(object sender, RoutedEventArgs e)
    {
        var folder = await Pickers.PickFolderAsync(this);
        if (folder is not null)
        {
            Vm.Add([folder]);
        }
    }

    private void OnRemove(object sender, RoutedEventArgs e) => Vm.RemoveCommand.Execute(null);

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        Vm.Selected.Clear();
        Vm.Selected.AddRange(SourceList.SelectedItems.OfType<SourceRow>());
        Vm.RemoveCommand.Refresh();
        RemoveSources.IsEnabled = Vm.RemoveCommand.CanExecute(null);
    }

    // ---- output ----

    private void OnNameCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.Name = NameBox.Text;
        }
    }

    private void OnFolderCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.OutputDir = FolderBox.Text;
        }
    }

    private async void OnBrowseFolder(object sender, RoutedEventArgs e)
    {
        var folder = await Pickers.PickFolderAsync(this);
        if (folder is not null)
        {
            Vm.OutputDir = folder;
        }
    }

    private void OnOverwriteChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.Overwrite = OverwriteBox.IsChecked == true;
        }
    }

    // ---- archive ----

    private void OnSplitChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.Split = SplitSize.IsChecked == true ? RarSplit.Size
            : SplitCount.IsChecked == true ? RarSplit.Count
            : RarSplit.None;
    }

    private void OnVolumeSizeCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.VolumeSizeText = VolumeSizeBox.Text;
        }
    }

    private void OnVolumeCountChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.VolumeCount = (int)args.NewValue;
        }
    }

    private void OnCompressionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && CompressionBox.SelectedIndex >= 0)
        {
            Vm.Compression = PostingSetViewModel.CompressionLevels[CompressionBox.SelectedIndex].Level;
        }
    }

    private void OnSolidChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.Solid = SolidBox.IsChecked == true;
        }
    }

    private void OnPasswordChanged(object sender, RoutedEventArgs e) => Vm.Password = PasswordField.Password;

    private void OnEncryptHeadersChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.EncryptHeaders = EncryptHeadersBox.IsChecked == true;
        }
    }

    private void OnRecoveryRecordChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.RecoveryRecordPercent = (int)args.NewValue;
        }
    }

    // ---- PAR2 ----

    private void OnRecoveryModeChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.RecoveryMode = RecByCount.IsChecked == true ? RecoveryMode.Count
            : RecBySize.IsChecked == true ? RecoveryMode.Size
            : RecoveryMode.Percent;
    }

    private void OnPercentChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.RecoveryPercent = args.NewValue;
        }
    }

    private void OnRecoveryCountChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.RecoveryCount = (int)args.NewValue;
        }
    }

    private void OnRecoverySizeCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.RecoverySizeText = RecSizeBox.Text;
        }
    }

    // ---- actions ----

    private void OnCreate(object sender, RoutedEventArgs e)
    {
        // A name typed and not yet tabbed out of is committed first, so the job
        // carries what the user sees in the box.
        Vm.Name = NameBox.Text;
        Vm.OutputDir = FolderBox.Text;
        _shell!.StartPosting(showProgress: true);
    }

    private void OnAddToQueue(object sender, RoutedEventArgs e)
    {
        Vm.Name = NameBox.Text;
        Vm.OutputDir = FolderBox.Text;
        _shell!.StartPosting(showProgress: false);
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Vm.CancelCommand.Execute(null);

    private void OnToggleLog(object sender, RoutedEventArgs e) => _shell!.ToggleLog();

    /// <summary>
    /// Scrolls to the route and written-files card once the job has written its
    /// files. For the screenshot run's posting-done state: that card is below the
    /// fold at the default window size, so without it the shot is the form again.
    /// </summary>
    public void ScrollToResultWhenDone()
    {
        _scrollToResult = true;
        Sync();
    }

    private void ScrollToBottom()
    {
        FormView.UpdateLayout();
        FormView.ChangeView(null, FormView.ScrollableHeight, null, disableAnimation: true);
    }
}
