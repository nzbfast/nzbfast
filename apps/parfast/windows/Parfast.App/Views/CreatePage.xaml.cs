using Parfast.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Parfast.Core.Contracts;
using Parfast.ViewModels;
using Windows.System;

namespace Parfast.App.Views;

/// <summary>
/// Create (plan section 5.3).
/// </summary>
/// <remarks>
/// TWO THINGS SHAPE THE CODE HERE.
/// <para>
/// First, the preview is recomputed on every change and the non-chosen quantities
/// are read back out of it, so this page writes to the view model and then reads
/// everything, rather than computing anything itself. There is no arithmetic in
/// this file at all, which is deliberate: the planner is one implementation and
/// the CLI will eventually share it.
/// </para>
/// <para>
/// Second, <see cref="_syncing"/> guards the setters. Filling a ComboBox or a
/// NumberBox from the view model raises the same changed event a user's click
/// does, so without the guard a Sync would write back what it had just read,
/// which turns a radio group into a loop and a text box into a field that
/// refuses to hold what you type.
/// </para>
/// </remarks>
public sealed partial class CreatePage : UserControl
{
    private ShellViewModel? _shell;
    private bool _syncing;

    public CreatePage() => InitializeComponent();

    private CreateViewModel Vm => _shell!.Create;

    public void Bind(ShellViewModel shell)
    {
        _shell = shell;
        Localise();
        BuildChips();

        shell.Create.PropertyChanged += (_, _) => Sync();
        shell.Create.Sources.CollectionChanged += (_, _) => Sync();
        SizeChanged += (_, _) => Reflow();

        Sync();
        Reflow();
    }

    private void Localise()
    {
        EmptyTitle.Text = Strings.EmptyCreateTitle;
        EmptyBody.Text = Strings.EmptyCreateBody;
        EmptyAddFiles.Content = Strings.EmptyCreateAddFiles;
        EmptyAddFolder.Content = Strings.EmptyCreateAddFolder;

        SourcesHeader.Text = Strings.CreateSources;
        AddFiles.Content = Strings.EmptyCreateAddFiles;
        AddFolder.Content = Strings.EmptyCreateAddFolder;
        RemoveSources.Content = Strings.CommonRemove;
        RefreshSources.Content = Strings.CreateSourcesRefresh;
        ColName.Text = Strings.CommonName;
        ColModified.Text = Strings.CommonModified;
        ColSize.Text = Strings.CommonSize;
        PathModeLabel.Text = Strings.CreatePathsLabel;

        BlocksHeader.Text = Strings.CreateBlocksTitle;
        BlockBySize.Content = Strings.CreateBlocksBySize;
        BlockByCount.Content = Strings.CreateBlocksByCount;
        PaddingLabel.Text = Strings.CreateBlocksPadding;
        EfficiencyLabel.Text = Strings.CreateBlocksEfficiency;

        RecoveryHeader.Text = Strings.CreateRecoveryTitle;
        RecByPercent.Content = Strings.CreateRecoveryPercent;
        RecByCount.Content = Strings.CreateRecoveryCount;
        RecBySize.Content = Strings.CreateRecoverySize;
        DerivedRecoveryLabel.Text = Strings.CreateRecoveryTitle;

        OutputHeader.Text = Strings.CreateOutputTitle;
        BrowseOutput.Content = Strings.CommonBrowse;
        BrowseBase.Content = Strings.CommonBrowse;
        BaseLabel.Text = Strings.CreateBaseFolder;
        SchemeLabel.Text = Strings.CreateOutputVolumes;
        UniformFilesRadio.Content = Strings.CreateOutputUniformFiles;
        UniformPerFileRadio.Content = Strings.CreateOutputUniformBlocks;
        UniformSizeRadio.Content = Strings.CreateOutputUniformSize;
        Pow2LargestRadio.Content = Strings.CreateOutputLimitLargest;
        Pow2BlocksRadio.Content = Strings.CreateOutputLimitBlocks;
        Pow2SizeRadio.Content = Strings.CreateOutputLimitSize;
        FirstBlockLabel.Text = Strings.CreateOutputFirstBlock;
        FirstBlockTip.Text = Strings.CreateOutputFirstBlockTip;
        CommentBox.Header = Strings.CreateOutputComment;
        CommentBox.PlaceholderText = Strings.CreateOutputComment;
        OverwriteBox.Content = Strings.CreateOutputOverwrite;
        StdNamingBox.Content = Strings.CreateOutputStdNaming;
        UnicodeLabel.Text = Strings.CreateOutputUnicode;
        OutputBox.Header = Strings.CreateOutputIndex;

        PreviewHeader.Text = Strings.CreatePreviewTitle;
        PvName.Text = Strings.CommonName;
        PvSize.Text = Strings.CommonSize;
        PvBlocks.Text = Strings.CommonBlocks;
        PvEff.Text = Strings.CreateBlocksEfficiency;

        CopyCommandButton.Content = Strings.CommonCopyCommand;
        LogButton.Content = Strings.CommonLog;
        QueueButton.Content = Strings.CreateActionQueue;
        CreateButton.Content = Strings.CreateActionCreate;

        Fill(PathModeBox, [Strings.CreatePathsBasename, Strings.CreatePathsRelative]);
        Fill(SchemeBox, [
            Strings.CreateOutputSchemeNone, Strings.CreateOutputSchemeUniform,
            Strings.CreateOutputSchemePow2, Strings.CreateOutputSchemePow2Limit,
        ]);
        Fill(UnicodeBox, [Strings.CreateOutputUnicodeAuto, Strings.CreateOutputUnicodeNever, Strings.CreateOutputUnicodeAlways]);
    }

    private static void Fill(ComboBox box, IEnumerable<string> items)
    {
        box.Items.Clear();
        foreach (var item in items)
        {
            box.Items.Add(item);
        }
    }

    /// <summary>The recovery quick chips of plan section 5.3, built from
    /// <see cref="CreateViewModel.PercentChips"/> so the set is stated once.</summary>
    private void BuildChips()
    {
        PercentChips.Children.Clear();
        foreach (var percent in CreateViewModel.PercentChips)
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

    /// <summary>
    /// Two columns on a wide window, stacked on a narrow one (plan section 5.3).
    /// </summary>
    /// <remarks>
    /// Done in code against the measured width rather than with an AdaptiveTrigger,
    /// because the trigger fires on the WINDOW's width and this control is inside a
    /// NavigationView whose compact pane takes 48 px of it: at the boundary the
    /// trigger and the actual available width disagree by exactly the pane, and
    /// the columns snap at the wrong moment.
    /// </remarks>
    private void Reflow()
    {
        var wide = ActualWidth >= 1000;
        RightColumn.Width = wide ? new GridLength(420) : new GridLength(0);
        Columns.RowSpacing = 12;

        if (wide)
        {
            Grid.SetRow(RightPanel(), 0);
            Grid.SetColumn(RightPanel(), 1);
            Columns.RowDefinitions.Clear();
        }
        else
        {
            if (Columns.RowDefinitions.Count == 0)
            {
                Columns.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                Columns.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            }

            Grid.SetRow(RightPanel(), 1);
            Grid.SetColumn(RightPanel(), 0);
        }
    }

    private FrameworkElement RightPanel() => (FrameworkElement)Columns.Children[1];

    private void Sync()
    {
        if (_shell is null || _syncing)
        {
            return;
        }

        _syncing = true;
        try
        {
            var has = Vm.HasSources;
            EmptyState.Visibility = has ? Visibility.Collapsed : Visibility.Visible;
            FormView.Visibility = has ? Visibility.Visible : Visibility.Collapsed;

            SourceList.ItemsSource = Vm.Sources;
            SourcesFooter.Text = Vm.SourcesFooter;
            PathModeBox.SelectedIndex = Vm.PathMode == PathMode.Relative ? 1 : 0;

            BlockBySize.IsChecked = Vm.ByBlockSize;
            BlockByCount.IsChecked = Vm.ByBlockCount;
            BlockSizeBox.IsEnabled = Vm.ByBlockSize;
            BlockCountBox.IsEnabled = Vm.ByBlockCount;
            if (!BlockSizeBox.FocusState.Equals(FocusState.Keyboard))
            {
                BlockSizeBox.Text = Vm.BlockSizeText;
            }

            BlockCountBox.Value = Vm.BlockCount;
            DerivedLabel.Text = Vm.ByBlockCount ? Strings.CreateBlocksBySize : Strings.CreateBlocksByCount;
            DerivedValue.Text = Vm.DerivedBlockText;
            PaddingValue.Text = Vm.PaddingText;
            EfficiencyValue.Text = Vm.EfficiencyText;

            RecByPercent.IsChecked = Vm.ByPercent;
            RecByCount.IsChecked = Vm.ByRecoveryCount;
            RecBySize.IsChecked = Vm.ByRecoverySize;
            PercentBox.IsEnabled = Vm.ByPercent;
            RecCountBox.IsEnabled = Vm.ByRecoveryCount;
            RecSizeBox.IsEnabled = Vm.ByRecoverySize;
            PercentBox.Value = Vm.RecoveryPercent;
            RecCountBox.Value = Vm.RecoveryCount;
            RecSizeBox.Text = Vm.RecoverySizeText;
            DerivedRecoveryValue.Text = Vm.DerivedRecoveryText;

            OutputBox.Text = Vm.Output;
            BasePathRow.Visibility = Vm.ShowBasePath ? Visibility.Visible : Visibility.Collapsed;
            BaseBox.Text = Vm.BasePath ?? string.Empty;
            SchemeBox.SelectedIndex = (int)Vm.Scheme;
            UniformPanel.Visibility = Vm.ShowUniform ? Visibility.Visible : Visibility.Collapsed;
            Pow2Panel.Visibility = Vm.ShowPow2Limit ? Visibility.Visible : Visibility.Collapsed;

            UniformFilesRadio.IsChecked = Vm.UniformArm == "files";
            UniformPerFileRadio.IsChecked = Vm.UniformArm == "per_file";
            UniformSizeRadio.IsChecked = Vm.UniformArm == "file_size";
            UniformFilesBox.Value = Vm.UniformFiles;
            UniformPerFileBox.Value = Vm.UniformBlocksPerFile;
            UniformSizeBox.Text = Fmt.Bytes(Vm.UniformFileSize);
            UniformFilesBox.IsEnabled = Vm.UniformArm == "files";
            UniformPerFileBox.IsEnabled = Vm.UniformArm == "per_file";
            UniformSizeBox.IsEnabled = Vm.UniformArm == "file_size";

            Pow2LargestRadio.IsChecked = Vm.Pow2LimitArm == "largest";
            Pow2BlocksRadio.IsChecked = Vm.Pow2LimitArm == "blocks";
            Pow2SizeRadio.IsChecked = Vm.Pow2LimitArm == "size";
            Pow2BlocksBox.Value = Vm.Pow2LimitBlocks;
            Pow2SizeBox.Text = Fmt.Bytes(Vm.Pow2LimitSize);
            Pow2BlocksBox.IsEnabled = Vm.Pow2LimitArm == "blocks";
            Pow2SizeBox.IsEnabled = Vm.Pow2LimitArm == "size";

            FirstBlockBox.Value = Vm.FirstRecoveryBlock;
            CommentBox.Text = Vm.Comment;
            OverwriteBox.IsChecked = Vm.Overwrite;
            StdNamingBox.IsChecked = Vm.StdNaming;
            UnicodeBox.SelectedIndex = (int)Vm.Unicode;

            // Capability gating, as in Verify's options: absent, not greyed. A
            // greyed control invites the user to wonder what would enable it; an
            // absent one says the engine does not do that. Against today's engine
            // all four of these are off (crates/parfast-ffi/API.md), so the
            // Advanced row is empty and the Comment field is gone.
            StdNamingBox.Visibility = Vm.ShowStdNaming ? Visibility.Visible : Visibility.Collapsed;
            UnicodeRow.Visibility = Vm.ShowUnicodePolicy ? Visibility.Visible : Visibility.Collapsed;
            CommentBox.Visibility = Vm.ShowComment ? Visibility.Visible : Visibility.Collapsed;

            // The pow2 ceiling: only "largest source file" is real while the engine
            // runs a create through the reference's dialect, which has exactly one
            // ceiling. Showing the other two would let somebody type a number the
            // run ignores.
            var explicitLimit = Vm.ShowExplicitVolumeLimit;
            Pow2BlocksRadio.Visibility = explicitLimit ? Visibility.Visible : Visibility.Collapsed;
            Pow2BlocksBox.Visibility = Pow2BlocksRadio.Visibility;
            Pow2SizeRadio.Visibility = Pow2BlocksRadio.Visibility;
            Pow2SizeBox.Visibility = Pow2BlocksRadio.Visibility;

            PreviewList.ItemsSource = Vm.PreviewFiles;
            PreviewTotal.Text = Vm.PreviewTotalText;

            // Assign AND Refresh. The view model owns one CostBarModel for the life of
            // the page and mutates it in place on every recompute, so this assignment
            // hands the dependency property the value it already holds and WinUI raises
            // no change for that - the same trap that left the block map frozen for its
            // whole life until 12 Sep 2026.
            Cost.Model = Vm.Cost;
            Cost.Refresh();
            WarningBar.IsOpen = Vm.Warnings.Count > 0;
            WarningBar.Message = string.Join("  ", Vm.Warnings);

            CreateButton.IsEnabled = Vm.CreateCommand.CanExecute(null);
            QueueButton.IsEnabled = Vm.AddToQueueCommand.CanExecute(null);
            RemoveSources.IsEnabled = Vm.RemoveCommand.CanExecute(null);
            RefreshSources.IsEnabled = Vm.RefreshCommand.CanExecute(null);
            CopyCommandButton.IsEnabled = !string.IsNullOrEmpty(Vm.CommandText);
        }
        finally
        {
            _syncing = false;
        }
    }

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

    private void OnRefresh(object sender, RoutedEventArgs e) => Vm.RefreshCommand.Execute(null);

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        Vm.Selected.Clear();
        Vm.Selected.AddRange(SourceList.SelectedItems.OfType<SourceRow>());
        RemoveSources.IsEnabled = Vm.RemoveCommand.CanExecute(null);
    }

    private void OnPathModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.PathMode = PathModeBox.SelectedIndex == 1 ? PathMode.Relative : PathMode.Basename;
        }
    }

    // ---- blocks ----

    private void OnBlockModeChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.BlockMode = BlockBySize.IsChecked == true ? BlockMode.Size : BlockMode.Count;
    }

    private void OnBlockSizeCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.BlockSizeText = BlockSizeBox.Text;
        }
    }

    /// <summary>Return commits the size field, which is what a typist expects.</summary>
    private void OnBlockSizeKey(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            Vm.BlockSizeText = BlockSizeBox.Text;
        }
    }

    private void OnBlockCountChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.BlockCount = (int)args.NewValue;
        }
    }

    // ---- recovery ----

    private void OnRecoveryModeChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.RecoveryMode = RecByPercent.IsChecked == true ? RecoveryMode.Percent
            : RecByCount.IsChecked == true ? RecoveryMode.Count
            : RecoveryMode.Size;
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

    // ---- output ----

    private void OnOutputCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.Output = OutputBox.Text;
        }
    }

    private void OnBaseCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.BasePath = BaseBox.Text;
        }
    }

    private async void OnBrowseOutput(object sender, RoutedEventArgs e)
    {
        var name = string.IsNullOrEmpty(Vm.Output) ? "set.par2" : PathUtil.FileName(Vm.Output);
        var path = await Pickers.SaveFileAsync(this, name, "PAR2 recovery set", [".par2"]);
        if (path is not null)
        {
            Vm.Output = path;
        }
    }

    private async void OnBrowseBase(object sender, RoutedEventArgs e)
    {
        var folder = await Pickers.PickFolderAsync(this);
        if (folder is not null)
        {
            Vm.BasePath = folder;
        }
    }

    private void OnSchemeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && SchemeBox.SelectedIndex >= 0)
        {
            Vm.Scheme = (VolumeScheme)SchemeBox.SelectedIndex;
        }
    }

    private void OnUniformArmChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.UniformArm = UniformFilesRadio.IsChecked == true ? "files"
            : UniformPerFileRadio.IsChecked == true ? "per_file"
            : "file_size";
    }

    private void OnUniformChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (_syncing || double.IsNaN(args.NewValue))
        {
            return;
        }

        if (ReferenceEquals(sender, UniformFilesBox))
        {
            Vm.UniformFiles = (int)args.NewValue;
        }
        else
        {
            Vm.UniformBlocksPerFile = (int)args.NewValue;
        }
    }

    private void OnUniformSizeCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing && Fmt.ParseSize(UniformSizeBox.Text) is { } size and > 0)
        {
            Vm.UniformFileSize = size;
        }
    }

    private void OnPow2ArmChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.Pow2LimitArm = Pow2LargestRadio.IsChecked == true ? "largest"
            : Pow2BlocksRadio.IsChecked == true ? "blocks"
            : "size";
    }

    private void OnPow2Changed(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.Pow2LimitBlocks = (int)args.NewValue;
        }
    }

    private void OnPow2SizeCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing && Fmt.ParseSize(Pow2SizeBox.Text) is { } size and > 0)
        {
            Vm.Pow2LimitSize = size;
        }
    }

    private void OnFirstBlockChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!_syncing && !double.IsNaN(args.NewValue))
        {
            Vm.FirstRecoveryBlock = (int)args.NewValue;
        }
    }

    private void OnCommentCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.Comment = CommentBox.Text;
        }
    }

    private void OnFlagsChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
        {
            return;
        }

        Vm.Overwrite = OverwriteBox.IsChecked == true;
        Vm.StdNaming = StdNamingBox.IsChecked == true;
    }

    private void OnUnicodeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && UnicodeBox.SelectedIndex >= 0)
        {
            Vm.Unicode = (UnicodePolicy)UnicodeBox.SelectedIndex;
        }
    }

    // ---- actions ----

    private void OnCreate(object sender, RoutedEventArgs e) => _shell!.StartCreate(showProgress: true);

    private void OnAddToQueue(object sender, RoutedEventArgs e) => _shell!.StartCreate(showProgress: false);

    /// <summary>
    /// Scrolls the form to its Preview card, for the screenshot harness.
    /// </summary>
    /// <remarks>
    /// THE PREVIEW CARD IS BELOW THE FOLD at the app's own 1280 x 860 default, and
    /// that is where the cost bar lives - so the standard `--shot create` frame
    /// shows the form and not the one chart on this screen. The whole prettiness
    /// review came out of looking at pictures, and a deliverable that appears in no
    /// picture has not been looked at. Chip C hit the same thing with the Comment
    /// and volume-ceiling controls and reached them the same way.
    /// <para>
    /// UpdateLayout FIRST: the extent is otherwise still the frame before the
    /// preview was filled in, and the scroll lands short of the bottom.
    /// </para>
    /// </remarks>
    public void ScrollToPreview()
    {
        FormView.UpdateLayout();
        FormView.ChangeView(null, FormView.ScrollableHeight, null, disableAnimation: true);
    }

    private void OnCopyCommand(object sender, RoutedEventArgs e) => _shell!.CopyCommandCommand.Execute(null);

    private void OnToggleLog(object sender, RoutedEventArgs e) => _shell!.ToggleLog();
}
