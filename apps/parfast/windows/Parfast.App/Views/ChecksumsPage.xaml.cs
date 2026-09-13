using Parfast.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Parfast.Core.Contracts;
using Parfast.ViewModels;

namespace Parfast.App.Views;

/// <summary>Checksums (plan section 5.4): SFV, MD5, SHA-1 and SHA-256, create and verify.</summary>
public sealed partial class ChecksumsPage : UserControl
{
    private ShellViewModel? _shell;
    private bool _syncing;

    public ChecksumsPage() => InitializeComponent();

    private ChecksumsViewModel Vm => _shell!.Checksums;

    public void Bind(ShellViewModel shell)
    {
        _shell = shell;
        Localise();
        shell.Checksums.PropertyChanged += (_, _) => Sync();
        shell.Checksums.Sources.CollectionChanged += (_, _) => Sync();
        shell.Checksums.Rows.CollectionChanged += (_, _) => Sync();
        Sync();
    }

    private void Localise()
    {
        TabCreate.Text = Strings.ChecksumsCreate;
        TabVerify.Text = Strings.ChecksumsVerify;
        FormatLabel.Text = Strings.ChecksumsFormat;
        EmptyTitle.Text = Strings.EmptyChecksumsTitle;
        EmptyBody.Text = Strings.EmptyChecksumsBody;
        EmptyAddFiles.Content = Strings.EmptyCreateAddFiles;
        EmptyAddFolder.Content = Strings.EmptyCreateAddFolder;
        SourcesHeader.Text = Strings.CreateSources;
        AddFiles.Content = Strings.EmptyCreateAddFiles;
        AddFolder.Content = Strings.EmptyCreateAddFolder;
        OutputBox.Header = Strings.ChecksumsOutput;
        BrowseOutput.Content = Strings.CommonBrowse;
        RelativeBox.Content = Strings.ChecksumsRelative;
        ColName.Text = Strings.CommonName;
        ColExpected.Text = Strings.ChecksumsExpected;
        ColStatus.Text = Strings.CommonStatus;
        LogButton.Content = Strings.CommonLog;
        VerifyAgainButton.Content = Strings.ChecksumsVerifyAgain;
        CreateButton.Content = Strings.ChecksumsCreate;

        FormatBox.Items.Clear();
        foreach (var name in new[] { "SFV", "MD5", "SHA-1", "SHA-256" })
        {
            FormatBox.Items.Add(name);
        }

        FormatBox.SelectedIndex = 0;
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
            var verifying = Vm.Verifying;
            CreateView.Visibility = verifying ? Visibility.Collapsed : Visibility.Visible;
            VerifyView.Visibility = verifying ? Visibility.Visible : Visibility.Collapsed;
            TabCreate.IsSelected = !verifying;
            TabVerify.IsSelected = verifying;

            // The format picker belongs to Create only: in Verify the format is
            // whatever the opened file is, and offering a choice there would look
            // like an option to reinterpret the file.
            FormatRow.Visibility = verifying ? Visibility.Collapsed : Visibility.Visible;
            FormatBox.SelectedIndex = (int)Vm.Format;

            SourceList.ItemsSource = Vm.Sources;
            CreateEmpty.Visibility = Vm.Sources.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            CreateCard.Visibility = Vm.Sources.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
            OutputBox.Text = Vm.Output;
            RelativeBox.IsChecked = Vm.Relative;

            RowList.ItemsSource = Vm.Rows;
            NoDetailBar.IsOpen = Vm.ShowNoDetailNote;
            NoDetailBar.Message = Vm.NoDetailNote;
            RowList.Visibility = Vm.ShowNoDetailNote ? Visibility.Collapsed : Visibility.Visible;
            FileLabel.Text = Vm.ChecksumFile is { } file ? PathUtil.FileName(file) : string.Empty;
            PassBar.Value = Vm.PassFraction;
            PassBar.ShowPaused = Vm.SummaryTone == PillTone.Bad;

            Summary.Text = Vm.SummaryText;
            Summary.Tone = Vm.SummaryTone;
            Summary.IsBusy = Vm.IsBusy;

            CreateButton.Visibility = verifying ? Visibility.Collapsed : Visibility.Visible;
            CreateButton.IsEnabled = Vm.CreateCommand.CanExecute(null);
            VerifyAgainButton.Visibility = verifying ? Visibility.Visible : Visibility.Collapsed;
            VerifyAgainButton.IsEnabled = Vm.VerifyAgainCommand.CanExecute(null);
        }
        finally
        {
            _syncing = false;
        }
    }

    private void OnSubModeChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
    {
        if (!_syncing)
        {
            Vm.Verifying = TabVerify.IsSelected;
        }
    }

    private void OnFormatChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && FormatBox.SelectedIndex >= 0)
        {
            Vm.Format = (ChecksumFormat)FormatBox.SelectedIndex;
        }
    }

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

    private void OnOutputCommitted(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.Output = OutputBox.Text;
        }
    }

    private async void OnBrowseOutput(object sender, RoutedEventArgs e)
    {
        var extension = ChecksumsViewModel.ExtensionOf(Vm.Format);
        var name = string.IsNullOrEmpty(Vm.Output) ? "checksums" + extension : PathUtil.FileName(Vm.Output);
        var path = await Pickers.SaveFileAsync(this, name, "Checksum file", [extension]);
        if (path is not null)
        {
            Vm.Output = path;
        }
    }

    private void OnRelativeChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            Vm.Relative = RelativeBox.IsChecked == true;
        }
    }

    private void OnCreate(object sender, RoutedEventArgs e)
    {
        Vm.CreateCommand.Execute(null);
        _shell!.Progress.Open(Vm.JobId);
    }

    private void OnVerifyAgain(object sender, RoutedEventArgs e) => Vm.VerifyAgainCommand.Execute(null);

    private void OnToggleLog(object sender, RoutedEventArgs e) => _shell!.ToggleLog();
}
