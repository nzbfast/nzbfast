using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Parfast.Core.Contracts;
using Parfast.ViewModels;

namespace Parfast.App.Views;

/// <summary>Queue (plan section 5.5).</summary>
public sealed partial class QueuePage : UserControl
{
    /// <summary>
    /// The concurrency choices the picker offers: one at a time, then a short
    /// ladder. Not a NumberBox up to the core count: the honest answer for almost
    /// everyone is one, and a spinner invites a number that makes every job slower.
    /// </summary>
    private static readonly int[] ConcurrencyChoices = [1, 2, 3, 4];

    private ShellViewModel? _shell;
    private bool _syncing;

    public QueuePage() => InitializeComponent();

    private QueueViewModel Vm => _shell!.Queue;

    public void Bind(ShellViewModel shell)
    {
        _shell = shell;
        Localise();
        shell.Queue.PropertyChanged += (_, _) => Sync();
        shell.Queue.Rows.CollectionChanged += (_, _) => Sync();
        Sync();
    }

    private void Localise()
    {
        RunNowButton.Content = Strings.QueueRunNow;
        CancelButton.Content = Strings.CommonCancel;
        RemoveButton.Content = Strings.CommonRemove;
        ClearButton.Content = Strings.QueueClearFinished;
        EmptyTitle.Text = Strings.EmptyQueueTitle;
        EmptyBody.Text = Strings.EmptyQueueBody;
        ColKind.Text = Strings.CommonKind;
        ColName.Text = Strings.CommonName;
        ColStatus.Text = Strings.CommonStatus;
        ColProgress.Text = Strings.CommonProgress;
        ColAdded.Text = Strings.CommonAdded;
        ConcurrencyLabel.Text = Strings.QueueConcurrency;
        PostLabel.Text = Strings.QueueWhenFinished;

        ConcurrencyBox.Items.Clear();
        foreach (var n in ConcurrencyChoices)
        {
            ConcurrencyBox.Items.Add(n == 1
                ? Strings.QueueConcurrencyOne
                : Strings.Fill(Strings.QueueConcurrencyN, "n", Fmt.Count(n)));
        }

        PostBox.Items.Clear();
        foreach (var label in new[]
                 {
                     Strings.QueueFinishNone, Strings.QueueFinishNotify,
                     Strings.QueueFinishSleep, Strings.QueueFinishShutdown,
                 })
        {
            PostBox.Items.Add(label);
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
            RowList.ItemsSource = Vm.Rows;
            EmptyState.Visibility = Vm.IsEmpty ? Visibility.Visible : Visibility.Collapsed;
            TableCard.Visibility = Vm.IsEmpty ? Visibility.Collapsed : Visibility.Visible;

            PauseButton.Content = Vm.PauseText;
            CountText.Text = Vm.IsEmpty
                ? string.Empty
                : $"{Fmt.Count(Vm.RunningCount)} running, {Fmt.Count(Vm.WaitingCount)} waiting";

            RunNowButton.IsEnabled = Vm.RunNowCommand.CanExecute(null);
            CancelButton.IsEnabled = Vm.CancelSelectedCommand.CanExecute(null);
            RemoveButton.IsEnabled = Vm.RemoveCommand.CanExecute(null);
            ClearButton.IsEnabled = Vm.ClearFinishedCommand.CanExecute(null);

            var index = Array.IndexOf(ConcurrencyChoices, Vm.Concurrency);
            ConcurrencyBox.SelectedIndex = index < 0 ? 0 : index;
            PostBox.SelectedIndex = (int)Vm.PostAction;
        }
        finally
        {
            _syncing = false;
        }

        ShowPendingConfirmation();
    }

    /// <summary>
    /// Sleep and shut down are confirmed ONCE, when chosen (plan section 5.5). The
    /// view model raises the request and the view asks; keeping the dialog out of
    /// the view model is what lets the tests assert that the request was raised.
    /// </summary>
    private async void ShowPendingConfirmation()
    {
        if (Vm.PendingConfirmation is not { } message)
        {
            return;
        }

        Vm.PendingConfirmation = null;
        var keep = await Dialogs.ConfirmAsync(
            this, Strings.QueueWhenFinished, message, Strings.QueueWhenFinished, Strings.CommonCancel);
        if (!keep)
        {
            Vm.SetPostAction(PostQueueAction.None);
        }
    }

    private void OnPause(object sender, RoutedEventArgs e) => Vm.PauseCommand.Execute(null);

    private void OnRunNow(object sender, RoutedEventArgs e) => Vm.RunNowCommand.Execute(null);

    private void OnCancel(object sender, RoutedEventArgs e) => Vm.CancelSelectedCommand.Execute(null);

    private void OnRemove(object sender, RoutedEventArgs e) => Vm.RemoveCommand.Execute(null);

    private void OnClear(object sender, RoutedEventArgs e) => Vm.ClearFinishedCommand.Execute(null);

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        Vm.Selected.Clear();
        Vm.Selected.AddRange(RowList.SelectedItems.OfType<QueueRow>());
        RunNowButton.IsEnabled = Vm.RunNowCommand.CanExecute(null);
        CancelButton.IsEnabled = Vm.CancelSelectedCommand.CanExecute(null);
        RemoveButton.IsEnabled = Vm.RemoveCommand.CanExecute(null);
    }

    private void OnConcurrencyChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && ConcurrencyBox.SelectedIndex >= 0)
        {
            Vm.SetConcurrency(ConcurrencyChoices[ConcurrencyBox.SelectedIndex]);
        }
    }

    private void OnPostChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && PostBox.SelectedIndex >= 0)
        {
            Vm.SetPostAction((PostQueueAction)PostBox.SelectedIndex);
        }
    }
}
