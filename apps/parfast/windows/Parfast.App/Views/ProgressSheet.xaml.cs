using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Parfast.ViewModels;

namespace Parfast.App.Views;

/// <summary>
/// The progress sheet of plan section 5.3, used by every job kind.
/// </summary>
/// <remarks>
/// ITS BUTTONS ARE IN THE CONTENT, NOT THE DIALOG'S OWN BUTTON ROW, and that is
/// on purpose. A ContentDialog's primary and close buttons dismiss the dialog when
/// clicked, and Pause must not: the sheet has to stay open with the button now
/// reading Resume. Handling the dismissal by cancelling the button's event is
/// possible and fights the control; putting the buttons in the content is
/// simpler and gives the right behaviour by construction.
/// <para>
/// Cancel asks for confirmation while a job is running (plan 5.2: "Escape cancels
/// a running verify with a confirm"). The confirmation is an INLINE bar inside
/// this sheet rather than a second dialog, because WinUI permits exactly one
/// ContentDialog open at a time and a nested one throws instead of asking. After
/// the job has settled there is nothing to lose, so Close needs no confirmation.
/// </para>
/// </remarks>
public sealed partial class ProgressSheet : ContentDialog
{
    private readonly ProgressViewModel _vm;

    public ProgressSheet(ProgressViewModel vm, XamlRoot root)
    {
        InitializeComponent();
        _vm = vm;
        XamlRoot = root;

        ElapsedLabel.Text = Strings.ProgressElapsed;
        RemainingLabel.Text = Strings.ProgressRemaining;
        RateLabel.Text = Strings.ProgressRate;
        LowPriorityBox.Content = Strings.ProgressBackground;
        NotifyBox.Content = Strings.ProgressNotify;
        CancelButton.Content = Strings.CommonCancel;
        CloseButton.Content = Strings.CommonClose;
        ConfirmBar.Title = Strings.ProgressCancelConfirm;
        ConfirmBar.Message = Strings.ProgressCancelConfirmBody;
        ConfirmStop.Content = Strings.ProgressCancelConfirmStop;
        ConfirmKeep.Content = Strings.ProgressCancelConfirmKeep;

        vm.PropertyChanged += (_, _) => Sync();
        Sync();
    }

    private bool _syncing;

    private void Sync()
    {
        if (_syncing)
        {
            return;
        }

        _syncing = true;
        try
        {
            Title = _vm.Title;
            Bar.Value = _vm.Progress;

            // Indeterminate through a phase the engine cannot measure. API.md:
            // "a bar that sat at a number would be a claim".
            Bar.IsIndeterminate = _vm.IsIndeterminate;
            Bar.ShowPaused = _vm.IsPaused;
            StatusLine.Text = _vm.StatusLine;
            PercentText.Text = _vm.PercentText;
            ElapsedValue.Text = _vm.ElapsedText;
            RemainingValue.Text = _vm.RemainingText;
            RateValue.Text = _vm.RateText;

            // Assign AND Refresh, then show or hide the pair together. The history is
            // one object mutated in place for the life of the sheet, so assigning it is
            // not a change WinUI can notice - see the Sparkline's own remarks. Both the
            // chart and the sentence go away while there is nothing to plot: a flat line
            // along the floor of an empty chart reads as a stall rather than as an
            // absence of measurement, and the figure above it already says 0 MB/s.
            RateChart.Model = _vm.Rates;
            RateChart.Refresh();
            var showTrend = _vm.ShowRateTrend;
            RateChart.Visibility = showTrend ? Visibility.Visible : Visibility.Collapsed;
            RateTrend.Text = _vm.RateTrendText;
            RateTrend.Visibility = showTrend && _vm.RateTrendText.Length > 0
                ? Visibility.Visible
                : Visibility.Collapsed;
            LogLines.ItemsSource = _vm.Log;
            LowPriorityBox.IsChecked = _vm.LowPriority;
            LowPriorityBox.Visibility = _vm.ShowLowPriority ? Visibility.Visible : Visibility.Collapsed;
            NotifyBox.IsChecked = _vm.Notify;

            PauseButton.Content = _vm.PauseText;

            // Pause is SHOWN AND DISABLED, with the reason, when the engine cannot
            // reach this job kind right now - rather than hidden. A create that
            // cannot be paused mid-fold is a property of the engine worth telling
            // the user about; a button that silently vanishes once the job starts
            // looks like the app losing its nerve.
            PauseButton.Visibility = _vm.CanPause || _vm.PauseUnavailableReason is not null
                ? Visibility.Visible
                : Visibility.Collapsed;
            PauseButton.IsEnabled = _vm.CanPause;
            ToolTipService.SetToolTip(PauseButton, _vm.PauseUnavailableReason);
            CancelButton.Visibility = _vm.IsActive ? Visibility.Visible : Visibility.Collapsed;
            CloseButton.Visibility = _vm.IsActive ? Visibility.Collapsed : Visibility.Visible;

            // The log scrolls to the bottom as lines arrive, which is what a
            // transcript is for. UpdateLayout first: without it the extent is
            // still the previous frame's and the scroll lands one line short.
            LogScroller.UpdateLayout();
            LogScroller.ChangeView(null, LogScroller.ScrollableHeight, null, disableAnimation: true);

            // A job that has settled has nothing left to stop, so the open
            // confirmation goes away by itself rather than sitting there offering
            // to cancel something that already finished.
            if (!_vm.IsActive)
            {
                ConfirmBar.IsOpen = false;
            }

            if (!_vm.IsOpen)
            {
                Hide();
            }
        }
        finally
        {
            _syncing = false;
        }
    }

    private void OnPause(object sender, RoutedEventArgs e) => _vm.PauseCommand.Execute(null);

    private void OnCancel(object sender, RoutedEventArgs e) => ConfirmBar.IsOpen = true;

    private void OnConfirmStop(object sender, RoutedEventArgs e)
    {
        ConfirmBar.IsOpen = false;
        _vm.CancelCommand.Execute(null);
    }

    private void OnConfirmKeep(object sender, RoutedEventArgs e) => ConfirmBar.IsOpen = false;

    private void OnClose(object sender, RoutedEventArgs e)
    {
        _vm.Close();
        Hide();
    }

    private void OnLowPriorityChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            _vm.LowPriority = LowPriorityBox.IsChecked == true;
        }
    }

    private void OnNotifyChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing)
        {
            _vm.Notify = NotifyBox.IsChecked == true;
        }
    }
}
