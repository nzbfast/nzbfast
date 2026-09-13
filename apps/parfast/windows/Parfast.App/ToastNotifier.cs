using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace Parfast.App;

/// <summary>
/// Completion notifications through <c>AppNotificationManager</c> (plan 6.2).
/// </summary>
/// <remarks>
/// An UNPACKAGED app has no package identity, so AppNotificationManager registers
/// one at runtime. Two consequences worth knowing before changing anything here:
/// Register must be called before the first Show or the call throws, and the
/// notification carries the exe's own icon rather than a package logo.
/// <para>
/// Every call is guarded. On Windows 10 1809, which is the plan's floor, the
/// Windows App SDK's notification stack is not available at all, and a
/// notification that cannot be posted must not take down the job that finished.
/// So a failure here is recorded in <see cref="LastError"/> and otherwise
/// ignored: the work succeeded, only the announcement did not.
/// </para>
/// </remarks>
public sealed class ToastNotifier
{
    private bool _registered;
    private bool _unavailable;

    public string? LastError { get; private set; }

    public void Post(string title, string body)
    {
        if (_unavailable)
        {
            return;
        }

        try
        {
            if (!_registered)
            {
                AppNotificationManager.Default.Register();
                _registered = true;
            }

            var notification = new AppNotificationBuilder()
                .AddText(title)
                .AddText(body)
                .BuildNotification();
            AppNotificationManager.Default.Show(notification);
        }
        catch (Exception e)
        {
            // Broad on purpose. The failure modes are a missing runtime component,
            // a COM registration error and a policy block, which surface as at
            // least three different exception types across Windows versions, and
            // the right answer to all of them is the same: stop trying, and say
            // why if anyone asks.
            LastError = e.Message;
            _unavailable = true;
        }
    }
}
