using System.Diagnostics;
using System.Runtime.InteropServices;
using Parfast.Core.Contracts;

namespace Parfast.App;

/// <summary>
/// Sleeping or shutting the machine down when the queue drains (plan 5.5).
/// </summary>
/// <remarks>
/// The core reports the action as due and refuses to perform it, deliberately:
/// it is a platform call and a decision a human has to be able to stop
/// (crates/parfast-ffi/API.md). This is the Windows half.
/// <para>
/// SHUTDOWN IS DELAYED SIXTY SECONDS AND IS CANCELLABLE. <c>shutdown /s /t 60</c>
/// puts up the system's own warning, which the user can stop with
/// <c>shutdown /a</c> - and Windows tells them so. An immediate shutdown from a
/// background app is indistinguishable from a crash or a power cut, and the user
/// who set this an hour ago is not necessarily the person at the desk now.
/// </para>
/// <para>
/// Sleep goes through <c>SetSuspendState</c> rather than through
/// <c>shutdown /h</c>: the shutdown verb's sleep arm is hibernate, and asking for
/// sleep and getting hibernate is a different thing happening to the user's
/// machine than the one they chose.
/// </para>
/// </remarks>
public static class PowerActions
{
    public static bool Perform(PostQueueAction action)
    {
        try
        {
            switch (action)
            {
                case PostQueueAction.Sleep:
                    // hibernate: false is sleep; forceCritical: false so a driver
                    // that refuses is heard rather than overridden; wakeupEventsDisabled:
                    // false so the machine can still be woken normally.
                    return SetSuspendState(hibernate: false, forceCritical: false, wakeupEventsDisabled: false);

                case PostQueueAction.Shutdown:
                    Process.Start(new ProcessStartInfo("shutdown.exe", "/s /t 60")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    });
                    return true;

                default:
                    return false;
            }
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception
                                     or InvalidOperationException
                                     or PlatformNotSupportedException
                                     or EntryPointNotFoundException)
        {
            // A policy-blocked shutdown, a missing powrprof, or a machine that
            // cannot sleep. The queue has finished either way, which is the part
            // that mattered; the user is at worst left with the machine awake.
            return false;
        }
    }

    [DllImport("powrprof.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool SetSuspendState(
        [MarshalAs(UnmanagedType.I1)] bool hibernate,
        [MarshalAs(UnmanagedType.I1)] bool forceCritical,
        [MarshalAs(UnmanagedType.I1)] bool wakeupEventsDisabled);
}
