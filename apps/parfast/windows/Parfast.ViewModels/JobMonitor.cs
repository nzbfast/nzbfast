using Parfast.Core;
using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>
/// Turns the core's wake callback into UI-thread updates, and holds the poll.
/// </summary>
/// <remarks>
/// THE ONE PLACE THAT KNOWS ABOUT THREADS. The contract (plan section 3.2) is
/// that the wake callback carries no data and may fire from any thread, and the
/// host marshals to its UI thread and then polls. That is exactly what this
/// class does, and every view model above it only ever sees a fresh
/// <see cref="QueueSnapshot"/> arriving on the UI thread.
/// <para>
/// It also COALESCES. The core promises at most about twenty wakes a second and
/// the plan budgets a 10 Hz poll, so a flag plus a posted pump means a burst of
/// wakes costs one snapshot read rather than twenty, and a slow UI thread cannot
/// build a backlog of posted work.
/// </para>
/// </remarks>
public sealed class JobMonitor : IDisposable
{
    private readonly ICoreClient _core;
    private readonly IUiDispatcher _ui;
    private readonly object _gate = new();
    private bool _pumpPosted;
    private bool _disposed;

    public JobMonitor(ICoreClient core, IUiDispatcher ui)
    {
        _core = core;
        _ui = ui;
        _core.Wake += OnWake;
    }

    /// <summary>Raised on the UI thread with a fresh queue snapshot.</summary>
    public event Action<QueueSnapshot>? Updated;

    public QueueSnapshot Latest { get; private set; } = QueueSnapshot.Empty;

    /// <summary>Reads once now, without waiting for a wake.</summary>
    public void Refresh()
    {
        var snapshot = _core.QueueSnapshot();
        Latest = snapshot;
        Updated?.Invoke(snapshot);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _core.Wake -= OnWake;
    }

    private void OnWake()
    {
        lock (_gate)
        {
            if (_disposed || _pumpPosted)
            {
                return;
            }

            _pumpPosted = true;
        }

        _ui.Post(Pump);
    }

    private void Pump()
    {
        lock (_gate)
        {
            _pumpPosted = false;
            if (_disposed)
            {
                return;
            }
        }

        Refresh();
    }
}
