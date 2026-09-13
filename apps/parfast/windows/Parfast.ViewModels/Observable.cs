using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace Parfast.ViewModels;

/// <summary>
/// The smallest MVVM base that does the job.
/// </summary>
/// <remarks>
/// Hand written rather than taken from CommunityToolkit.Mvvm on purpose. The
/// WinUI app already needs a NuGet restore of the Windows App SDK on a build
/// box that has never restored a .NET package, and every package this solution
/// does not need is one fewer thing to go wrong there. The cost is this file.
/// </remarks>
public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        Raise(name);
        return true;
    }

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name ?? string.Empty));

    /// <summary>Raises several names at once, for a computed cluster.</summary>
    protected void RaiseAll(params string[] names)
    {
        foreach (var name in names)
        {
            Raise(name);
        }
    }
}

/// <summary>A command with an explicit CanExecute, refreshed by the owner.</summary>
public sealed class Command(Action run, Func<bool>? can = null) : ICommand
{
    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => can?.Invoke() ?? true;

    public void Execute(object? parameter)
    {
        if (CanExecute(parameter))
        {
            run();
        }
    }

    public void Refresh() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>
/// Where a view model posts work that must run on the UI thread.
/// </summary>
/// <remarks>
/// The whole cross-thread story of this app is this one interface. The core's
/// wake callback fires from any thread; the view models never touch their own
/// collections from it. They call <see cref="Post"/> and the WinUI
/// implementation hands the work to the window's DispatcherQueue, while the
/// tests run it inline. Nothing else in the app is allowed to know about
/// threads.
/// </remarks>
public interface IUiDispatcher
{
    void Post(Action work);
}

/// <summary>Runs the work where it is called. Used by the unit tests.</summary>
public sealed class ImmediateDispatcher : IUiDispatcher
{
    public void Post(Action work) => work();
}

/// <summary>An ObservableCollection that can be refilled without N notifications.</summary>
public sealed class Rows<T> : ObservableCollection<T>
{
    /// <summary>
    /// Replaces the contents in place, reusing the existing items where the
    /// key matches, so a ten thousand row table does not rebuild every item on
    /// every 10 Hz poll and a selection survives a refresh.
    /// </summary>
    public void Sync<TKey>(IEnumerable<T> incoming, Func<T, TKey> key, Action<T, T> update)
        where TKey : notnull
    {
        var list = incoming as IList<T> ?? incoming.ToList();
        var existing = new Dictionary<TKey, T>(Count);
        foreach (var item in this)
        {
            existing[key(item)] = item;
        }

        for (var i = 0; i < list.Count; i++)
        {
            var k = key(list[i]);
            if (i < Count && Equals(key(this[i]), k))
            {
                update(this[i], list[i]);
                continue;
            }

            if (existing.TryGetValue(k, out var found))
            {
                update(found, list[i]);
                var at = IndexOf(found);
                if (at != i)
                {
                    Move(at, i);
                }

                continue;
            }

            Insert(i, list[i]);
        }

        while (Count > list.Count)
        {
            RemoveAt(Count - 1);
        }
    }

    public void Reset(IEnumerable<T> items)
    {
        Clear();
        foreach (var item in items)
        {
            Add(item);
        }
    }
}
