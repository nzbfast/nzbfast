using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Parfast.Core;
using Parfast.Core.Contracts;
using Parfast.ViewModels;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;

namespace Parfast.App;

/// <summary>
/// The one window: the mode picker, the drag strip, the pages and the log drawer.
/// </summary>
/// <remarks>
/// It is the ONLY type in the app that knows about Windows: the DispatcherQueue,
/// the backdrop, the title bar, the clipboard, notifications, the registry and
/// the file pickers all enter through here or through the helpers it owns.
/// Everything above it is <see cref="ShellViewModel"/>, which is plain .NET and
/// tested on any host.
/// </remarks>
public sealed partial class MainWindow : Window, IShellHost, IUiDispatcher
{
    private readonly ShellViewModel _shell;
    private readonly DispatcherQueue _queue;
    private readonly ToastNotifier _toasts = new();
    private readonly ICoreClient _core;
    private Views.ProgressSheet? _sheet;

    private readonly CommandLineOptions _options;

    /// <summary>The last RESTORED (un-maximised) bounds, and whether we are maximised.</summary>
    private SavedWindowFrame? _frame;

    /// <summary>Coalesces the writes a drag would otherwise make one per frame.</summary>
    private DispatcherQueueTimer? _frameSaveTimer;

    /// <summary>A screenshot run neither reads nor writes the remembered window.</summary>
    private bool PersistFrame => !_options.IsScreenshot;

    public MainWindow(ICoreClient core, string? coreFallbackReason, CommandLineOptions? options = null)
    {
        InitializeComponent();
        _options = options ?? new CommandLineOptions();

        _queue = DispatcherQueue.GetForCurrentThread();
        _core = core;
        _shell = new ShellViewModel(core, this, this, new RegistryIntegration(),
            _options.IsScreenshot ? MockStat : Stat);

        ApplyBackdrop();
        ExtendTitleBar();
        LocaliseChrome();
        RestoreOrSizeWindow();

        PageVerify.Bind(_shell);
        PageCreate.Bind(_shell);
        PageChecksums.Bind(_shell);
        PageQueue.Bind(_shell);
        PageSettings.Bind(_shell);

        _shell.PropertyChanged += (_, _) => Sync();
        _shell.Progress.PropertyChanged += (_, _) => SyncProgressSheet();
        Nav.SelectedItem = NavVerify;

        // Whether the window is frontmost decides whether a finished job posts a
        // notification (plan 5.2). Tracked here because only the window knows.
        Activated += (_, e) => _shell.WindowActive = e.WindowActivationState != WindowActivationState.Deactivated;
        AppWindow.Changed += OnAppWindowChanged;
        Closed += (_, _) =>
        {
            SaveWindowFrame();
            _frameSaveTimer?.Stop();
            _shell.Dispose();
            core.Dispose();
        };

        if (_shell.IsMock)
        {
            MockBadge.Visibility = Visibility.Visible;
            MockBadgeText.Text = coreFallbackReason is null
                ? _shell.MockBanner
                : $"{_shell.MockBanner} {coreFallbackReason}";
        }

        ApplyForcedTheme();
        Sync();

        if (_options.IsScreenshot)
        {
            // AFTER THE CONTENT HAS LOADED, not here in the constructor, and the
            // `progress` shot is why. Staging it inline starts the create before
            // Content.XamlRoot exists, and SyncProgressSheet cannot show a
            // ContentDialog without a XamlRoot - so it takes its documented
            // fallback, closes the progress state and leaves the job running on
            // the Queue tab. The picture that came back was the Create screen
            // with a queue badge, which is a perfectly plausible screenshot of
            // the wrong thing: the progress sheet, with its pause, cancel, ETA
            // and rate, had no frame at all in the first Windows set (12 Sep
            // 2026) and the run reported 32 of 32 written.
            //
            // Every other shot is unaffected, so this could have stayed a
            // one-case special. It is not, because "stage the app once it is
            // actually a window" is true of all of them and the next state that
            // needs a XamlRoot would fail the same silent way.
            if (Content is FrameworkElement fe)
            {
                fe.Loaded += (_, _) => StageScreenshot();
            }
            else
            {
                StageScreenshot();
            }
        }
    }

    /// <summary>
    /// Forces light or dark for a screenshot pass.
    /// </summary>
    /// <remarks>
    /// RequestedTheme on the root element, which is where WinUI resolves
    /// ThemeResource and where ActualTheme propagates from, so the custom-drawn
    /// controls pick the right palette too. Setting it on the Application would
    /// not: an Application's RequestedTheme can only be assigned before the first
    /// window exists, and by here one does.
    /// </remarks>
    private void ApplyForcedTheme()
    {
        if (_options.Theme is not { } theme || Content is not FrameworkElement root)
        {
            return;
        }

        root.RequestedTheme = theme == "dark" ? ElementTheme.Dark : ElementTheme.Light;
    }

    /// <summary>
    /// Drives the window into one named state for the screenshot harness.
    /// </summary>
    /// <remarks>
    /// The harness (tools/screenshots.ps1) starts one process per picture and
    /// captures the window after a fixed settle, so this method's job is to reach
    /// a state that is STILL when the shutter opens. Hence the mock's
    /// <see cref="Parfast.Core.Mock.MockCore.Speed"/>: the scenarios that need to
    /// be finished are run fast, and the one that has to be caught mid flight is
    /// run slow enough that the settle lands in the middle of it rather than at
    /// whatever frame the timer happened to reach.
    /// </remarks>
    private void StageScreenshot()
    {
        if (_core is Parfast.Core.Mock.MockCore mock)
        {
            mock.Speed = _options.Shot is "verifying" or "progress" ? 0.35 : 6.0;
        }

        var scenario = _options.Scenario ?? "damaged";
        var par2 = $@"D:\Usenet\complete\{scenario}.par2";

        switch (_options.Shot)
        {
            case "empty":
                _shell.Mode = Mode.Verify;
                break;

            case "verify":
            case "verifying":
                _shell.Mode = Mode.Verify;
                _shell.Verify.Open(par2, autoRepair: false);
                break;

            case "repaired":
                _shell.Mode = Mode.Verify;
                _shell.Verify.Open(par2, autoRepair: true);
                break;

            case "failed":
                _shell.Mode = Mode.Verify;
                _shell.Verify.Open(@"D:\Usenet\incomplete\broken.par2", autoRepair: false);
                break;

            case "create":
                _shell.Mode = Mode.Create;
                _shell.Create.Add(SampleSources());
                break;

            // The same screen scrolled to its Preview card, which is below the fold
            // at the default window size and is where the cost bar of the 12 Sep
            // prettiness review lives. A separate state rather than scrolling the
            // `create` shot, because that frame is the FORM and comparing two rounds
            // of it means comparing the same view.
            case "create-preview":
                _shell.Mode = Mode.Create;
                _shell.Create.Add(SampleSources());
                PageCreate.ScrollToPreview();
                break;

            case "progress":
                _shell.Mode = Mode.Create;
                _shell.Create.Add(SampleSources());
                _shell.StartCreate(showProgress: true);
                break;

            case "checksums":
                _shell.Mode = Mode.Checksums;
                _shell.Checksums.Open(@"D:\Usenet\complete\holiday-photos-2026.sfv");
                break;

            case "queue":
                _shell.Mode = Mode.Queue;
                _shell.Create.Add(SampleSources());
                _shell.Create.Start();
                _shell.Create.Start();
                _shell.Create.Start();
                break;

            case "settings":
                _shell.Mode = Mode.Settings;
                break;

            case "log":
                _shell.Mode = Mode.Verify;
                _shell.Verify.Open(par2, autoRepair: false);
                _shell.ToggleLog();
                break;
        }
    }

    /// <summary>
    /// The Create screen's sources for a screenshot, sized by the mock rather
    /// than by the disk, so the picture is the same on any box.
    /// </summary>
    private static IReadOnlyList<string> SampleSources() =>
    [
        @"D:\Work\new-set\new-set.part1.rar",
        @"D:\Work\new-set\new-set.part2.rar",
        @"D:\Work\new-set\new-set.part3.rar",
    ];

    /// <summary>
    /// Opens a path handed in by the association, a shell verb or a drop.
    /// </summary>
    /// <param name="verb">
    /// "verify" or "create" when an Explorer verb said which it meant, else null
    /// to let the drop router decide from the extension. The verb wins, because
    /// "Create PAR2 with parfast" on a .par2 file is a legitimate thing to ask
    /// for and routing it to Verify would be the app overruling the user.
    /// </param>
    public void OpenPath(string path, string? verb = null)
    {
        switch (verb)
        {
            case "create":
                _shell.Mode = Mode.Create;
                _shell.Create.Add([path]);
                break;
            case "verify":
                _shell.Mode = Mode.Verify;
                _shell.Verify.Open(path, _shell.Settings.VerifyThenRepair);
                break;
            default:
                _shell.OpenFromCommandLine(path);
                break;
        }
    }

    // ---- IUiDispatcher ----

    /// <summary>
    /// Marshals the core's wake onto the UI thread (plan section 3.2).
    /// </summary>
    /// <remarks>
    /// TryEnqueue and not a check-then-run: the wake can arrive after the window
    /// has closed and its queue has shut down, and TryEnqueue returns false there
    /// rather than throwing. Dropping a wake at that point is exactly right, since
    /// there is nothing left to repaint.
    /// </remarks>
    public void Post(Action work) => _queue.TryEnqueue(() => work());

    // ---- IShellHost ----

    public void Notify(string title, string body) => _toasts.Post(title, body);

    public void Reveal(string path) => Shell32.Reveal(path);

    /// <summary>
    /// Where this app keeps its data, which is where the core persists the queue.
    /// </summary>
    /// <remarks>
    /// LocalApplicationData and not Roaming: a queue names absolute paths on THIS
    /// machine, so roaming it to another one would restore jobs pointing at files
    /// that are not there.
    /// </remarks>
    public string? QueueStorePath
    {
        get
        {
            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "parfast");
                Directory.CreateDirectory(dir);
                return Path.Combine(dir, "queue.json");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // No store rather than no app: the queue simply does not persist.
                return null;
            }
        }
    }

    public bool PerformPostQueueAction(PostQueueAction action) => PowerActions.Perform(action);

    public void SetClipboard(string text)
    {
        var package = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
        package.SetText(text);
        Clipboard.SetContent(package);
    }

    // ---- chrome ----

    /// <summary>
    /// Mica, falling back to Acrylic and then to a plain surface.
    /// </summary>
    /// <remarks>
    /// The fallback chain is not decoration: Mica needs Windows 11 build 22000,
    /// Acrylic needs 1903, and the plan's floor is Windows 10 1809. On 1809 both
    /// controllers report unsupported and the window paints the theme's own
    /// background, which is a plain window rather than a broken one.
    /// </remarks>
    private void ApplyBackdrop()
    {
        if (MicaController.IsSupported())
        {
            SystemBackdrop = new MicaBackdrop { Kind = MicaKind.Base };
            return;
        }

        if (DesktopAcrylicController.IsSupported())
        {
            SystemBackdrop = new DesktopAcrylicBackdrop();
        }
    }

    /// <summary>
    /// Extends the title bar into the client area and makes the top strip
    /// draggable (plan 6.2).
    /// </summary>
    /// <remarks>
    /// SetTitleBar is what tells Windows which element is the drag region. Without
    /// it, ExtendsContentIntoTitleBar leaves a window that cannot be moved by its
    /// own top edge, which is the most common way this is got wrong.
    /// </remarks>
    private void ExtendTitleBar()
    {
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(TitleStrip);
        // THE STAGE IS IN THE TITLE because it is the only surface this app has
        // for it: there is no About box and no version anywhere in the Windows
        // UI, so without this a tester who installed a pre-release has nothing
        // on screen telling them so. It also reaches the taskbar and the window
        // switcher, which is where somebody actually looks. Stage-neutral on
        // purpose: it reads Strings.AppStage, so alpha -> beta at 1.6.0 needed
        // no edit here and neither will the next move.
        //
        // The window title only - NOT Strings.AppName itself, which names the
        // product in a dozen other places (the drop caption below, the
        // installer, the file associations) and must stay "parfast".
        Title = $"{Strings.AppName} ({Strings.AppStage.ToLowerInvariant()})";

        if (AppWindow.TitleBar is { } bar)
        {
            bar.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
            bar.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
        }
    }

    /// <summary>
    /// Restores the remembered window, or applies the first-run default.
    /// </summary>
    /// <remarks>
    /// Until 12 Sep 2026 this was <see cref="SizeWindow"/> alone, called
    /// UNCONDITIONALLY on every launch, so whatever size the user left the
    /// window at was overridden on the next start and the position was never
    /// saved at all. Found while testing the alpha: "lets make it remember a
    /// resize for the next time it starts up so people can make it bigger if
    /// they want to". <see cref="SizeWindow"/> is now the FIRST-RUN path and
    /// nothing else.
    /// <para>
    /// The recover rule - what a saved frame turns into on the displays
    /// attached right now - is <see cref="WindowFrameRule"/>, shared in shape
    /// with the mac app and unit-tested on any host. Everything platform-shaped
    /// is here: reading the displays, the DPI, and applying the result.
    /// </para>
    /// </remarks>
    private void RestoreOrSizeWindow()
    {
        var saved = PersistFrame ? WindowFrameStore.Load() : null;
        if (saved is null)
        {
            SizeWindow();
            RememberCurrentFrame();
            return;
        }

        // The minimum is a LOGICAL size and everything else here is physical,
        // so it scales like the default does. The DPI is the one the window
        // opened on, which is not necessarily the display it is about to move
        // to; on a mixed-DPI desktop that makes the floor slightly wrong in the
        // direction of "too small", which the work-area clamp then bounds.
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var dpi = GetDpiForWindow(hwnd);
        var scale = dpi == 0 ? 1.0 : dpi / 96.0;

        var outcome = WindowFrameRule.Recover(
            new WindowRect(saved.X, saved.Y, saved.Width, saved.Height),
            saved.Maximised,
            WorkAreas(),
            (int)Math.Round(Tokens.Size.WindowMinWidth * scale),
            (int)Math.Round(Tokens.Size.WindowMinHeight * scale));

        var bounds = outcome.Bounds;
        if (outcome.PlaceByOS)
        {
            // The saved origin named no attached display. Keep the size and let
            // Windows place the window where it would have anyway.
            AppWindow.Resize(new Windows.Graphics.SizeInt32(bounds.Width, bounds.Height));
        }
        else
        {
            AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(
                bounds.X, bounds.Y, bounds.Width, bounds.Height));
        }

        RememberCurrentFrame();

        // AFTER the move, so the window maximises onto the display the rule
        // chose rather than onto whichever one it happened to open on.
        if (outcome.Maximised && AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.Maximize();
        }
    }

    /// <summary>
    /// The work area of every attached display, PRIMARY FIRST, which is the
    /// order <see cref="WindowFrameRule"/> is written against.
    /// </summary>
    /// <remarks>
    /// WorkArea and not OuterBounds: it already excludes the taskbar, wherever
    /// the user keeps it, which is what makes it the rectangle a window has to
    /// fit inside.
    /// </remarks>
    private static List<WindowRect> WorkAreas()
    {
        var areas = new List<WindowRect>();
        var primary = DisplayArea.Primary;
        if (primary is not null)
        {
            areas.Add(ToRect(primary.WorkArea));
        }

        foreach (var area in DisplayArea.FindAll())
        {
            if (primary is null || area.DisplayId.Value != primary.DisplayId.Value)
            {
                areas.Add(ToRect(area.WorkArea));
            }
        }

        return areas;
    }

    private static WindowRect ToRect(Windows.Graphics.RectInt32 r) =>
        new(r.X, r.Y, r.Width, r.Height);

    /// <summary>
    /// Tracks the geometry worth remembering as the user moves and sizes.
    /// </summary>
    /// <remarks>
    /// THE RESTORED BOUNDS ARE ONLY READ WHILE THE PRESENTER SAYS RESTORED,
    /// which is what keeps the pre-maximise size. <c>AppWindow.Position</c> and
    /// <c>Size</c> report the MAXIMISED rectangle while a window is maximised,
    /// so a handler that took them unconditionally would remember the screen
    /// rather than the window, and un-maximising after a restart would spring
    /// the window to full size instead of back to what the user had.
    /// </remarks>
    private void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (!args.DidPositionChange && !args.DidSizeChange && !args.DidPresenterChange)
        {
            return;
        }

        RememberCurrentFrame();
        ScheduleFrameSave();
    }

    private void RememberCurrentFrame()
    {
        var maximised = AppWindow.Presenter
            is OverlappedPresenter { State: OverlappedPresenterState.Maximized };

        if (maximised)
        {
            // Keep the bounds already held: they are the un-maximised ones.
            if (_frame is { } held)
            {
                _frame = held with { Maximised = true };
            }

            return;
        }

        // Minimised reports a position off the desktop, which is not a frame
        // anybody wants back.
        if (AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Minimized })
        {
            return;
        }

        _frame = new SavedWindowFrame
        {
            X = AppWindow.Position.X,
            Y = AppWindow.Position.Y,
            Width = AppWindow.Size.Width,
            Height = AppWindow.Size.Height,
            Maximised = false,
        };
    }

    /// <summary>
    /// Writes the frame two seconds after the last change.
    /// </summary>
    /// <remarks>
    /// Saving only on Closed would be simpler and would lose the frame to
    /// anything that is not a clean close - a kill, a power loss, an update
    /// that restarts the app. Saving on every Changed would write a file per
    /// frame of a drag. The debounce is the middle, and it is what gives this
    /// app the same property the mac half gets free from
    /// <c>setFrameAutosaveName</c>.
    /// </remarks>
    private void ScheduleFrameSave()
    {
        if (!PersistFrame)
        {
            return;
        }

        if (_frameSaveTimer is null)
        {
            _frameSaveTimer = _queue.CreateTimer();
            _frameSaveTimer.Interval = TimeSpan.FromSeconds(2);
            _frameSaveTimer.IsRepeating = false;
            _frameSaveTimer.Tick += OnFrameSaveTick;
        }

        // Stop then Start, which is what makes it a DEBOUNCE rather than a
        // heartbeat: a Start on a running timer does not restart the interval,
        // so a long drag would otherwise write once in the middle of it and
        // never again at the end.
        _frameSaveTimer.Stop();
        _frameSaveTimer.Start();
    }

    private void OnFrameSaveTick(DispatcherQueueTimer sender, object args) => SaveWindowFrame();

    private void SaveWindowFrame()
    {
        if (PersistFrame && _frame is { } frame)
        {
            WindowFrameStore.Save(frame);
        }
    }

    /// <summary>The FIRST-RUN size. See <see cref="RestoreOrSizeWindow"/>.</summary>
    private void SizeWindow()
    {
        // A deliberate default rather than whatever Windows picks: the Create
        // screen is two columns at this width and one below it. The number is
        // `size.window_default_*` in apps/parfast/shared/design/tokens.json, so
        // the mac app opens at the same size from the same table rather than
        // from a second copy of it.
        //
        // The research/ screenshots do NOT depend on this: the demo route sets
        // its own size explicitly, which is what keeps a round comparable to
        // the one before it across a change like this one.
        //
        // SCALED BY THE WINDOW'S DPI, and the unscaled version of this line is
        // what the first run on a real Windows box found (12 Sep 2026).
        // AppWindow.Resize takes PHYSICAL PIXELS, while every size XAML lays out
        // against is a device-independent one, so `Resize(1280, 860)` asks for
        // 1280x860 logical pixels only on a 96 DPI display. On the 192 DPI panel
        // this was first run on it produced a 640x430 LOGICAL canvas - half the
        // intended layout in each direction - and the result was not a smaller
        // window but a WRONG one: the header card's fourth figure (recovery
        // blocks available) fell off the row entirely, the third was clipped
        // mid-number to "1,08", and the mock banner overlapped the title bar.
        // That is the shape worth remembering: a DPI mistake does not look like
        // a DPI mistake, it looks like a layout bug on one machine.
        //
        // 96 is the reference DPI the whole USER32 scaling model is defined
        // against. GetDpiForWindow is per-monitor and the app is PerMonitorV2
        // (DefaultDpiAwareSettings in the Windows App SDK props), so this is the
        // scale for the monitor the window opened on.
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var dpi = GetDpiForWindow(hwnd);
        var scale = dpi == 0 ? 1.0 : dpi / 96.0;

        var wantW = (int)Math.Round(Tokens.Size.WindowDefaultWidth * scale);
        var wantH = (int)Math.Round(Tokens.Size.WindowDefaultHeight * scale);

        // CLAMPED TO THE WORK AREA, which is the half that makes this a
        // default rather than a demand. The size above is what looks right
        // on a desktop; a laptop is the case that has to still work, and on
        // 12 Sep 2026 it did not - the first run on a 13in 2880x1800 panel
        // at 192 DPI opened a window TALLER THAN THE SCREEN, because
        // 860 logical against a 900-logical display leaves nothing for the
        // title bar and the taskbar.
        //
        // WorkArea, not OuterBounds: it already excludes the taskbar,
        // wherever the user keeps it. The margin is for the title bar and
        // the window's own border, which the work area does NOT exclude -
        // without it a window exactly the height of the work area still has
        // its title bar pushed off the top.
        //
        // The floor is the MINIMUM size, deliberately, and it can exceed the
        // work area on a very small display: a window smaller than its own
        // minimum is a layout this app has no design for, so on such a
        // display it is right to overflow and let the user scroll or resize
        // rather than to render something nothing was drawn against.
        var area = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
            AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
        if (area is not null)
        {
            var margin = (int)Math.Round(48 * scale);
            var maxW = Math.Max((int)Math.Round(Tokens.Size.WindowMinWidth * scale),
                                area.WorkArea.Width - margin);
            var maxH = Math.Max((int)Math.Round(Tokens.Size.WindowMinHeight * scale),
                                area.WorkArea.Height - margin);
            wantW = Math.Min(wantW, maxW);
            wantH = Math.Min(wantH, maxH);
        }

        AppWindow.Resize(new Windows.Graphics.SizeInt32(wantW, wantH));
    }

    /// <summary>The window's per-monitor DPI; 96 is 100% scaling.</summary>
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);

    /// <summary>
    /// Fills the chrome's text from the generated copy table.
    /// </summary>
    /// <remarks>
    /// In code rather than through x:Uid on each item. NavigationViewItem's
    /// Content is what x:Uid would set and the generated .resw uses slash-separated
    /// names, so either would work; doing it here keeps the copy for the whole
    /// window in one readable block and means a missing key is a compile error
    /// rather than a blank label at runtime.
    /// </remarks>
    private void LocaliseChrome()
    {
        NavVerify.Content = Strings.ModeVerify;
        NavCreate.Content = Strings.ModeCreate;
        NavChecksums.Content = Strings.ModeChecksums;
        NavQueue.Content = Strings.ModeQueue;
        LogTitle.Text = Strings.LogTitle;
        LogEmpty.Text = Strings.LogEmpty;
        CopyCommand.Content = Strings.CommonCopyCommand;
        CopyLog.Content = Strings.LogCopy;
        ToolTipService.SetToolTip(LogClose, Strings.CommonClose);
    }

    private void OnNavSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            _shell.Mode = Mode.Settings;
            return;
        }

        // Parenthesised: `x as string switch { ... }` is CS8848, because `as` binds
        // looser than the switch expression and the compiler will not guess.
        _shell.Mode = ((args.SelectedItem as NavigationViewItem)?.Tag as string) switch
        {
            "create" => Mode.Create,
            "checksums" => Mode.Checksums,
            "queue" => Mode.Queue,
            _ => Mode.Verify,
        };
    }

    private void OnToggleLog(object sender, RoutedEventArgs e) => _shell.ToggleLog();

    private void OnCopyCommand(object sender, RoutedEventArgs e) => _shell.CopyCommandCommand.Execute(null);

    private void OnCopyLog(object sender, RoutedEventArgs e)
    {
        if (_shell.Log.Count > 0)
        {
            SetClipboard(string.Join(Environment.NewLine, _shell.Log));
            _shell.CopyConfirmation = Strings.CommonCommandCopied;
        }
    }

    /// <summary>
    /// Reflects the shell's state onto the chrome.
    /// </summary>
    /// <remarks>
    /// Visibility rather than a Frame with pages: five pages of a one-window app,
    /// all of which must keep their state when the user switches away and back.
    /// A Frame would either rebuild a page per navigation (losing the sources
    /// table a user spent a minute filling in) or need a cache policy per page,
    /// which is more machinery than five Visibility flips.
    /// </remarks>
    private void Sync()
    {
        PageVerify.Visibility = _shell.IsVerify ? Visibility.Visible : Visibility.Collapsed;
        PageCreate.Visibility = _shell.IsCreate ? Visibility.Visible : Visibility.Collapsed;
        PageChecksums.Visibility = _shell.IsChecksums ? Visibility.Visible : Visibility.Collapsed;
        PageQueue.Visibility = _shell.IsQueue ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = _shell.IsSettings ? Visibility.Visible : Visibility.Collapsed;

        var selected = _shell.Mode switch
        {
            Mode.Create => NavCreate,
            Mode.Checksums => NavChecksums,
            Mode.Queue => NavQueue,
            Mode.Settings => null,
            _ => (NavigationViewItem?)NavVerify,
        };
        if (selected is not null && !ReferenceEquals(Nav.SelectedItem, selected))
        {
            Nav.SelectedItem = selected;
        }

        // The badge on the Queue item: running plus waiting (plan 5.1).
        var badge = _shell.Queue.BadgeCount;
        NavQueue.InfoBadge = badge > 0 ? new InfoBadge { Value = badge } : null;

        LogDrawer.Visibility = _shell.LogVisible ? Visibility.Visible : Visibility.Collapsed;
        if (_shell.LogVisible)
        {
            var empty = _shell.Log.Count == 0;
            LogEmpty.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
            LogScroller.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
            CopyLog.IsEnabled = !empty;
            LogLines.ItemsSource = _shell.Log;

            // Shown for a moment after a copy, then cleared. The view owns the
            // timing because "briefly" is a rendering decision; the view model only
            // says that something was copied.
            CopyConfirmation.Text = _shell.CopyConfirmation ?? string.Empty;
            CopyConfirmation.Visibility = _shell.CopyConfirmation is null
                ? Visibility.Collapsed
                : Visibility.Visible;
            if (_shell.CopyConfirmation is not null)
            {
                ClearCopyConfirmationLater();
            }

            CommandLine.Text = _shell.CommandText;
            CommandLine.Visibility = _shell.ShowCommand && !string.IsNullOrEmpty(_shell.CommandText)
                ? Visibility.Visible
                : Visibility.Collapsed;
            CopyCommand.Visibility = CommandLine.Visibility;
        }
    }

    /// <summary>
    /// Shows or hides the progress sheet to match the view model.
    /// </summary>
    /// <remarks>
    /// The sheet is created fresh each time and dropped when it closes, rather
    /// than kept and reshown. A ContentDialog that has been hidden can be shown
    /// again, but only from the same XamlRoot, and holding one across a theme
    /// change or a window reopen is how a stale dialog ends up refusing to show
    /// with no error. Creating one is cheap; the job it watches is not.
    /// </remarks>
    private async void SyncProgressSheet()
    {
        if (!_shell.Progress.IsOpen)
        {
            _sheet?.Hide();
            _sheet = null;
            return;
        }

        if (_sheet is not null)
        {
            return;
        }

        // A dialog with no XamlRoot throws at ShowAsync. Content.XamlRoot is null
        // until the window's content has been loaded, which a wake arriving during
        // startup can beat, so the sheet is skipped rather than thrown from: the
        // job is running either way and the Queue tab shows it.
        if (Content?.XamlRoot is not { } root)
        {
            _shell.Progress.Close();
            return;
        }

        _sheet = new Views.ProgressSheet(_shell.Progress, root);
        try
        {
            await _sheet.ShowAsync();
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException)
        {
            // Another dialog is already up (WinUI allows exactly one), or the
            // XamlRoot went away mid show. Either way the job is still running and
            // visible on the Queue tab, so the right answer is to give up on the
            // sheet rather than to fail the job.
        }
        finally
        {
            _sheet = null;
            _shell.Progress.Close();
        }
    }

    /// <summary>
    /// Clears the copy confirmation after a moment.
    /// </summary>
    /// <remarks>
    /// One timer, reused: pressing Copy twice in quick succession must not leave
    /// two timers racing to clear one label, with the first clearing it while the
    /// second press is still being read.
    /// </remarks>
    private DispatcherQueueTimer? _copyTimer;

    private void ClearCopyConfirmationLater()
    {
        _copyTimer ??= _queue.CreateTimer();
        _copyTimer.Interval = TimeSpan.FromSeconds(2);
        _copyTimer.IsRepeating = false;
        _copyTimer.Tick -= OnCopyTimerTick;
        _copyTimer.Tick += OnCopyTimerTick;
        _copyTimer.Start();
    }

    private void OnCopyTimerTick(DispatcherQueueTimer sender, object args) =>
        _shell.CopyConfirmation = null;

    // ---- drop routing ----

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            return;
        }

        e.AcceptedOperation = DataPackageOperation.Copy;
        e.DragUIOverride.Caption = Strings.AppName;
        e.DragUIOverride.IsContentVisible = true;
    }

    private async void OnDrop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems))
        {
            return;
        }

        // The deferral matters: GetStorageItemsAsync is awaited, and without it
        // the drag operation completes and the data view is disposed while the
        // await is still pending, which throws on some shells and silently
        // returns nothing on others.
        var deferral = e.GetDeferral();
        try
        {
            var items = await e.DataView.GetStorageItemsAsync();
            var paths = items.OfType<IStorageItem>().Select(i => i.Path)
                .Where(p => !string.IsNullOrEmpty(p)).ToList();
            if (paths.Count > 0)
            {
                _shell.Drop(paths);
            }
        }
        finally
        {
            deferral.Complete();
        }
    }

    /// <summary>
    /// A fake filesystem for the screenshot pass, so the Create screen shows a
    /// plausible set of sources on a box where those files do not exist.
    /// </summary>
    private static (long Size, DateTimeOffset Modified, bool IsFolder)? MockStat(string path) =>
        PathUtil.Extension(path).Length == 0
            ? (0L, new DateTimeOffset(2026, 9, 11, 14, 22, 0, TimeSpan.Zero), true)
            : (700L * 1024 * 1024, new DateTimeOffset(2026, 9, 11, 14, 22, 0, TimeSpan.Zero), false);

    /// <summary>The real filesystem, which the shell takes as a parameter so the tests need none.</summary>
    private static (long Size, DateTimeOffset Modified, bool IsFolder)? Stat(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                var dir = new DirectoryInfo(path);
                return (dir.EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length),
                    dir.LastWriteTimeUtc, true);
            }

            var file = new FileInfo(path);
            return file.Exists ? (file.Length, file.LastWriteTimeUtc, false) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
