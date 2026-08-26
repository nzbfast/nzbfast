import AppKit
import ServiceManagement
import UniformTypeIdentifiers

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuItemValidation {
    private let daemon = Daemon.shared
    private var windowController: DashboardWindowController!
    /// .nzb files that arrived (open-with) before the daemon was up.
    private var pendingNzbs: [URL] = []
    /// nzblnk: links clicked before the daemon was up. Kept apart from
    /// pendingNzbs because they take a different endpoint, not because
    /// they arrive differently - both come through application(_:open:).
    private var pendingLinks: [String] = []
    private var stackReady = false
    /// Did THIS app spawn the engine now running, as opposed to attaching
    /// to one that was already up? Set from every `StartResult`.
    ///
    /// Not `Daemon.spawnedByUs`, which answers the same question for the
    /// engine's own bookkeeping and is cleared BY the termination handler
    /// as the child dies. `engineGone` needs the question answered about
    /// the generation, and a probe that lands in the gap between that
    /// handler and the `childDied` hop behind it would read the freshly
    /// cleared flag, call an attached engine's death, and put a second
    /// alert behind the one already coming.
    private var engineIsOurs = false
    private var quitting = false
    private let quitWatchdog = QuitWatchdog()
    private let statusItem = StatusItemController()

    // MARK: lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        // First, because applyPreferences() below is the first thing
        // to read either key and an unregistered bool(forKey:) is
        // false - which would ship the menu bar item off.
        StatusItemController.registerDefaults()
        buildMenus()
        windowController = DashboardWindowController()
        windowController.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        // The menu bar item performs no action of its own: it calls the
        // ones this delegate already owns, so its "Open in Browser" is
        // the same guarded call as the View menu's, key handling and all.
        statusItem.onOpenWindow = { [weak self] in self?.showMainWindow() }
        statusItem.onOpenBrowser = { [weak self] in self?.openInBrowser() }
        statusItem.onOpenDownloads = { [weak self] in self?.openDownloads() }
        statusItem.onEngineGone = { [weak self] why in self?.engineGone(why) }
        statusItem.applyPreferences()

        daemon.onUnexpectedExit = { [weak self] tail in
            Task { @MainActor in self?.childDied(tail) }
        }
        // Take over kAEQuitApplication (registered after AppKit installs
        // its handler, so ours wins). AppKit's own routing never delivers
        // a quit that arrives while an NSAlert.runModal loop is up - the
        // event just waits for a click that, on an unattended machine
        // mid-shutdown, never comes. That is the observed hang (8 Aug
        // 2026): an error alert nobody saw, then a software-update
        // restart the app silently blocked. Ours aborts the modal first,
        // so terminate() always gets its turn.
        NSAppleEventManager.shared().setEventHandler(
            self, andSelector: #selector(handleQuitEvent(_:withReply:)),
            forEventClass: AEEventClass(kCoreEventClass),
            andEventID: AEEventID(kAEQuitApplication))
        Task { await startStack() }
    }

    @objc private func handleQuitEvent(
        _ event: NSAppleEventDescriptor, withReply reply: NSAppleEventDescriptor
    ) {
        QuitWatchdog.log.notice(
            "kAEQuitApplication received (modal up: \(NSApp.modalWindow != nil))")
        if NSApp.modalWindow != nil { NSApp.abortModal() }
        NSApp.terminate(nil)
    }

    private func startStack() async {
        windowController.setOverlay(visible: true)
        let started = await daemon.start()
        switch started {
        case .attached, .spawned:
            if case .spawned = started { engineIsOurs = true } else { engineIsOurs = false }
            stackReady = true
            statusItem.setStackReady(true)
            // dashboardURL, not baseURL: only now is the port confirmed to
            // be an nzbfast, and the page needs the key handed to it or a
            // fresh install lands on a prompt for a credential it has never
            // been shown.
            windowController.showDashboard(daemon.dashboardURL)
            let files = pendingNzbs
            pendingNzbs = []
            for f in files { await postNzb(f) }
            let links = pendingLinks
            pendingLinks = []
            for l in links { await postNzblnk(l) }
        case .failed(let why):
            statusItem.setStackReady(false)
            windowController.setOverlay(visible: true, text: "nzbfast couldn't start")
            let alert = NSAlert()
            alert.messageText = "nzbfast couldn't start"
            alert.informativeText = "\(why)\n\nLast log lines:\n\(daemon.logTail())"
            alert.addButton(withTitle: "Try Again")
            alert.addButton(withTitle: "Quit")
            let choice = alert.runModal()
            // Same as childDied: a quit may have aborted this modal.
            guard !quitting else { return }
            if choice == .alertFirstButtonReturn {
                Task { await startStack() }
            } else {
                NSApp.terminate(nil)
            }
        }
    }

    private func childDied(_ tail: String) {
        engineStopped(
            message: "nzbfast stopped unexpectedly",
            detail: "Last log lines:\n\(tail)")
    }

    /// The listener on our port stopped being the engine we proved, and
    /// no child of ours died to say so.
    ///
    /// This is the ATTACHED case, and it is the only death this app could
    /// not see. A child has a `terminationHandler`; an engine we attached
    /// to has no child, so until 26 Aug 2026 its death was invisible and
    /// the wrapper went on posting the master API key at the freed port
    /// every 3 to 5 seconds, with the embedded dashboard doing the same
    /// once a second in an `X-Api-Key` header (both measured against a
    /// recording listener). `Daemon.recheckListener` is what notices, and
    /// it has already dropped the key by the time this runs; what is left
    /// is the part only this delegate can do - stop the poll, unload the
    /// page that holds the key of its own, and tell the user.
    ///
    /// A child of ours is NOT handled here even when a probe fails first.
    /// `Process.terminationHandler` is the authority on a child and it
    /// arrives on its own; a probe can also fail against a child that is
    /// alive and merely wedged, and calling that death would raise an
    /// alert over a running engine. The test is `engineIsOurs`, which is
    /// this delegate's own record of the last `StartResult` - see there
    /// for why `Daemon.spawnedByUs` is the wrong one to read here.
    private func engineGone(_ why: Daemon.ProbeVerdict) {
        guard !quitting, stackReady, !engineIsOurs else { return }
        let port = daemon.port
        let detail: String
        switch why {
        case .stranger:
            detail = """
                Another program is answering on port \(port), so nzbfast \
                has stopped talking to it. Restart starts a fresh engine.
                """
        default:
            detail = """
                The engine on port \(port) stopped answering. This app \
                attached to an engine that was already running rather than \
                starting one, so there is no log here from the run that \
                ended. Restart starts a fresh engine.
                """
        }
        engineStopped(message: "nzbfast stopped", detail: detail)
    }

    /// The engine is gone: stop everything that was still talking to its
    /// port, then offer a restart. Shared by the child's termination
    /// handler and by `engineGone`, so the two cannot drift into two
    /// different ideas of what a stopped engine looks like.
    private func engineStopped(message: String, detail: String) {
        guard !quitting else { return }
        stackReady = false
        statusItem.setStackReady(false)
        windowController.setOverlay(visible: true, text: "nzbfast stopped")
        // Not just covered - unloaded. The page polls once a second with
        // the API key in a header, and the port it is polling is free the
        // moment the engine dies. See `blankDashboard`.
        windowController.blankDashboard()
        let alert = NSAlert()
        alert.messageText = message
        alert.informativeText = detail
        alert.addButton(withTitle: "Restart")
        alert.addButton(withTitle: "Quit")
        let choice = alert.runModal()
        // A quit can abort this modal from under us (handleQuitEvent).
        // Termination is already in flight then - restarting the engine
        // would fight the stop, and terminate() again would skip it.
        guard !quitting else { return }
        if choice == .alertFirstButtonReturn {
            Task {
                let restarted = await daemon.restart()
                if case .failed(let why) = restarted {
                    self.windowController.setOverlay(visible: true, text: why)
                } else {
                    if case .spawned = restarted {
                        self.engineIsOurs = true
                    } else {
                        self.engineIsOurs = false
                    }
                    self.stackReady = true
                    self.statusItem.setStackReady(true)
                    self.windowController.showDashboard(self.daemon.dashboardURL)
                }
            }
        } else {
            NSApp.terminate(nil)
        }
    }

    /// Graceful quit (shared rule 6): stop OUR child cleanly, then go.
    /// An attached daemon is never touched. QuitWatchdog bounds the whole
    /// thing - once quit is asked for, the reply WILL be sent within its
    /// ceiling even if the stop wedges, because the OS asks exactly once
    /// and an unanswered .terminateLater holds a whole shutdown (the
    /// observed software-update hang, 8 Aug 2026).
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if quitting {
            // A second ask (Cmd-Q again, or a rushed logout): the stop is
            // already under way and the watchdog bounds it - just go.
            QuitWatchdog.log.notice("quit re-requested while stopping - terminateNow")
            return .terminateNow
        }
        quitting = true
        QuitWatchdog.log.notice("quit requested")
        // Before the stop below, not after: a poll in flight against an
        // engine that is shutting down is a request nobody will read the
        // answer to, and its timer would keep firing through the wait.
        statusItem.suspend()
        // An error alert nobody is around to dismiss (the engine-crash
        // dialog on an unattended machine) holds its modal loop through a
        // whole shutdown otherwise. Aborting makes runModal return
        // .abort, whose else-branches call NSApp.terminate - which lands
        // in the quitting-guard above and terminates now. That is the
        // right outcome: quit was asked for.
        if NSApp.modalWindow != nil {
            QuitWatchdog.log.notice("aborting modal panel so quit can proceed")
            NSApp.abortModal()
        }
        quitWatchdog.arm()
        // Detached on purpose: after .terminateLater the main run loop is
        // in a modal-ish mode, and a main-actor Task hop is exactly the
        // scheduling this path must not depend on - the stop runs off the
        // main thread and the watchdog owns reply delivery.
        Task.detached { [quitWatchdog] in
            await Daemon.shared.stop()
            quitWatchdog.deliver(why: "engine stop finished")
        }
        return .terminateLater
    }

    /// Dock-icon click with the window closed: bring it back.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows {
            windowController.showWindow(nil)
        }
        return true
    }

    // MARK: .nzb open-with, and nzblnk: links

    /// One delegate method serves both: macOS routes an "open with" file
    /// and a clicked `nzblnk:` URL here alike, so the branch is on what
    /// the URL IS, not on how it arrived.
    func application(_ application: NSApplication, open urls: [URL]) {
        let nzbs = urls.filter { $0.isFileURL && $0.pathExtension.lowercased() == "nzb" }
        // absoluteString, deliberately: the daemon owns the only NZBLNK
        // parser, and re-forming the link through URLComponents here
        // would normalise the `+` and `%` escapes that its decoder reads.
        let links = urls
            .filter { $0.scheme?.lowercased() == "nzblnk" }
            .map(\.absoluteString)
        guard !nzbs.isEmpty || !links.isEmpty else { return }
        if stackReady {
            Task {
                for f in nzbs { await postNzb(f) }
                for l in links { await postNzblnk(l) }
            }
        } else {
            // Cold start: the stack is coming up; post once it answers.
            pendingNzbs.append(contentsOf: nzbs)
            pendingLinks.append(contentsOf: links)
        }
    }

    private func postNzb(_ file: URL) async {
        if let err = await daemon.addNzb(file) {
            let alert = NSAlert()
            alert.messageText = "Couldn't add \(file.lastPathComponent)"
            alert.informativeText = err
            alert.runModal()
        }
    }

    private func postNzblnk(_ link: String) async {
        if let err = await daemon.addNzblnk(link) {
            let alert = NSAlert()
            alert.messageText = "Couldn't add that link"
            alert.informativeText = err
            alert.runModal()
        }
    }

    // MARK: menus

    private func buildMenus() {
        let main = NSMenu()

        // App menu
        let appItem = main.addItem(withTitle: "nzbfast", action: nil, keyEquivalent: "")
        let appMenu = NSMenu()
        appItem.submenu = appMenu
        appMenu.addItem(withTitle: "About nzbfast", action: #selector(showAbout), keyEquivalent: "")
        appMenu.addItem(.separator())
        let login = appMenu.addItem(
            withTitle: "Start at Login", action: #selector(toggleLogin), keyEquivalent: "")
        login.target = self
        // Beside Start at Login because they answer the same question -
        // what does this app do when its window is not in front - and
        // because the app has no Preferences window to put them in.
        let menuBar = appMenu.addItem(
            withTitle: "Show in Menu Bar", action: #selector(toggleMenuBar), keyEquivalent: "")
        menuBar.target = self
        menuBar.toolTip =
            "Keep an nzbfast icon in the menu bar, with the queue and a pause control behind it."
        let menuBarSpeed = appMenu.addItem(
            withTitle: "Show Speed in Menu Bar", action: #selector(toggleMenuBarSpeed),
            keyEquivalent: "")
        menuBarSpeed.target = self
        menuBarSpeed.toolTip =
            "Put the current download speed beside the menu bar icon while a download is running."
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide nzbfast", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: "Quit nzbfast", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        // File
        let fileItem = main.addItem(withTitle: "File", action: nil, keyEquivalent: "")
        let fileMenu = NSMenu(title: "File")
        fileItem.submenu = fileMenu
        fileMenu.addItem(withTitle: "Open .nzb…", action: #selector(openNzbPanel), keyEquivalent: "o")
        fileMenu.addItem(.separator())
        fileMenu.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")

        // Edit - standard actions so the dashboard's text fields get
        // cut/copy/paste/select-all keyboard shortcuts.
        let editItem = main.addItem(withTitle: "Edit", action: nil, keyEquivalent: "")
        let editMenu = NSMenu(title: "Edit")
        editItem.submenu = editMenu
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        // View
        let viewItem = main.addItem(withTitle: "View", action: nil, keyEquivalent: "")
        let viewMenu = NSMenu(title: "View")
        viewItem.submenu = viewMenu
        viewMenu.addItem(withTitle: "Open in Browser", action: #selector(openInBrowser), keyEquivalent: "b")
        viewMenu.addItem(withTitle: "Open Downloads Folder", action: #selector(openDownloads), keyEquivalent: "d")

        // Window
        let winItem = main.addItem(withTitle: "Window", action: nil, keyEquivalent: "")
        let winMenu = NSMenu(title: "Window")
        winItem.submenu = winMenu
        winMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        winMenu.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        NSApp.windowsMenu = winMenu

        // Help
        let helpItem = main.addItem(withTitle: "Help", action: nil, keyEquivalent: "")
        let helpMenu = NSMenu(title: "Help")
        helpItem.submenu = helpMenu
        helpMenu.addItem(withTitle: "nzbfast User Manual", action: #selector(openManual), keyEquivalent: "?")
        NSApp.helpMenu = helpMenu

        NSApp.mainMenu = main
    }

    /// Keep the Start at Login checkmark honest.
    func validateMenuItem(_ item: NSMenuItem) -> Bool {
        if item.action == #selector(toggleLogin) {
            item.state = SMAppService.mainApp.status == .enabled ? .on : .off
        }
        if item.action == #selector(toggleMenuBar) {
            item.state = UserDefaults.standard.bool(forKey: StatusItemController.showKey)
                ? .on : .off
        }
        // The speed rides beside the icon, so with no icon there is
        // nowhere for it to go. Greyed rather than hidden: a checkbox
        // that vanishes reads as a setting that was lost.
        if item.action == #selector(toggleMenuBarSpeed) {
            item.state = UserDefaults.standard.bool(forKey: StatusItemController.speedKey)
                ? .on : .off
            return UserDefaults.standard.bool(forKey: StatusItemController.showKey)
        }
        // Nothing to open in a browser - and no confirmed port to hand the
        // API key to - until the daemon has answered.
        if item.action == #selector(openInBrowser) { return stackReady }
        return true
    }

    // MARK: menu actions

    @objc private func showAbout() {
        let bundleVer = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        Task {
            let dv = await daemon.daemonVersion()
            let alert = NSAlert()
            alert.messageText = "nzbfast"
            var info = "App v\(bundleVer)"
            if let dv { info += " · engine v\(dv)" }
            info += "\nThe fast Usenet downloader.\nGPL-3.0 - https://github.com/nzbfast/nzbfast"
            alert.informativeText = info
            alert.runModal()
        }
    }

    @objc private func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            let alert = NSAlert()
            alert.messageText = "Couldn't change Start at Login"
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }

    @objc private func toggleMenuBar() {
        let d = UserDefaults.standard
        d.set(!d.bool(forKey: StatusItemController.showKey), forKey: StatusItemController.showKey)
        statusItem.applyPreferences()
    }

    @objc private func toggleMenuBarSpeed() {
        let d = UserDefaults.standard
        d.set(!d.bool(forKey: StatusItemController.speedKey), forKey: StatusItemController.speedKey)
        statusItem.applyPreferences()
    }

    /// Show and focus the one window. Same as the Dock-icon reopen path
    /// above, and reached the same way from the menu bar item - closing
    /// the window leaves the app (and the engine) running, so "open" has
    /// to mean bring it back rather than make another.
    @objc private func showMainWindow() {
        windowController.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func openNzbPanel() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        if let nzb = UTType(filenameExtension: "nzb") {
            panel.allowedContentTypes = [nzb]
        }
        panel.begin { [weak self] resp in
            guard resp == .OK, let self else { return }
            self.application(NSApp, open: panel.urls)
        }
    }

    /// Hand the system browser the same keyed URL the embedded webview gets,
    /// or it lands on a prompt for a credential the user has never been
    /// shown. dashboardURL returns the plain baseURL on a keyless install,
    /// so that case is unchanged.
    ///
    /// Gated on stackReady, which is dashboardURL's own contract: the key
    /// may only go to a port start() has confirmed is nzbfast. Before that,
    /// `port` is just a number remembered from a previous run and anything
    /// could be listening on it. validateMenuItem greys the item out until
    /// then, so this guard is the belt to that item's braces.
    @objc private func openInBrowser() {
        guard stackReady else { return }
        NSWorkspace.shared.open(daemon.dashboardURL)
    }

    @objc private func openDownloads() {
        try? FileManager.default.createDirectory(at: daemon.downloadsDir, withIntermediateDirectories: true)
        NSWorkspace.shared.open(daemon.downloadsDir)
    }

    @objc private func openManual() {
        NSWorkspace.shared.open(daemon.baseURL.appendingPathComponent("manual"))
    }
}
