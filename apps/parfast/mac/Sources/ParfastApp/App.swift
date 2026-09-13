import AppKit
import SwiftUI
import ParfastCore

/// The scenes. Everything the app does with the OS - opening documents, the
/// URL scheme, the Finder Quick Actions, the menu bar - routes into
/// `AppModel.open(paths:)`, the one router in plan 5.1.
struct ParfastSwiftUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var app: AppModel

    init() {
        let model = AppModel(core: ParfastSwiftUIApp.makeCore())
        _app = StateObject(wrappedValue: model)
        AppDelegate.shared = model
    }

    /// The size the main window opens at when nothing has been restored -
    /// which since 12 Sep 2026 means the FIRST RUN and nothing else, because
    /// `MainWindowFrame` restores the saved frame over the top of it
    /// (shared/design/window-frame.md).
    ///
    /// The wanted size is the SHARED token (`size.window_default_*`), which
    /// is what the Windows app uses too. The clamp is what makes it a
    /// default rather than a demand: a 13in laptop is the case that has to
    /// still work, and on 12 Sep 2026 it did not - 1280x860 against a
    /// 1440x900 logical display leaves nothing for the menu bar and opened a
    /// window taller than the screen.
    ///
    /// `visibleFrame`, not `frame`: it already excludes the menu bar and the
    /// Dock, wherever the user keeps the Dock. The margin is for the title
    /// bar, which `visibleFrame` does NOT exclude.
    ///
    /// The floor is the MINIMUM size, deliberately, and it can exceed the
    /// visible frame on a very small display: a window smaller than its own
    /// minimum is a layout this app has no design for, so there it is right
    /// to overflow rather than render something nothing was drawn against.
    ///
    /// `NSScreen.main` is the screen with the key window, falling back to
    /// the first - at launch, before any window exists, that is the screen
    /// the menu bar is on, which is where the window will open.
    static var defaultWindowSize: CGSize {
        let want = CGSize(width: T.sizeWindowDefaultWidth,
                          height: T.sizeWindowDefaultHeight)
        guard let vis = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame else {
            return want
        }
        let margin: CGFloat = 48
        return CGSize(
            width: min(want.width, max(T.sizeWindowMinWidth, vis.width - margin)),
            height: min(want.height, max(T.sizeWindowMinHeight, vis.height - margin)))
    }

    /// The real engine when it is linked, the mock when it is not (plan 3.3).
    /// Nothing above `CoreClient` knows which one it got; the window says so
    /// in the chrome, and `AppModel.isDemoBuild` is the one place that asks.
    static func makeCore() -> CoreClient {
        #if PARFAST_FFI
        if let core = FfiCore() {
            // The queue outlives the app (plan 5.5). The core does not know
            // where a mac keeps application support, so the host names it.
            if let support = try? FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask,
                appropriateFor: nil, create: true) {
                let dir = support.appendingPathComponent("parfast", isDirectory: true)
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                try? core.openQueueStore(at: dir.appendingPathComponent("queue.json").path)
            }
            return core
        }
        #endif
        return MockCore()
    }

    var body: some Scene {
        // `Window` and not `WindowGroup`: this is a single-window utility, and
        // a WindowGroup opens a NEW window for every `open parfast://...` and
        // every document open. That is not a cosmetic difference - the first
        // screenshot run left forty stacked windows behind, each showing the
        // state of the URL that made it, and `LSMultipleInstancesProhibited`
        // does not help because they are all one process.
        Window(S.appName, id: "main") {
            RootView()
                .environmentObject(app)
                // Frame persistence: the window remembers its size and place
                // between runs. This is the bridge to the NSWindow behind the
                // scene - see WindowFrame.swift and
                // shared/design/window-frame.md.
                .background(WindowFrameAccessor())
                .onAppear { app.prepareNotifications() }
        }
        .windowToolbarStyle(.unified)
        // The default comes from the SHARED table (size.window_default_*), so
        // the Windows app opens at the same size rather than from a second
        // copy of the number, and it is CLAMPED to the screen the window
        // opens on - see `defaultWindowSize` below.
        .defaultSize(Self.defaultWindowSize)
        .commands { menuCommands }

        Settings {
            SettingsView()
                .environmentObject(app)
        }
    }

    @CommandsBuilder
    private var menuCommands: some Commands {
        CommandGroup(replacing: .newItem) {
            Button(S.emptyVerifyOpen) {
                if let path = FilePicker.choose(directory: false, extensions: ["par2"],
                                                save: false, suggestion: "") {
                    app.openPar2(path)
                }
            }
            .keyboardShortcut("o")
            Button(S.emptyCreateAddFiles) {
                app.mode = .create
                app.create.addSources(FilePicker.chooseMany(directories: false))
            }
            .keyboardShortcut("n")
        }
        CommandMenu(S.modeQueue) {
            ForEach(AppModel.Mode.allCases) { mode in
                Button(mode.title) { app.mode = mode }
            }
            Divider()
            Toggle(S.logTitle, isOn: Binding(
                get: { app.logOpen }, set: { app.logOpen = $0 }))
                .keyboardShortcut("l", modifiers: [.command, .shift])
        }
        // The demo menu is how a mock build is driven, and it is the harness
        // the screenshots are taken through. It disappears the moment the app
        // is built against a real core, because a real core has no scenarios.
        if app.isDemoBuild {
            CommandMenu("Demo") {
                ForEach(MockScenario.all) { scenario in
                    Button(scenario.title) { app.openPar2(scenario.par2Path) }
                }
                Divider()
                Button("Long create") {
                    app.mode = .create
                    let spec = MockScenario.longCreateSpec()
                    app.create.addSources(spec.sources.map(\.path))
                    app.create.output = spec.output
                    app.create.outputEdited = true
                }
                Button("Three queued jobs") { queueThree() }
                Divider()
                Picker("Speed", selection: Binding(
                    get: { app.demoSpeed },
                    set: { app.demoSpeed = $0; (app.core as? MockCore)?.speed = $0 })) {
                    ForEach([0.5, 1.0, 4.0, 20.0], id: \.self) { Text("\($0, specifier: "%.1f")x").tag($0) }
                }
            }
        }
    }

    private func queueThree() {
        app.mode = .queue
        for scenario in [MockScenario.clean, .damagedRepairable, .unicodeNames] {
            _ = app.submit(.verify(VerifySpec(par2: scenario.par2Path)), showSheet: false)
        }
    }

}

/// `application(_:open:)` and the Finder Quick Actions arrive here. A dock
/// drop is the same call, which is why there is nothing else to write for it.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Set by the App's init, before any document can be delivered.
    @MainActor static var shared: AppModel?

    /// AppKit delivers BOTH file opens and custom-scheme URLs here, and a
    /// delegate that implements this takes them instead of SwiftUI's
    /// `onOpenURL`. So this is the one entry point, and it routes both.
    func application(_ application: NSApplication, open urls: [URL]) {
        Task { @MainActor in
            guard let app = AppDelegate.shared else { return }
            let files = urls.filter(\.isFileURL)
            if !files.isEmpty { app.open(paths: files.map(\.path)) }
            for url in urls where url.scheme == "parfast" {
                if DemoRoute.handle(url, app: app) { continue }
                let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
                let paths = items.filter { $0.name == "path" }.compactMap(\.value)
                if !paths.isEmpty { app.open(paths: paths) }
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    /// The two `NSServices` entries in Info.plist call these. Their selectors
    /// are named in the plist and must stay in step with these signatures.
    @objc func verifyWithParfast(_ pboard: NSPasteboard, userData: String,
                                 error: AutoreleasingUnsafeMutablePointer<NSString>) {
        route(pboard)
    }

    @objc func createWithParfast(_ pboard: NSPasteboard, userData: String,
                                 error: AutoreleasingUnsafeMutablePointer<NSString>) {
        route(pboard)
    }

    private func route(_ pboard: NSPasteboard) {
        let urls = pboard.readObjects(forClasses: [NSURL.self]) as? [URL] ?? []
        Task { @MainActor in
            AppDelegate.shared?.open(paths: urls.filter(\.isFileURL).map(\.path))
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}
