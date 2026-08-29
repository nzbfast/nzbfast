// nzbfast mobile shell.
//
// TWO SOURCES since TODO 281 IO1: the engine can run on this phone
// (nzbfast-ffi linked in, serving 127.0.0.1 from a thread of this
// process) or on a machine of the user's elsewhere. Both are
// bring-your-own-server; neither has an indexer, a search box or any
// content in it, which is the posture
// research/PLAN-MOBILE-DOWNLOADER-2026-08-24.md rests on.
//
// NO WebView anywhere, deliberately, and it is a rule rather than an
// accident (the plan's addendum A). The engine still compiles the web
// dashboard in - it is one include_str! - but nothing in this app points
// at it. The A3 spike harness beside this file does, and it is a
// throwaway.
import SwiftUI

@main
struct NzbfastMobileApp: App {
    @StateObject private var state: AppState

    /// The one place the app is allowed to be, at the one moment
    /// `BGTaskScheduler` insists on.
    ///
    /// Registration MUST happen before the app finishes launching, so it
    /// cannot be a `.task` or an `onAppear` - by then the scheduler has
    /// already decided the identifier is unhandled and will never
    /// deliver it. Registering an identifier that is not in
    /// `BGTaskSchedulerPermittedIdentifiers` raises an uncatchable
    /// exception, so this line and that plist array are a pair.
    ///
    /// The state is created HERE and put in the box before registration:
    /// a BGProcessing relaunch runs this init and may never open a
    /// window, so the box has to own the state rather than wait for a
    /// view task that is not guaranteed to run (C23). The handler still
    /// closes over the box and reads it at FIRE time.
    init() {
        let box = AppStateBox.shared
        let s = box.state ?? AppState()
        box.state = s
        _state = StateObject(wrappedValue: s)
        Lifecycle.registerTasks { box.state }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(state)
                .preferredColorScheme(.dark)
        }
    }
}

struct RootView: View {
    @EnvironmentObject var state: AppState
    @StateObject private var link = LinkWatcher()

    var body: some View {
        Group {
            if state.isConnected && !state.needsServerSetup {
                MainTabView()
            } else if state.isConnected && state.needsServerSetup {
                // The on-device engine is up but has no provider yet. An
                // engine with an empty server list HOLDS every job
                // rather than failing it (TODO 154), so without this the
                // first NZB would sit at 0% with nothing on screen
                // saying why.
                NavigationStack { ServerSetupView() }
            } else {
                ConnectView()
            }
        }
        .onOpenURL { url in
            state.handleOpenURL(url)
        }
        // `task(id:)` rather than `onChange`: it runs on appear AND on
        // every change, which is what a policy wants (a launch already
        // on cellular has to be held too), and the two-closure
        // `onChange(of:initial:_:)` is iOS 17 against this project's 16.
        .task(id: link.status) {
            await state.applyCellularPolicy(link.status)
        }
        .task {
            // Restart the on-device engine on a cold launch. The port is
            // OS-chosen per run, so there is nothing persisted to adopt
            // and this is the only thing that brings the queue back.
            if AppSettings.source == .device && !state.isConnected {
                try? await state.useDevice()
            }
        }
        #if DEBUG
        // Headless QA path: simctl launch arguments land in the
        // arguments domain of UserDefaults, so a driver can route deep
        // links without the OS open dialog (`simctl openurl` on a custom
        // scheme raises one, and parks at SpringBoard level until a
        // restart).
        //
        // A LIST, run in order and awaited one at a time: on-device mode
        // is start the engine, then save a provider, then import an NZB,
        // and each step needs the one before it. Numbered keys rather
        // than one delimited string, because a news server password is
        // in one of these and there is no separator a password cannot
        // contain.
        .task {
            var links: [URL] = []
            for key in ["qaurl", "qaurl2", "qaurl3", "qaurl4"] {
                if let s = UserDefaults.standard.string(forKey: key),
                   let u = URL(string: s) {
                    links.append(u)
                }
            }
            for u in links { await state.handleQA(u) }
        }
        #endif
    }
}

struct MainTabView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        TabView(selection: $state.selectedTab) {
            NavigationStack { HomeView() }
                .tabItem { Label("Downloads", systemImage: "arrow.down.circle") }
                .tag(AppState.MainTab.home)
            NavigationStack { AddView() }
                .tabItem { Label("Add", systemImage: "plus.circle") }
                .tag(AppState.MainTab.add)
            NavigationStack { HistoryView() }
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
                .tag(AppState.MainTab.history)
            NavigationStack { SettingsView() }
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(AppState.MainTab.settings)
        }
        .fullScreenCover(item: $state.playRequest) { target in
            PlayerView(target: target)
        }
    }
}

/// A way for the background-task handler to reach the live `AppState`.
///
/// The handler `BGTaskScheduler.register` takes can fire hours later in
/// a launch that never showed a window, so it closes over this and
/// reads it at FIRE time. RETAINED, not weak, and filled by `App.init`
/// before registration: a BGProcessing relaunch runs no view task, and
/// a box that stayed empty made every cold delivery report failure
/// without ever starting the engine (C23).
@MainActor
final class AppStateBox {
    static let shared = AppStateBox()
    var state: AppState?
    private init() {}
}
