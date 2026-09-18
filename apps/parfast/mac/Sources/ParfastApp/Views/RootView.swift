import SwiftUI
import UniformTypeIdentifiers
import ParfastCore

/// The one window: a vibrancy sidebar with the four modes and the unified
/// toolbar carrying the mode's primary action on the right (plan 5.1).
struct RootView: View {
    @EnvironmentObject var app: AppModel
    @State private var dropTargeted = false
    @State private var columnVisibility: NavigationSplitViewVisibility = .all

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            sidebar
        } detail: {
            detail
        }
        .navigationTitle(title)
        .navigationSubtitle(subtitle)
        .toolbar { toolbarItems }
        .frame(minWidth: T.sizeWindowMinWidth, minHeight: T.sizeWindowMinHeight)
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            load(providers)
            return true
        }
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: T.radiusCard, style: .continuous)
                    .strokeBorder(T.accentPrimary, style: StrokeStyle(lineWidth: 3, dash: [8, 6]))
                    .padding(6)
                    .allowsHitTesting(false)
            }
        }
        .overlay(alignment: .bottom) {
            if let toast = app.toast {
                ToastView(text: toast.text)
                    .padding(.bottom, T.spacingXxl)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .task(id: toast.id) {
                        try? await Task.sleep(nanoseconds: 2_200_000_000)
                        withAnimation { app.toast = nil }
                    }
            }
        }
        .sheet(item: Binding(
            get: { app.progressSnapshot.map { IdentifiedJob(job: $0) } },
            set: { if $0 == nil { app.progressJob = nil } })) { wrapper in
            ProgressSheet(job: wrapper.job)
                .environmentObject(app)
        }
        .alert(item: $app.alert) { box in
            if let confirm = box.confirm, let action = box.action {
                return Alert(title: Text(box.title), message: Text(box.message),
                             primaryButton: .default(Text(confirm), action: action),
                             secondaryButton: .cancel(Text(S.commonCancel)))
            }
            return Alert(title: Text(box.title), message: Text(box.message),
                         dismissButton: .default(Text(S.commonOk)))
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List(selection: $app.mode) {
            Section {
                ForEach(AppModel.Mode.allCases) { mode in
                    Label {
                        HStack {
                            Text(mode.title)
                            if mode == .queue, app.queue.running + app.queue.waiting > 0 {
                                Spacer()
                                Text(Fmt.count(app.queue.running + app.queue.waiting))
                                    .font(.system(size: 11, weight: .semibold))
                                    .monospacedDigit()
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 1)
                                    .background(Capsule().fill(T.accentPrimary))
                                    .foregroundStyle(.white)
                                    .accessibilityLabel(S.queueBadgeLabel(
                                        running: Fmt.count(app.queue.running),
                                        waiting: Fmt.count(app.queue.waiting)))
                            }
                        }
                    } icon: {
                        Image(systemName: mode.symbol)
                    }
                    .tag(mode)
                }
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: T.sizeSidebarMin, ideal: 200, max: 260)
        .safeAreaInset(edge: .bottom) {
            VStack(alignment: .leading, spacing: 2) {
                Divider().overlay(T.surfaceGridLine)
                Text(S.appTagline)
                    .font(.system(size: 10))
                    .foregroundStyle(T.textTertiary)
                // The stage, then the ENGINE's version - which is what
                // capabilities.version is, and it is further along than this
                // app. Without the stage beside it the footer reads as the
                // app's own version, and at 1.6.0 that is a bare release
                // number on a beta app (it was "beta" on an alpha one
                // before; the gap moved, it did not close).
                Text("\(S.appStage) \u{00B7} \(app.capabilities.version)")
                    .font(.system(size: 10))
                    .monospacedDigit()
                    .foregroundStyle(T.textTertiary)
            }
            .padding(.horizontal, T.spacingM)
            .padding(.bottom, T.spacingS)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Detail

    private var detail: some View {
        VStack(spacing: 0) {
            // A build with no engine says so where it cannot be missed. Every
            // figure on every screen behind this bar is arithmetic over a
            // scripted scenario, and a demo mistaken for a verify is the one
            // way this app could do real harm.
            if app.isDemoBuild {
                HStack(spacing: T.spacingS) {
                    Image(systemName: "exclamationmark.triangle.fill")
                    Text(S.mockBanner)
                    Spacer(minLength: 0)
                }
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(T.statusOnWarn)
                .padding(.horizontal, T.spacingL)
                .padding(.vertical, 5)
                .frame(maxWidth: .infinity)
                .background(T.statusWarn)
                .accessibilityLabel(S.mockBanner)
            }
            // Each mode owns its own scrolling. It has to: Create pins a
            // preview bar to the bottom of the window, and a bar inside an
            // outer scroll view scrolls away with the content instead.
            Group {
                switch app.mode {
                case .verify: VerifyView(model: app.verify)
                case .create: CreateView(model: app.create)
                case .checksums: ChecksumsView(model: app.checksums)
                case .queue: QueueView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(T.surfaceWell)

            if app.logOpen {
                LogDrawer(lines: logLines, command: logCommand)
                    .transition(.move(edge: .bottom))
            }
        }
        .animation(.easeInOut(duration: 0.18), value: app.logOpen)
    }

    private var logLines: [String] {
        switch app.mode {
        case .verify: return app.verify.snapshot?.log_tail ?? []
        case .create: return app.create.snapshot?.log_tail ?? []
        case .checksums: return app.checksums.snapshot?.log_tail ?? []
        case .queue:
            return app.queue.jobs.last(where: { $0.state == .running })?.log_tail
                ?? app.queue.jobs.last?.log_tail ?? []
        }
    }

    private var logCommand: String? {
        switch app.mode {
        case .create: return app.create.preview?.command
        case .verify:
            guard let path = app.verify.par2Path else { return nil }
            return "parfast v \(path)"
        case .checksums, .queue: return nil
        }
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarItems: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Button {
                withAnimation { app.logOpen.toggle() }
            } label: {
                Label(S.commonLog, systemImage: "text.alignleft")
            }
            .help(S.logTitle)
        }
        ToolbarItemGroup(placement: .primaryAction) {
            switch app.mode {
            case .verify:
                // No set open means no primary action: an inert Repair button
                // over an empty drop zone reads as something being wrong.
                if app.verify.par2Path != nil {
                    Button {
                        app.startRepair()
                    } label: {
                        Label(S.verifyActionRepair, systemImage: "wrench.and.screwdriver")
                    }
                    .disabled(!app.verify.canRepair)
                }
            case .create:
                Button {
                    app.startCreate()
                } label: {
                    Label(S.createActionCreate, systemImage: "plus.square.on.square")
                }
                .disabled(app.create.sources.isEmpty)
            case .checksums:
                Button {
                    app.checksums.subMode == .create
                        ? app.startChecksumCreate() : app.startChecksumVerify()
                } label: {
                    Label(app.checksums.subMode == .create ? S.checksumsCreate : S.checksumsVerifyAgain,
                          systemImage: "number.square")
                }
            case .queue:
                Button {
                    app.setQueuePaused(!app.queue.paused)
                } label: {
                    Label(app.queue.paused ? S.queueResume : S.queuePause,
                          systemImage: app.queue.paused ? "play.fill" : "pause.fill")
                }
            }
        }
    }

    private var title: String { S.appName }

    private var subtitle: String {
        switch app.mode {
        case .verify: return app.verify.survey?.set_name ?? app.mode.title
        case .create: return app.create.sources.isEmpty
            ? app.mode.title
            : S.createSourcesFooter(files: Fmt.fileCount(app.create.sources.count),
                                    size: Fmt.bytes(app.create.totalBytes))
        case .checksums, .queue: return app.mode.title
        }
    }

    // MARK: - Drop

    private func load(_ providers: [NSItemProvider]) {
        var paths: [String] = []
        let group = DispatchGroup()
        for provider in providers {
            group.enter()
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url, url.isFileURL { paths.append(url.path) }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            app.open(paths: paths.sorted())
        }
    }
}

/// `sheet(item:)` needs an Identifiable; a job id is one.
struct IdentifiedJob: Identifiable {
    var job: JobSnapshot
    var id: Int64 { job.id }
}
