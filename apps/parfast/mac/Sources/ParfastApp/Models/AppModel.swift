import Foundation
import SwiftUI
import UserNotifications
import ParfastCore

/// The one object the window hangs off: the core client, the queue it polls,
/// the four screens' models, and the routing rules from plan 5.1.
///
/// It owns the POLL. The core wakes us ("a snapshot would differ"), we
/// marshal to the main actor and pull a fresh queue snapshot; a slow 10 Hz
/// timer backs that up so a missed wake shows as a late frame rather than a
/// frozen window. That is the contract in 4.5 and it is the same shape
/// against the mock and against the FFI.
@MainActor
final class AppModel: ObservableObject {

    enum Mode: String, CaseIterable, Identifiable, Hashable {
        case verify, create, checksums, queue

        var id: String { rawValue }

        var title: String {
            switch self {
            case .verify: return S.modeVerify
            case .create: return S.modeCreate
            case .checksums: return S.modeChecksums
            case .queue: return S.modeQueue
            }
        }

        /// One MEANING per slot, plan 5.7: a shield-check for verify, a wrench
        /// for repair, a plus-square for create, a list for queue.
        var symbol: String {
            switch self {
            case .verify: return "checkmark.shield"
            case .create: return "plus.square.on.square"
            case .checksums: return "number.square"
            case .queue: return "list.bullet.rectangle"
            }
        }
    }

    struct Toast: Identifiable, Equatable {
        let id = UUID()
        var text: String
    }

    struct AlertBox: Identifiable {
        let id = UUID()
        var title: String
        var message: String
        var confirm: String?
        var action: (() -> Void)?
    }

    let core: CoreClient
    let verify: VerifyModel
    let create: CreateModel
    let checksums: ChecksumsModel

    @Published var mode: Mode = .verify
    @Published var queue = QueueSnapshot()
    @Published var capabilities: Capabilities
    @Published var settings = CoreSettings()
    @Published var logOpen = false
    @Published var toast: Toast?
    @Published var alert: AlertBox?
    /// The job the progress sheet is showing, if any.
    @Published var progressJob: Int64?
    /// Raised by the demo menu so a whole scenario plays inside a screenshot.
    @Published var demoSpeed: Double = 1

    private var timer: Timer?
    private var seenFinished: Set<Int64> = []
    private var notificationsAsked = false

    init(core: CoreClient) {
        self.core = core
        self.capabilities = (try? core.capabilities()) ?? Capabilities(
            version: "unknown", engine: "unknown", cpu: "", kernel: "",
            std_naming: false, unicode_policy: false, data_skipping: false,
            fast_solver: false, pause: false, low_priority: false)
        self.verify = VerifyModel()
        self.create = CreateModel()
        self.checksums = ChecksumsModel()
        self.settings = (try? core.settingsGet()) ?? CoreSettings()
        create.applyDefaults(settings)
        checksums.applyDefaults(settings)
        verify.applyDefaults(settings)
        start()
    }

    deinit { timer?.invalidate() }

    private func start() {
        core.setWake { [weak self] in
            Task { @MainActor in self?.refresh() }
        }
        let t = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
        refresh()
    }

    // MARK: - The poll

    func refresh() {
        guard let snapshot = try? core.queueSnapshot() else { return }
        queue = snapshot
        verify.apply(queue: snapshot)
        create.apply(queue: snapshot)
        checksums.apply(queue: snapshot)
        noteCompletions(snapshot)
    }

    private func noteCompletions(_ snapshot: QueueSnapshot) {
        for job in snapshot.jobs where job.state.isFinished && !seenFinished.contains(job.id) {
            seenFinished.insert(job.id)
            if settings.general.auto_close_progress && job.state == .done && progressJob == job.id {
                progressJob = nil
            }
            if settings.general.notifications {
                postNotification(for: job)
            }
        }
        runPostActionIfDue()
    }

    /// The CORE says the queue drained and the action is outstanding; the
    /// HOST performs it, because sleeping a machine is a platform call and a
    /// decision a human must be able to stop.
    ///
    /// It is cleared whether or not the action was carried out. Left
    /// uncleared it falls due again on the next snapshot, and at this poll
    /// rate that is a shutdown attempt ten times a second - chip C's finding,
    /// and the reason `clear` is in a `defer` rather than after a success.
    private func runPostActionIfDue() {
        guard queue.post_action_due else { return }
        let action = queue.post_action
        defer {
            try? core.clearQueuePostAction()
            refresh()
        }
        switch action {
        case .none: break
        case .notify:
            toast = Toast(text: S.queueWhenFinished + ": " + S.queueFinishNotify)
        case .sleep, .shutdown:
            // 5.5: these confirm ONCE, when they are set, so by here the user
            // has already agreed and this only announces it.
            toast = Toast(text: action == .sleep ? S.queueFinishSleep : S.queueFinishShutdown)
            PowerAction.perform(action)
        }
    }

    // MARK: - Notifications

    /// UserNotifications needs a real app bundle: asking for authorisation
    /// from a plain executable (the XCTest runner, `swift run`) raises
    /// "bundleProxyForCurrentProcess is nil" and takes the process down. The
    /// app is always bundled; the tests are not, and they exercise everything
    /// around this.
    static let canPostNotifications = Bundle.main.bundleURL.pathExtension == "app"

    func prepareNotifications() {
        guard Self.canPostNotifications, !notificationsAsked else { return }
        notificationsAsked = true
        UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func postNotification(for job: JobSnapshot) {
        // Section 5.2: post only when the window is not frontmost. A banner
        // over the window you are already watching is noise.
        guard Self.canPostNotifications, !NSApplication.shared.isActive else { return }
        let content = UNMutableNotificationContent()
        let name = job.title ?? ""
        content.title = S.notifyDoneTitle(job: displayKind(job.kind))
        switch (job.kind, job.state) {
        case (_, .failed), (_, .cancelled):
            content.title = S.notifyFailed(job: displayKind(job.kind),
                                           reason: job.error?.message ?? "")
            content.body = name
        case (.verify, _):
            switch job.survey?.verdict {
            case .complete: content.body = S.notifyVerifyComplete(set: name)
            case .repairable: content.body = S.notifyVerifyRepairable(set: name)
            case .unrepairable:
                let short = max(0, (job.survey?.recovery_needed ?? 0) - (job.survey?.recovery_available ?? 0))
                content.body = S.notifyVerifyUnrepairable(set: name, short: Fmt.count(short))
            default: content.body = name
            }
        case (.repairSet, _):
            content.body = S.notifyRepairDone(set: name)
        case (.create, _):
            let size = job.result?.written?.reduce(Int64(0)) { $0 + $1.size } ?? 0
            content.body = S.notifyCreateDone(set: name, size: Fmt.bytes(size))
        case (.checksumCreate, _), (.checksumVerify, _):
            if let c = job.result?.checksum {
                content.body = S.checksumsResult(ok: Fmt.count(c.ok),
                                                 mismatch: Fmt.count(c.mismatch),
                                                 missing: Fmt.count(c.missing))
            } else {
                content.body = name
            }
        }
        let request = UNNotificationRequest(identifier: "job-\(job.id)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// A job's kind as a short noun. Not the MODE name: "Verify & Repair" is
    /// a sidebar item and reads oddly on a queue row or a progress sheet.
    func displayKind(_ kind: JobKind) -> String {
        switch kind {
        case .create: return S.jobKindCreate
        case .verify: return S.jobKindVerify
        case .repairSet: return S.jobKindRepair
        case .checksumCreate, .checksumVerify: return S.jobKindChecksums
        }
    }

    // MARK: - Drop routing (5.1)

    static let checksumExtensions = ["sfv", "md5", "sha1", "sha256"]

    /// The ONE router. A Finder drop, a dock drop, `application(_:open:)`, the
    /// `parfast://open?path=` URL and the demo menu all come through here, so
    /// there is one set of rules and one place to change them.
    func open(paths: [String]) {
        guard !paths.isEmpty else { return }
        let lower = paths.map { ($0 as NSString).pathExtension.lowercased() }
        if let index = lower.firstIndex(of: "par2") {
            openPar2(paths[index])
            return
        }
        if let index = lower.firstIndex(where: { Self.checksumExtensions.contains($0) }) {
            openChecksumFile(paths[index])
            return
        }
        mode = .create
        create.addSources(paths)
    }

    func openPar2(_ path: String) {
        mode = .verify
        verify.setTarget(path)
        startVerify()
    }

    func openChecksumFile(_ path: String) {
        mode = .checksums
        checksums.subMode = .verify
        checksums.file = path
        startChecksumVerify()
    }

    // MARK: - Actions

    @discardableResult
    func submit(_ spec: JobSpec, showSheet: Bool = true) -> Int64? {
        do {
            let id = try core.submit(spec)
            refresh()
            if showSheet { progressJob = id }
            return id
        } catch {
            report(error)
            return nil
        }
    }

    func startVerify() {
        guard let path = verify.par2Path else { return }
        let spec = VerifySpec(par2: path, extra_dirs: verify.extraDirs, options: verify.options)
        if let id = submit(.verify(spec), showSheet: false) {
            verify.jobId = id
            verify.lastRepairJobId = nil
        }
    }

    func startRepair() {
        guard let path = verify.par2Path else { return }
        let spec = RepairSpec(
            par2: path, extra_dirs: verify.extraDirs, options: verify.options,
            purge: verify.purge, keep_damaged: verify.keepDamaged,
            exclude: Array(verify.excluded))
        if let id = submit(.repairSet(spec)) {
            verify.jobId = id
            verify.lastRepairJobId = id
        }
    }

    func startCreate(queueOnly: Bool = false) {
        guard !create.sources.isEmpty else {
            alert = AlertBox(title: S.errorTitle, message: S.errorNoSources)
            return
        }
        let spec = create.spec()
        if let id = submit(.create(spec), showSheet: !queueOnly) {
            create.jobId = id
            if queueOnly { toast = Toast(text: S.createActionQueue) }
        }
    }

    func startChecksumCreate() {
        guard !checksums.sources.isEmpty else {
            alert = AlertBox(title: S.errorTitle, message: S.errorNoSources)
            return
        }
        if let id = submit(.checksumCreate(checksums.createSpec())) {
            checksums.jobId = id
        }
    }

    func startChecksumVerify() {
        guard !checksums.file.isEmpty else { return }
        if let id = submit(.checksumVerify(ChecksumVerifySpec(file: checksums.file)),
                           showSheet: false) {
            checksums.jobId = id
        }
    }

    func cancel(_ id: Int64) {
        do { try core.cancel(job: id) } catch { report(error) }
        refresh()
    }

    func pause(_ id: Int64) {
        do { try core.pause(job: id) } catch { report(error) }
        refresh()
    }

    func resume(_ id: Int64) {
        do { try core.resume(job: id) } catch { report(error) }
        refresh()
    }

    func remove(_ id: Int64) {
        do { try core.remove(job: id) } catch { report(error) }
        refresh()
    }

    func runNext(_ id: Int64) {
        do { try core.runNext(job: id) } catch { report(error) }
        refresh()
    }

    func setLowPriority(_ id: Int64, _ on: Bool) {
        do { try core.setLowPriority(job: id, on) } catch { report(error) }
        refresh()
    }

    func setQueuePaused(_ paused: Bool) {
        do { try core.setQueuePaused(paused) } catch { report(error) }
        refresh()
    }

    func setConcurrency(_ n: Int) {
        do { try core.setQueueConcurrency(UInt32(max(1, n))) } catch { report(error) }
        refresh()
    }

    func setPostAction(_ action: PostAction) {
        // Confirm ONCE, when it is set (5.5).
        if action == .sleep || action == .shutdown {
            alert = AlertBox(
                title: action == .sleep ? S.queueFinishConfirmSleep : S.queueFinishConfirmShutdown,
                message: "",
                confirm: S.commonOk,
                action: { [weak self] in
                    guard let self else { return }
                    try? self.core.setQueuePostAction(action)
                    self.refresh()
                })
            return
        }
        do { try core.setQueuePostAction(action) } catch { report(error) }
        refresh()
    }

    func apply(settings newValue: CoreSettings) {
        settings = newValue
        do { try core.settingsSet(newValue) } catch { report(error) }
    }

    func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        toast = Toast(text: S.commonCommandCopied)
    }

    func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    func report(_ error: Error) {
        let message: String
        if let core = error as? CoreError {
            message = core.message
        } else {
            message = error.localizedDescription
        }
        alert = AlertBox(title: S.errorTitle, message: message)
    }

    /// True when no engine is linked. The views ask THIS rather than testing
    /// the core's concrete type, so linking FfiCore turns the banner and the
    /// demo menu off in one place.
    var isDemoBuild: Bool { core is MockCore }

    /// Job for the progress sheet.
    var progressSnapshot: JobSnapshot? {
        guard let id = progressJob else { return nil }
        return queue.jobs.first { $0.id == id }
    }
}

/// The post-queue actions, isolated so the rest of the app never talks to
/// System Events directly and a test can compile without it.
enum PowerAction {
    static func perform(_ action: PostAction) {
        let script: String
        switch action {
        case .sleep: script = "tell application \"System Events\" to sleep"
        case .shutdown: script = "tell application \"System Events\" to shut down"
        case .none, .notify: return
        }
        // Best effort and deliberately quiet: a Mac that refuses to sleep is
        // not a reason to put an error sheet over a finished queue.
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
    }
}
