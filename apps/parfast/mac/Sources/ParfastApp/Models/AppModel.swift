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
        case verify, create, posting, checksums, queue

        var id: String { rawValue }

        var title: String {
            switch self {
            case .verify: return S.modeVerify
            case .create: return S.modeCreate
            case .posting: return S.modePosting
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
            case .posting: return "shippingbox"
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
    let posting: PostingModel

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
    /// False until the first snapshot has been read. The jobs already finished
    /// in it came back from the queue store (a previous run's), and they are
    /// marked seen without a notification: posting one for each of them at
    /// launch replayed every old completion as if it had just happened.
    private var sawFirstSnapshot = false
    private var notificationsAsked = false
    /// The name of each job this run submitted, from its spec: the fallback
    /// for a core before 9 Nov 2026, which sent no `title`, and for a store
    /// job loaded with an empty one (sweep finding A37; see
    /// `JobSnapshot.title`). A job restored from the store was submitted by
    /// an earlier run and is not in here; it falls back to its survey's set
    /// name where it has one.
    private var submittedTitles: [Int64: String] = [:]

    init(core: CoreClient) {
        self.core = core
        self.capabilities = (try? core.capabilities()) ?? Capabilities(
            version: "unknown", engine: "unknown", cpu: "", kernel: "",
            std_naming: false, unicode_policy: false, data_skipping: false,
            fast_solver: false, pause: false, low_priority: false)
        self.verify = VerifyModel()
        self.create = CreateModel()
        self.checksums = ChecksumsModel()
        self.posting = PostingModel()
        self.settings = (try? core.settingsGet()) ?? CoreSettings()
        create.applyDefaults(settings)
        checksums.applyDefaults(settings)
        posting.applyDefaults(settings)
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
        guard var snapshot = try? core.queueSnapshot() else { return }
        fillTitles(&snapshot)
        queue = snapshot
        verify.apply(queue: snapshot)
        autoRepairIfDue()
        create.apply(queue: snapshot)
        checksums.apply(queue: snapshot)
        posting.apply(queue: snapshot)
        noteCompletions(snapshot)
    }

    /// A title for every job the core left untitled: the spec's name for a job
    /// this run submitted, else the survey's set name. The core's own value,
    /// when a core sends one, always wins.
    private func fillTitles(_ snapshot: inout QueueSnapshot) {
        for i in snapshot.jobs.indices where (snapshot.jobs[i].title ?? "").isEmpty {
            let job = snapshot.jobs[i]
            let name = submittedTitles[job.id] ?? job.survey?.set_name ?? ""
            if !name.isEmpty { snapshot.jobs[i].title = name }
        }
    }

    /// The jobs that finished since the last snapshot, each reported once.
    /// The first snapshot reports NONE: whatever is finished in it came back
    /// from the queue store, and announcing those at launch replayed every
    /// old completion as news (sweep, section B).
    func newlyFinished(in snapshot: QueueSnapshot) -> [JobSnapshot] {
        if !sawFirstSnapshot {
            sawFirstSnapshot = true
            for job in snapshot.jobs where job.state.isFinished {
                seenFinished.insert(job.id)
            }
        }
        var out: [JobSnapshot] = []
        for job in snapshot.jobs where job.state.isFinished && !seenFinished.contains(job.id) {
            seenFinished.insert(job.id)
            out.append(job)
        }
        return out
    }

    private func noteCompletions(_ snapshot: QueueSnapshot) {
        for job in newlyFinished(in: snapshot) {
            // Not when the job left something out: the sheet is where those
            // lines are shown, and closing it on Done would hide them (A36).
            if settings.general.auto_close_progress && job.state == .done
                && progressJob == job.id && (job.result?.leftOut.isEmpty ?? true) {
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
        // `.interrupted` belongs here too: it is a job that did NOT finish
        // (the app quit under it), and it used to fall through to the kind's
        // success arm and be announced as done.
        case (_, .failed), (_, .cancelled), (_, .interrupted):
            let reason = job.error?.message
                ?? (job.state == .interrupted ? S.queueStateInterrupted : "")
            content.title = S.notifyFailed(job: displayKind(job.kind), reason: reason)
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
        case (.postingSet, _):
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
        // What the job left out (A36), in the core's own words, under the
        // body: a Done that skipped files must not read as a plain Done.
        if job.state == .done, let first = job.result?.leftOut.first {
            content.body += content.body.isEmpty ? first : "\n" + first
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
        case .postingSet: return S.jobKindPostingSet
        }
    }

    /// The modes this core can serve, in sidebar order. The posting set is
    /// HIDDEN against a core whose `pf_capabilities.posting_set` is not true:
    /// that core would refuse the job (API.md, capability table).
    var availableModes: [Mode] {
        Mode.allCases.filter { $0 != .posting || capabilities.hasPostingSet }
    }

    // MARK: - Drop routing (5.1)

    static let checksumExtensions = ["sfv", "md5", "sha1", "sha256"]

    /// The ONE router. A Finder drop, a dock drop, `application(_:open:)`, the
    /// `parfast://open?path=` URL and the demo menu all come through here, so
    /// there is one set of rules and one place to change them.
    ///
    /// `fromURL` is the one difference a URL makes, and it only ever takes
    /// something AWAY. Any web page can fire a `parfast://` link at this app,
    /// so a URL may open a set and verify it - a read - but never starts the
    /// repair that Settings' "verify, then repair" would start after a Finder
    /// open: a repair writes into a folder of the link's choosing and, with
    /// the purge default on, deletes recovery files there (sweep finding A34).
    /// The Repair button is still offered when the verify says repairable, so
    /// the user is the one who confirms it.
    func open(paths: [String], fromURL: Bool = false) {
        guard !paths.isEmpty else { return }
        let lower = paths.map { ($0 as NSString).pathExtension.lowercased() }
        if let index = lower.firstIndex(of: "par2") {
            openPar2(paths[index], allowAutoRepair: !fromURL)
            return
        }
        if let index = lower.firstIndex(where: { Self.checksumExtensions.contains($0) }) {
            openChecksumFile(paths[index])
            return
        }
        // Plain files dropped on the posting-set pane are ITS sources; from
        // anywhere else they start a Create, as they always have.
        if mode == .posting && capabilities.hasPostingSet {
            posting.addSources(paths)
            return
        }
        mode = .create
        create.addSources(paths)
    }

    /// The paths a `parfast://open?path=...` URL names, and NOTHING for any
    /// other URL. The host used to be ignored, so `parfast://anything?path=`
    /// was an open too; `open` is the one host this route answers (the
    /// `demo` host is `DemoRoute`'s, which runs first). Only absolute paths
    /// are taken - a relative one would resolve against whatever directory
    /// the app happened to be started in.
    nonisolated static func pathsFromOpenURL(_ url: URL) -> [String] {
        guard url.scheme?.lowercased() == "parfast",
              url.host?.lowercased() == "open" else { return [] }
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        return items.filter { $0.name == "path" }
            .compactMap(\.value)
            .filter { $0.hasPrefix("/") }
    }

    func openPar2(_ path: String, allowAutoRepair: Bool = true) {
        mode = .verify
        verify.setTarget(path)
        // Settings' "Opening a .par2: verify, then repair". The setting was
        // stored and offered on this platform and acted on by nothing, so a
        // Mac user who chose it got a verify and a Repair button (Gemini
        // sweep M18.2). Windows has had it since chip D. Never armed by a
        // `parfast://` URL - see `open(paths:fromURL:)`.
        verify.autoRepairPending = allowAutoRepair
            && settings.general.open_par2 == .verifyThenRepair
        startVerify()
    }

    /// The repair an open under "verify, then repair" owes, on the snapshot
    /// in which its verify finishes. Once: the flag is cleared there whatever
    /// the verdict, so a clean or unrepairable set is left exactly as a plain
    /// verify leaves it.
    private func autoRepairIfDue() {
        guard verify.autoRepairPending,
              let job = verify.snapshot, job.id == verify.jobId, job.kind == .verify,
              job.state.isFinished else { return }
        verify.autoRepairPending = false
        if job.state == .done && verify.canRepair { startRepair() }
    }

    func openChecksumFile(_ path: String) {
        mode = .checksums
        checksums.subMode = .verify
        checksums.file = path
        // The previous file's result must not stand under this file's name
        // if the submit below is refused.
        checksums.verifyJobId = nil
        checksums.verifySnapshot = nil
        startChecksumVerify()
    }

    // MARK: - Actions

    @discardableResult
    func submit(_ spec: JobSpec, showSheet: Bool = true) -> Int64? {
        do {
            let id = try core.submit(spec)
            let name = spec.displayName
            if !name.isEmpty { submittedTitles[id] = name }
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

    /// `renameOnly` and `purge` are ONE-SHOT overrides for the buttons that
    /// mean a particular kind of run ("Rename to match set", "Delete .par2
    /// files"). They used to be written into the pane's own options before
    /// the call and never put back, so every later repair in the session -
    /// on this set or the next one opened - silently ran rename-only, or
    /// deleted its recovery files (Gemini sweep M18.3).
    func startRepair(renameOnly: Bool? = nil, purge: Bool? = nil) {
        guard let path = verify.par2Path else { return }
        var options = verify.options
        if let renameOnly { options.rename_only = renameOnly }
        let spec = RepairSpec(
            par2: path, extra_dirs: verify.extraDirs, options: options,
            purge: purge ?? verify.purge, keep_damaged: verify.keepDamaged,
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

    /// The posting set. The spec carries the password, if any, straight to the
    /// core; nothing here logs or keeps a copy of it.
    func startPosting(queueOnly: Bool = false) {
        guard capabilities.hasPostingSet else { return }
        guard !posting.sources.isEmpty else {
            alert = AlertBox(title: S.errorTitle, message: S.errorNoSources)
            return
        }
        if let id = submit(.postingSet(posting.spec()), showSheet: !queueOnly) {
            posting.jobId = id
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
            checksums.verifyJobId = id
            checksums.apply(queue: queue)
        }
    }

    /// A Cancel that lands on a job which finished a moment ago is refused
    /// by the core (`not_found`, API.md: it keeps the job's state and its
    /// result). That is the race between the click and the job, not a fault,
    /// so it is not an alert: the refresh shows the job as it finished.
    func cancel(_ id: Int64) {
        do { try core.cancel(job: id) } catch {
            if !Self.isAlreadyFinished(error) { report(error) }
        }
        refresh()
    }

    nonisolated static func isAlreadyFinished(_ error: Error) -> Bool {
        if let core = error as? CoreError { return core.code == "not_found" }
        if case ClientError.noSuchJob = error { return true }
        return false
    }

    /// `pf_queue_open_store` refused the store - written by a newer parfast
    /// and left alone (nothing is saved this run), or unreadable and moved
    /// aside to the path the message names. Either way the user's old queue
    /// is not on screen, so the core's own sentence is shown once, at launch.
    func reportStoreOpenFailure(_ error: Error) {
        report(error)
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

    /// Re-read the core's settings into `settings`. The Settings window calls
    /// this as it opens, so it edits what the core has NOW rather than the
    /// copy this model took at launch - the queue's stepper and "When
    /// finished" change the core's settings without passing through here.
    func reloadSettings() {
        if let fresh = try? core.settingsGet() { settings = fresh }
    }

    /// Write ONE edit: the fields that differ between `old` and `new`, over
    /// the core's settings as they are at this moment, and nothing at all when
    /// that changes nothing.
    ///
    /// This replaced `apply(settings:)`, which wrote the caller's whole struct.
    /// The caller's struct was always this model's launch-time copy, and
    /// `pf_settings_set` is a plain replace, so every toggle in Settings (and
    /// merely OPENING Settings, or the progress sheet with notifications off)
    /// put the queue's concurrency back to its launch value and restored or
    /// dropped "Shut down when finished" - sweep finding A30. See
    /// `CoreSettings.applyingChanges(from:to:)` for why the diff is per field.
    func apply(changesFrom old: CoreSettings, to new: CoreSettings) {
        guard old != new else { return }
        // No fallback to the cached `settings` when the read fails: that copy
        // can be stale, and writing over it is the bug this function fixes.
        let fresh: CoreSettings
        do { fresh = try core.settingsGet() } catch {
            report(error)
            return
        }
        let merged = fresh.applyingChanges(from: old, to: new)
        let previous = settings
        settings = merged
        verify.applyChangedDefaults(from: previous, to: merged)
        guard merged != fresh else { return }
        do { try core.settingsSet(merged) } catch { report(error) }
    }

    /// One field changed in place, by a control that is not the Settings
    /// window (the progress sheet's "Notify me").
    func updateSettings(_ edit: (inout CoreSettings) -> Void) {
        var new = settings
        edit(&new)
        apply(changesFrom: settings, to: new)
    }

    /// "Clear remembered checksums". True when the store is clear; a failure
    /// is reported the way every other core failure is.
    func clearDigestCache() -> Bool {
        do {
            try core.clearDigestCache()
            return true
        } catch {
            report(error)
            return false
        }
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
