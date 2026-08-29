// Session state: server config, the polling loop, and the queue and
// history snapshots every screen reads.
import Foundation
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

@MainActor
final class AppState: ObservableObject {
    @Published var config: ServerConfig?
    @Published var serverVersion: String?
    /// The one mode=playback poll: queue, history, per-file readiness
    /// and the byte-serving telemetry, all in a single response.
    @Published var snapshot: PlaybackSnapshot?
    /// Rolling throughput samples (MB/s), one per poll, for the Home
    /// chart. ~90 samples at the 2 s cadence = the last three minutes.
    @Published var speedHistory: [Double] = []
    @Published var lastError: String?
    @Published var offlineSince: Date?
    @Published var selectedTab: MainTab = .home
    @Published var playRequest: PlayerTarget?
    /// Where the queue comes from. Persisted, so a second launch in
    /// on-device mode starts the engine without asking again.
    @Published private(set) var source: JobSource = AppSettings.source
    /// One line under the offline banner when something is holding the
    /// queue that the user cannot see from the rows: today that is the
    /// cellular hold.
    @Published var holdNote: String?
    /// Free space where the bytes actually land - the phone's own
    /// filesystem in on-device mode, the daemon's answer otherwise.
    @Published var freeSpaceGB: Double = 0

    let engine = Engine()

    enum MainTab: Hashable { case home, add, history, settings }

    private var client: ApiClient?
    private var pollTask: Task<Void, Never>?
    private static let configKey = "nzbfast.server.config"

    /// Why THIS APP is holding the queue paused, if it is.
    ///
    /// A SET and not a boolean since TODO 281 IO2, because there are now
    /// two independent holders and they overlap in the ordinary case: a
    /// phone that steps onto cellular and is then put in a pocket is
    /// held for both reasons, and the walk back into wifi must not
    /// release the backgrounding hold with it. A boolean per holder
    /// would work too and is what this replaced; a set is one release
    /// rule instead of one per pair.
    ///
    /// WHAT IT IS REALLY FOR is unchanged from IO1 and is the reason it
    /// exists at all: it undoes only its OWN pauses. A user who pressed
    /// pause in the toolbar and then walked out of wifi range and back
    /// must find the queue exactly as they left it, so nothing here ever
    /// reads the daemon's `paused` flag and assumes the pause was ours.
    ///
    /// THE ONE CASE IT STILL CANNOT SEE, stated rather than left to be
    /// found: a user who presses pause WHILE a hold of ours is in force
    /// is indistinguishable, on this contract, from one who did not - so
    /// releasing our hold resumes their pause. Closing it needs the
    /// engine to say who paused it, which is a contract change and not
    /// this box's.
    private var pauseHolds: Set<PauseHold> = []

    /// Bumped by every `release`, checked by `hold` before it commits
    /// ownership: a hold whose pauseAll was in flight when the release
    /// ran must not insert itself into the set the release already
    /// emptied (C22).
    private var holdGeneration = 0

    /// The last link status the cellular policy saw. Kept so the
    /// Settings toggle can re-run the policy against the link as it
    /// stands: the policy task keys on link CHANGES, and a toggle
    /// flipped on an already-cellular link would otherwise wait for
    /// one (C16).
    private(set) var lastLinkStatus: DeviceProfile.LinkStatus = .unknown

    /// The persisted twin of the `.background` member of `pauseHolds`.
    /// The daemon persists ITS half of the pause across a process
    /// death, so ownership has to be persisted too - a cold launch
    /// otherwise reconstructs an empty set against a paused=true
    /// engine and nothing ever resumes it (C21).
    private static let backgroundHoldKey = "nzbfast.hold.background_pause"

    private static func setBackgroundHoldMarker(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: backgroundHoldKey)
    }

    /// A reason this app is holding the queue. One case per INDEPENDENT
    /// holder.
    enum PauseHold: String, Hashable {
        /// The phone is on cellular and the setting says hold.
        case cellular
        /// The app is going into the background and is winding the
        /// in-flight articles down - see `Lifecycle`.
        case background
    }

    /// True while real media is playing, which on iOS is what keeps the
    /// whole process - engine included - scheduled in the background.
    ///
    /// SET BY THE PLAYER and read by `Lifecycle`, which is the whole of
    /// the IO2/IO2b join: with this true, backgrounding does NOT wind the
    /// queue down, because nothing is about to be suspended. It is a
    /// statement about the audio session being active with real audio in
    /// it, never a wish - see `PlayerModel`.
    @Published private(set) var playbackHoldsProcess = false

    func setPlaybackHoldsProcess(_ on: Bool) {
        let had = playbackHoldsProcess
        playbackHoldsProcess = on
        // Playback can end WHILE backgrounded - media finished, failed,
        // or paused from the lock screen - and no application
        // notification fires for it: the process just lost the thing
        // keeping it scheduled. Run the same wind-down the background
        // transition runs (C24).
        if had && !on { lifecycle.playbackHoldDropped() }
        // And it can START again while backgrounded, off the lock
        // screen's PLAY button, with no notification for that either.
        // BOTH edges or neither: with only the drop edge wired up, a
        // pause-then-play on the lock screen wound the queue down and
        // nothing ever brought it back, because `enterForeground` was
        // the only release of the `.background` hold and the app was
        // still backgrounded. Fixed 28 Aug 2026; a change here that
        // drops this line restores a download that never resumes.
        if !had && on { lifecycle.playbackHoldTaken() }
    }

    private lazy var lifecycle = Lifecycle(state: self)

    var isConnected: Bool { config != nil }

    /// The on-device engine has no server until the user gives it one,
    /// and an engine with an empty list holds every job rather than
    /// failing (TODO 154). So the setup screen is shown until a server
    /// is saved, and this is what remembers that it was.
    var needsServerSetup: Bool {
        source == .device && !UserDefaults.standard.bool(forKey: Self.deviceServerKey)
    }

    private static let deviceServerKey = "nzbfast.device.server_saved"

    init() {
        lifecycle.start()
        // REMOTE ONLY on the persisted path. An on-device config carries
        // a port the OS chose for the PREVIOUS launch, and the engine is
        // not running yet in this one - adopting it would poll a dead
        // port and show "not answering" over an app that simply has not
        // started its engine. The engine is started by `useDevice()`
        // from the root view instead.
        guard source == .remote else { return }
        if let data = UserDefaults.standard.data(forKey: Self.configKey),
           let cfg = try? JSONDecoder().decode(ServerConfig.self, from: data) {
            adopt(cfg, version: nil)
        }
    }

    // MARK: source selection

    /// Start the on-device engine and point the app at it.
    ///
    /// Idempotent: a second call while it is up re-adopts the same
    /// endpoint rather than starting anything.
    func useDevice() async throws {
        source = .device
        AppSettings.source = .device
        let cfg = try await engine.start()
        adopt(cfg, version: nil, persist: false)
        // Reclaim a background pause an earlier process took and never
        // got to release: the engine restores paused=true from its
        // settings, and with the marker set that pause is OURS to
        // resume (C21). In the foreground it is released now; a
        // BGProcessing cold launch keeps it held for `runCatchUp` to
        // decide, cellular policy included.
        if UserDefaults.standard.bool(forKey: Self.backgroundHoldKey) {
            pauseHolds.insert(.background)
            #if canImport(UIKit)
            if UIApplication.shared.applicationState != .background {
                await release(.background)
            }
            #endif
        }
    }

    /// Point the app at a daemon elsewhere, and stop the local engine if
    /// one was running - two engines on one phone is a queue split in
    /// half with no way to see it.
    func useRemote() {
        source = .remote
        AppSettings.source = .remote
        engine.stop()
    }

    /// Remember that the on-device engine has a provider configured.
    func markServerConfigured() {
        UserDefaults.standard.set(true, forKey: Self.deviceServerKey)
        objectWillChange.send()
    }

    func api() -> ApiClient? { client }

    /// Validate URL + key against the daemon, then persist and start
    /// polling. mode=version answers without a key, so the key itself
    /// is proven with the call the app lives on: mode=playback needs
    /// the full key and proves the daemon speaks contract v1.
    func connect(urlString: String, apiKey: String) async throws {
        var s = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        if !s.contains("://") { s = "http://" + s }
        while s.hasSuffix("/") { s.removeLast() }
        guard let url = URL(string: s), url.host != nil else { throw ApiError.badURL }
        let cfg = ServerConfig(baseURL: url, apiKey: apiKey.trimmingCharacters(in: .whitespacesAndNewlines))
        let probe = ApiClient(config: cfg)
        let ver = try await probe.version()
        _ = try await probe.playback(limit: 1)
        if let data = try? JSONEncoder().encode(cfg) {
            UserDefaults.standard.set(data, forKey: Self.configKey)
        }
        source = .remote
        AppSettings.source = .remote
        adopt(cfg, version: ver.nzbfast ?? ver.version)
    }

    private func adopt(_ cfg: ServerConfig, version: String?, persist: Bool = true) {
        // Re-adopting over a live connection (the QA connect path) must
        // not carry the previous server's state: its snapshot, and the
        // chart samples that would otherwise be drawn against the new
        // server's link peak.
        if client != nil {
            snapshot = nil
            speedHistory = []
        }
        config = cfg
        serverVersion = version
        client = ApiClient(config: cfg)
        startPolling()
    }

    func disconnect() {
        pollTask?.cancel()
        pollTask = nil
        UserDefaults.standard.removeObject(forKey: Self.configKey)
        if source == .device { engine.stop() }
        config = nil
        client = nil
        snapshot = nil
        speedHistory = []
        lastError = nil
        offlineSince = nil
        holdNote = nil
        pauseHolds.removeAll()
        Self.setBackgroundHoldMarker(false)
        ScreenAwake.releaseAll()
        LiveProgress.end()
    }

    // MARK: platform policies

    /// Hold the queue while the phone is on cellular, and let it go
    /// again when it is not.
    ///
    /// It undoes ONLY ITS OWN PAUSE. A user who pressed pause in the
    /// toolbar and then walked out of wifi range and back must find the
    /// queue exactly as they left it, which is why this tracks whether
    /// the pause was its doing rather than reading the daemon's paused
    /// flag and assuming.
    func applyCellularPolicy(_ status: DeviceProfile.LinkStatus) async {
        lastLinkStatus = status
        // ON-DEVICE ONLY, and this is the whole scope of the setting.
        // In remote mode the downloading happens on a machine across the
        // house whose link has nothing to do with this phone's, so
        // pausing it because the phone stepped onto cellular would stop
        // a download that was costing the user nothing. The Settings
        // sheet hides the toggle there for the same reason.
        guard isConnected, source == .device else {
            holdNote = nil
            return
        }
        let shouldHold = AppSettings.pauseOnCellular && status == .cellular
        if shouldHold {
            await hold(.cellular)
            holdNote = "Holding on cellular. Change this in Settings."
        } else {
            await release(.cellular)
            holdNote = nil
        }
    }

    /// Take a pause hold. Idempotent, and the FIRST hold is what
    /// actually pauses: a second reason arriving over a queue this app
    /// already paused must not re-issue the call, or the release rule
    /// below stops being able to tell how many holders there are.
    func hold(_ reason: PauseHold) async {
        guard isConnected, source == .device else { return }
        if pauseHolds.isEmpty {
            // ALREADY PAUSED BY SOMEONE ELSE means there is nothing to
            // hold and, far more importantly, nothing to release: taking
            // a hold here would make the eventual release resume a queue
            // the user had paused themselves.
            guard snapshot?.paused != true else { return }
            let gen = holdGeneration
            // Persisted BEFORE the pause lands: the daemon persists its
            // paused flag on the way through, so if iOS kills this
            // process between the two writes the relaunch still knows
            // the pause was ours (C21).
            if reason == .background { Self.setBackgroundHoldMarker(true) }
            do {
                try await client?.pauseAll()
            } catch {
                // A REFUSED or timed-out pause is no pause: claiming
                // ownership over it would make the eventual release
                // resume a queue this app never held (C22).
                //
                // A CANCELLED one is a different animal, and treating
                // the two alike is how that same C22 remedy stranded
                // the queue. Foregrounding cancels the grace task this
                // runs on, and the cancellation lands on the AWAIT, not
                // on the request: the pause has already reached the
                // engine, which pauses. Disowning it there leaves a
                // paused queue nobody claims - through the relaunch as
                // well, because the marker is cleared with it - until
                // the user notices and taps Resume. MEASURED 27 Aug
                // 2026 on the Simulator: 0.3 s in another app and
                // straight back stranded it 3 runs out of 3, while a
                // 3 s trip (long enough for the pause to answer and
                // ownership to commit) was clean.
                //
                // So a cancellation COMPENSATES instead of disowning.
                // It cannot know whether the pause landed, and the two
                // wrong answers are not equal: resuming a queue that
                // never paused is a no-op, while disowning one that did
                // is a download that never restarts.
                if isCancellation(error) {
                    await undoOurPause(reason)
                } else if reason == .background {
                    Self.setBackgroundHoldMarker(false)
                }
                return
            }
            await refresh()
            // A release that ran while the pause was in flight
            // (foregrounding cancels the grace) must win, or this task
            // inserts its hold into a set the release already emptied
            // and strands a paused queue in the foreground (C22).
            guard !Task.isCancelled, gen == holdGeneration else {
                // Through `undoOurPause` and not a bare `try? await`:
                // the commonest way to reach this line is `Task
                // .isCancelled`, and a URLSession call on a cancelled
                // task fails before it leaves the process, so the bare
                // form is a resume that is never sent and a `try?` that
                // hides it.
                await undoOurPause(reason)
                return
            }
        } else if reason == .background {
            // Somebody else's hold already carries the pause; ownership
            // of OUR share still has to survive a process death (C21).
            Self.setBackgroundHoldMarker(true)
        }
        pauseHolds.insert(reason)
    }

    /// Give back a pause this app issued and is not going to keep.
    ///
    /// UNSTRUCTURED, and that is the fix rather than a style choice.
    /// Every caller is on a task that has just been cancelled, and an
    /// unstructured `Task` is the one thing here that does not inherit
    /// that - so the compensating call actually goes out. It keeps the
    /// main actor (the isolation IS inherited), so nothing about
    /// `client` has to become Sendable to say it.
    private func undoOurPause(_ reason: PauseHold) async {
        if reason == .background { Self.setBackgroundHoldMarker(false) }
        await Task { @MainActor [weak self] in
            try? await self?.client?.resumeAll()
            await self?.refresh()
        }.value
    }

    /// Did this fail because we were torn down, rather than because the
    /// engine said no? `URLSession` reports a cancelled request as
    /// `URLError.cancelled` (-999) and never as a `CancellationError`,
    /// so the task's own flag is not enough on its own to see it.
    private func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if (error as? URLError)?.code == .cancelled { return true }
        return Task.isCancelled
    }

    /// Drop a pause hold, and resume only when the LAST one goes.
    func release(_ reason: PauseHold) async {
        // Bumped even when there is nothing here to remove yet: the
        // in-flight `hold` whose pauseAll has not answered IS the thing
        // being released, and it checks this before committing (C22).
        holdGeneration += 1
        guard pauseHolds.remove(reason) != nil else { return }
        if reason == .background { Self.setBackgroundHoldMarker(false) }
        guard pauseHolds.isEmpty else { return }
        do {
            try await client?.resumeAll()
        } catch {
            // The resume did not land. Keep ownership so a later
            // release can try again rather than stranding the pause as
            // one nobody claims (C21).
            pauseHolds.insert(reason)
            if reason == .background { Self.setBackgroundHoldMarker(true) }
            return
        }
        await refresh()
    }

    /// Keep the display awake while there is work to do.
    ///
    /// The honest answer to the one platform limit that matters: with
    /// the app backgrounded the process is suspended and the sockets
    /// stop, so a phone that is meant to keep downloading has to stay
    /// awake on this screen. Only ever set while there IS work - a
    /// setting left on must not hold the screen awake over an empty
    /// queue.
    func updateKeepAwake() {
        let working = AppSettings.keepAwake
            && source == .device
            && snapshot?.paused != true
            && !(snapshot?.queue.isEmpty ?? true)
        // Through the arbiter and NEVER straight at
        // `isIdleTimerDisabled`: the player holds the same flag for its
        // own reason, and a direct write here turns the display off
        // under a video. See ScreenAwake for the two live instances of
        // that this replaced.
        ScreenAwake.set(.working, working)
    }

    func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh(sample: true)
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    /// `sample` is true only from the 2 s poll loop: pull-to-refresh and
    /// the refresh after every action call this too, and letting those
    /// append made the chart's timebase lie (extra near-simultaneous
    /// samples compress the "90 samples = 3 minutes" window).
    func refresh(sample: Bool = false) async {
        guard let client else { return }
        do {
            // One call for everything: readiness rides the job rows (no
            // per-job probes) and the telemetry feeds the player overlay.
            let snap = try await client.playback()
            snapshot = snap
            if sample {
                speedHistory = Array((speedHistory + [(snap.speedBps ?? 0) / 1e6]).suffix(90))
            }
            lastError = nil
            offlineSince = nil
            updateFreeSpace(snap)
            updateKeepAwake()
            LiveProgress.update(from: snap, source: source)
        } catch {
            // Keep the last good snapshot on screen; show a banner and
            // keep trying. A fault profile must never wedge the app.
            //
            // The idle timer goes back to the OS's own: a server that has
            // stopped answering is not work in progress, and a keep-awake
            // left latched on holds the display forever over nothing.
            // The WORKING hold only: a server that has stopped
            // answering is not work in progress. The PLAYER's hold
            // stays, because a failed poll says nothing about whether a
            // video is on screen - and dropping it here is exactly the
            // bug that put the display to sleep mid-playback.
            ScreenAwake.release(.working)
            if offlineSince == nil { offlineSince = Date() }
            lastError = (error as? LocalizedError)?.errorDescription ?? "The server did not answer."
        }
    }

    /// Present the player for a job row. Row 16 already hands over the
    /// tokenized play URL; /m3u is only the fallback for a row that
    /// lacked one. mode=playback is read-only by design; the probe is
    /// what promotes a live job's file index, so fire it once for the
    /// one job the user opened (contract row 13).
    func requestPlay(job: PlaybackJob) async throws {
        guard let client else { throw ApiError.daemon("Not connected.") }
        let url: URL
        if let s = job.stream, let u = URL(string: s) {
            url = u
        } else {
            url = try await client.playURL(for: job.nzoId)
        }
        if job.playback?.source == "live" {
            Task { _ = try? await client.probe(job.nzoId) }
        }
        playRequest = PlayerTarget(jobId: job.nzoId, url: url)
    }

    /// Resolve a tokenized play URL by id (the QA deep-link path).
    func requestPlay(id: String) async throws {
        guard let client else { throw ApiError.daemon("Not connected.") }
        let url = try await client.playURL(for: id)
        playRequest = PlayerTarget(jobId: id, url: url)
    }

    /// Free space, from the phone's own filesystem where that is the
    /// filesystem in question.
    ///
    /// `diskspace_gb` on the contract is the ENGINE's answer about its
    /// own out directory, which is right for a machine across the room.
    /// In on-device mode the local reading wins, because it is measured
    /// on the very directory the writes go to and it accounts for the
    /// purgeable reserve iOS holds back.
    private func updateFreeSpace(_ snap: PlaybackSnapshot) {
        if source == .device {
            let bytes = DeviceProfile.freeBytes(at: Engine.downloadsDir)
            if bytes > 0 {
                freeSpaceGB = Double(bytes) / 1e9
                return
            }
        }
        freeSpaceGB = snap.diskspaceGb ?? 0
    }

    // MARK: link handling

    /// nzblnk links arrive from the OS; the nzbfast scheme carries
    /// DEBUG-only QA hooks so headless Simulator runs can drive the
    /// same code paths the buttons call.
    func handleOpenURL(_ url: URL) {
        if url.scheme == "nzblnk" {
            Task {
                do {
                    guard let client else { throw ApiError.daemon("Not connected.") }
                    let resp = try await client.addNzblnk(url.absoluteString)
                    guard resp.status else {
                        throw ApiError.daemon(resp.error ?? "The server refused that link.")
                    }
                    await refresh()
                } catch {
                    lastError = (error as? LocalizedError)?.errorDescription
                        ?? "Could not add that link."
                }
            }
            return
        }
        // A .nzb shared from another app ("Open in nzbfast" on the
        // share sheet) arrives as a file URL - same upload path the
        // document picker uses, security scope included. Every failure
        // class is surfaced: an OS share that silently does nothing is
        // indistinguishable from success, and the user's NZB just
        // vanishes. Navigation to Home happens only on a real add.
        if url.isFileURL {
            Task {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                do {
                    guard let client else { throw ApiError.daemon("Not connected.") }
                    // Bounded: see readBoundedNzb. The sharing app
                    // chooses this file, not us.
                    let data = try readBoundedNzb(at: url)
                    let resp = try await client.addFile(data: data, filename: url.lastPathComponent)
                    guard resp.status else {
                        throw ApiError.daemon(resp.error ?? "The server refused that NZB.")
                    }
                    await refresh()
                    selectedTab = .home
                } catch {
                    lastError = (error as? LocalizedError)?.errorDescription
                        ?? "Could not add \(url.lastPathComponent)."
                }
            }
            return
        }
        #if DEBUG
        Task { await handleQA(url) }
        #endif
    }

    #if DEBUG
    /// The DEBUG-only QA surface, driven by `-qaurl` launch arguments.
    ///
    /// AWAITED, one link at a time, which is what makes a SEQUENCE
    /// possible: on-device mode has to start the engine, then save a
    /// provider, then import an NZB, and each of those needs the one
    /// before it to have finished. Firing them as detached Tasks (which
    /// is what this did while there was only ever one link per launch)
    /// races them against each other.
    ///
    /// It exists so a headless Simulator run can drive the same code
    /// paths the buttons call. `simctl openurl` is not usable for this:
    /// a custom scheme raises an "Open in app?" dialog nothing headless
    /// can tap, and it parks at SpringBoard level until a restart.
    func handleQA(_ url: URL) async {
        guard url.scheme == "nzbfast", url.host == "qa" else { return }
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var query: [String: String] = [:]
        for item in comps?.queryItems ?? [] { query[item.name] = item.value }
        switch url.path {
        case "/connect":
            if let u = query["url"] {
                try? await connect(urlString: u, apiKey: query["key"] ?? "")
            }
        case "/device":
            try? await useDevice()
        case "/server":
            var srv = NewsServer()
            srv.host = query["host"] ?? ""
            srv.port = Int(query["port"] ?? "") ?? 119
            srv.tls = query["tls"] == "1"
            srv.username = query["user"] ?? ""
            srv.password = query["pass"] ?? ""
            srv.connections = Int(query["conns"] ?? "") ?? 8
            // Spelled out rather than `if (try? await client?.save())
            // != nil`: `try?` over an optional-chained call is a DOUBLE
            // optional, so a missing client makes that read `.some(nil)`
            // and the condition passes with nothing having been saved.
            if let client {
                do {
                    try await client.serverSave(srv)
                    markServerConfigured()
                    await refresh()
                } catch {
                    lastError = (error as? LocalizedError)?.errorDescription
                        ?? "The engine would not save that server."
                }
            }
        case "/addfile":
            // The Files-app import path, exactly: a file URL through the
            // same handler a share or a Files "Open in" arrives on.
            if let path = query["path"] {
                handleOpenURL(URL(fileURLWithPath: path))
            }
        case "/addurl":
            if let u = query["u"] {
                _ = try? await client?.addUrl(u)
                await refresh()
            }
        case "/play":
            if let id = query["id"] {
                // THROUGH THE ROW where there is one, which is the path
                // the Play button takes: row 16 already carries the
                // tokenized play URL, so `requestPlay(job:)` needs no
                // network call and fires the live-job probe. Driving
                // `requestPlay(id:)` instead tested a FALLBACK the UI
                // only reaches for a row that lacked a URL - and it
                // raced, because that call resolves against readiness
                // that a just-relaunched engine has not re-established
                // yet, so the link failed silently and the player never
                // opened. A refresh first, for the same reason: on a
                // cold launch the first poll has not landed.
                await refresh()
                let rows = (snapshot.map { $0.queue + $0.history } ?? [])
                if let job = rows.first(where: { $0.nzoId == id }) {
                    try? await requestPlay(job: job)
                } else {
                    try? await requestPlay(id: id)
                }
            }
        case "/stopplay":
            // Dismisses the player the way the close button does, so a
            // headless run can drive the SECOND half of the IO2b claim:
            // that the queue goes back to being wound down when
            // playback stops. Without it only the "keeps downloading
            // while playing" half is reachable from a script, and a
            // one-sided test of a two-sided rule is the kind that
            // passes over a hold nothing ever releases.
            playRequest = nil
        case "/pause":
            if let id = query["id"] {
                try? await client?.pauseJob(id)
                await refresh()
            }
        case "/resume":
            if let id = query["id"] {
                try? await client?.resumeJob(id)
                await refresh()
            }
        case "/tab":
            switch query["name"] {
            case "add": selectedTab = .add
            case "history": selectedTab = .history
            case "settings": selectedTab = .settings
            default: selectedTab = .home
            }
        case "/stopengine":
            engine.stop()
        case "/disconnect":
            disconnect()
        default:
            break
        }
    }
    #endif
}
