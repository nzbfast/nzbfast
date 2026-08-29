// What happens to a download when the user switches away (TODO 281
// IO2), which on this platform is the whole product question.
//
// THE MATRIX, from the plan's addendum B, because every decision below
// is one row of it. There is NO general way to keep NNTP sockets alive
// in the background: Apple's background transfer service runs in a
// SYSTEM process and speaks HTTP only, and an in-process proxy does not
// help because the proxy is suspended with the app. Every competitor
// has the same wall. What is actually available, in order:
//
//   1. REAL PLAYBACK keeps the whole process alive - Picture in Picture
//      with video on screen, the audio background mode with it off.
//      Download and playback are one process here, so watching IS the
//      backgrounding story rather than something that coexists with it.
//      That is IO2b, and this file's job is to KEEP OUT OF ITS WAY:
//      see `playbackHolds`.
//   2. Foreground plus keep-awake. Plugged in on a shelf, a small
//      always-on downloader. `ScreenAwake`.
//   3. FINISH-IN-FLIGHT GRACE, which is this file. About half a minute
//      to wind the in-flight articles down and reach a point where
//      being frozen costs nothing.
//   4. Opportunistic completion via `BGProcessingTask`, at times iOS
//      picks. Never guaranteed and NEVER PROMISED IN UI.
//
// WHAT THE GRACE IS ACTUALLY FOR, since "iOS suspends you" sounds like
// something no amount of app code can improve. Suspension is not
// termination: a suspended process is frozen and thawed, and the engine
// resumes mid-article perfectly well. The thing worth spending thirty
// seconds on is the case where the app is later KILLED while suspended,
// which the OS does freely under memory pressure and which arrives with
// no callback at all. A queue wound down to a quiet point resumes from
// its journal with nothing to redo; one frozen mid-flight has articles
// in the air that nobody will ever answer for, and the resume re-fetches
// them. So the grace does not extend the download - it makes the STOP
// cheap, and the difference is only ever visible on the next launch.
//
// NEVER AN AUDIO SESSION WITH NOTHING PLAYING, and never a location
// trick. Those are the two moves that turn this app's review posture
// from safe to removable, and the plan says so twice. The audio
// entitlement in IO2b is legitimate for exactly one reason: real media
// is really playing.
import Foundation
import BackgroundTasks
import Network
#if canImport(UIKit)
import UIKit
#endif

@MainActor
final class Lifecycle {

    /// The identifier registered for opportunistic completion.
    ///
    /// It MUST also appear in `BGTaskSchedulerPermittedIdentifiers` in
    /// Info.plist: `BGTaskScheduler.register` throws an uncatchable
    /// exception for an identifier that is not listed, so a mismatch
    /// here is a crash on launch and not a feature that quietly does
    /// nothing.
    static let processingTaskID = "com.nzbfast.mobile.catchup"

    private unowned let state: AppState
    private var observers: [NSObjectProtocol] = []
    /// The wind-down in flight, so a fast switch back can cancel it
    /// rather than racing it.
    private var graceTask: Task<Void, Never>?

    init(state: AppState) {
        self.state = state
    }

    func start() {
        #if canImport(UIKit)
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                                        object: nil, queue: .main) { [weak self] _ in
            // The notification handler is the ONLY place a background
            // task may be begun: by the time an async continuation runs,
            // the app can already be suspended and the request is
            // refused. So the assertion is taken here, synchronously,
            // and the async work happens under it.
            MainActor.assumeIsolated { self?.enterBackground() }
        })
        observers.append(nc.addObserver(forName: UIApplication.willEnterForegroundNotification,
                                        object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.enterForeground() }
        })
        #endif
    }

    deinit {
        for o in observers { NotificationCenter.default.removeObserver(o) }
    }

    // MARK: - the grace

    private func enterBackground() {
        #if canImport(UIKit)
        // NOT OUR PROBLEM IN REMOTE MODE. The downloading is happening
        // on a machine across the house that this phone's app switcher
        // has no bearing on, so winding it down because the user opened
        // Messages would stop a download that was costing nothing. Same
        // scoping as the cellular hold, for the same reason.
        guard state.source == .device, state.isConnected else { return }

        // PLAYBACK OUTRANKS THE GRACE, and this line is where IO2 and
        // IO2b meet. With real media playing the process is not going to
        // be suspended at all: the audio background mode (or PiP) keeps
        // it scheduled, the engine keeps its sockets, and the download
        // runs at full speed with the phone in a pocket. Pausing here
        // would break the one case on this platform where backgrounding
        // is free.
        LiveProgress.qaJournal("grace enterBackground playbackHolds=\(state.playbackHoldsProcess)")
        guard !state.playbackHoldsProcess else { return }

        // Nothing to wind down, and more importantly nothing to resume:
        // a queue the USER paused must come back paused. `hold` records
        // whose pause it is, which is what makes that true.
        guard state.snapshot?.paused != true else { return }

        // Re-entry (the notification, plus a playback hold dropping
        // while already backgrounded) must not stack a second assertion
        // over the first - `endGrace` ends ONE identifier.
        guard backgroundTask == .invalid else { return }

        let task = UIApplication.shared.beginBackgroundTask(withName: "nzbfast.finish-in-flight") {
            // EXPIRATION. iOS kills an app that lets an assertion run
            // out, so this has to end it - and it has to be safe to run
            // concurrently with the body below, which is why `endGrace`
            // is idempotent.
            //
            // `assumeIsolated` HERE IS DELIBERATE AND WAS RE-EXAMINED
            // (28 Aug 2026), so do not "make it safe" by hopping to the
            // main queue. Apple documents the expiration handler as
            // called on the main thread, so the assumption is a
            // contract and not a bet - and the reason it must stay
            // synchronous is the sentence above: an `endBackgroundTask`
            // deferred past this handler's RETURN is exactly the late
            // work that gets the app killed, which is the failure this
            // handler exists to prevent. The lock-screen transport
            // handlers in `Playback.swift` are the opposite case (no
            // documented thread, nothing fatal about a one-turn delay)
            // and they hop; the difference is the documentation, not a
            // style preference.
            MainActor.assumeIsolated { [weak self] in self?.endGrace() }
        }
        guard task != .invalid else { return }
        backgroundTask = task

        graceTask = Task { [weak self] in
            await self?.windDown()
            self?.endGrace()
        }
        // Ask for a catch-up window, HERE rather than at launch or in
        // `endGrace`: this is the moment the answer is known - the app
        // is going away with work outstanding, which is the only state
        // the window is worth having. NOT in `endGrace`, which the
        // FOREGROUND path also runs, where a request for a background
        // window is exactly backwards.
        scheduleCatchUp()
        #endif
    }

    /// Pause gracefully and wait for the bytes to stop arriving.
    ///
    /// `mode=pause` with no arguments is the engine's GRACEFUL
    /// wind-down - "finish in-flight, keep the queue for resume" - and
    /// not the immediate abort (`value2=now`). That is the entire reason
    /// this is a wind-down rather than a stop, and the distinction is
    /// one API parameter wide, so it is worth saying at the call.
    private func windDown() async {
        // SAID WHILE THERE IS STILL A PROCESS TO SAY IT WITH. Once
        // suspended, nothing of ours runs, so the lock screen keeps
        // whatever it was last told - and "held, open the app to carry
        // on" is a far better thing to find frozen there than a progress
        // bar that stopped for no stated reason.
        //
        // FIRST, ahead of the pause it describes, which is a change from
        // the order this shipped in (C28). The message is already true -
        // the app is going away, so the queue is stopping whether or not
        // the pause lands - and saying it here buys two things. It is
        // published at the earliest moment the budget allows, which is
        // the whole game when the budget is short. And it spends one
        // ActivityKit update instead of two: `AppState.hold` refreshes
        // on its way through, and that poll used to push a bare
        // "Paused." a moment before this overwrote it, out of an
        // allowance the system meters and this is the one call that
        // needs.
        LiveProgress.hold(reason: "Held while nzbfast is in the background. Open it to carry on.")
        await state.hold(.background)
        await waitForQuiet()
        // AWAITED, and this is the point of the grace rather than a
        // tidy-up at the end of it: `hold` above only QUEUED the update,
        // and the assertion this runs under is ended by the caller the
        // instant this returns. Under a short budget the process is then
        // suspended with the one update the activity exists for still in
        // the air. Bounded, so a wedged ActivityKit call cannot spend
        // the assertion down to expiry - iOS kills an app for that.
        await LiveProgress.flush(timeout: publishBudget())
        LiveProgress.qaJournal("grace wind-down-returned")
    }

    /// Wait for the bytes to stop arriving, or for the grace budget to
    /// run out.
    private func waitForQuiet() async {
        // QUIET IS THE SIGNAL, and the frozen mode=playback contract has
        // no better one: a graceful pause reports `paused` true
        // immediately while the articles already in the air keep
        // landing, so the flag says the request arrived and says nothing
        // about whether it has taken effect. `speed_bps` at rest does.
        //
        // TWO CONSECUTIVE quiet polls, because one is satisfiable by the
        // gap between two articles on a slow line - which is precisely
        // the case where being wrong is dearest.
        var quiet = 0
        let deadline = Date().addingTimeInterval(graceBudget())
        while !Task.isCancelled, Date() < deadline {
            await state.refresh()
            let speed = state.snapshot?.speedBps ?? 0
            quiet = speed < Self.quietBytesPerSecond ? quiet + 1 : 0
            if quiet >= 2 { return }
            try? await Task.sleep(nanoseconds: 400_000_000)
        }
    }

    /// Below this the line is idle rather than slow.
    ///
    /// 64 kB/s is under any real article rate and far above the zero a
    /// float never quite reaches. It is a threshold and not an equality
    /// test on purpose: `speed_bps` is a smoothed figure, so waiting for
    /// it to be exactly 0 would spend the whole grace budget every time
    /// and then be cut off by the expiration handler anyway.
    private static let quietBytesPerSecond: Double = 64_000

    /// How long to spend winding down.
    ///
    /// ASKED, not assumed. The thirty seconds everyone quotes is a
    /// figure Apple has changed before and varies by device state, and
    /// `backgroundTimeRemaining` is the only thing that knows. Three
    /// seconds are left on the clock so the last poll and the
    /// `endBackgroundTask` land inside the assertion rather than racing
    /// the expiration handler.
    private func graceBudget() -> TimeInterval {
        #if DEBUG
        // THE QA SEAM (packaging/ios/README.md). The case this file's
        // `flush` exists for is a SHORT remaining budget, and a
        // Simulator never has one - it answers
        // `.greatestFiniteMagnitude` in the background and does not
        // suspend the app at all, so the wind-down's own quiet loop
        // outlasts every ActivityKit call and the ordering comes out
        // right whether or not anybody waited for it. Measured 27 Aug
        // 2026: the loop ran ~10 s past the Held push. Forcing the
        // budget is the only way to put the two in the order a phone
        // with a second left on the clock puts them.
        let forced = UserDefaults.standard.double(forKey: "qaGraceSeconds")
        if forced > 0 { return forced }
        #endif
        #if canImport(UIKit)
        let left = UIApplication.shared.backgroundTimeRemaining
        // `.greatestFiniteMagnitude` is what it answers in the
        // foreground and in some transitions; it is not a budget.
        if left.isFinite, left < 600 { return max(1, left - 3) }
        #endif
        return 25
    }

    /// How long to give the Held update to actually reach ActivityKit.
    ///
    /// ASKED like `graceBudget`, and for the same reason: what is left
    /// on the clock here is whatever the wind-down did not spend. One
    /// second is held back so `endBackgroundTask` still lands inside the
    /// assertion rather than racing the expiration handler, and the
    /// three-second ceiling is because this is a lock-screen update and
    /// not work - past that it is wedged, and waiting longer only makes
    /// the suspension later.
    private func publishBudget() -> TimeInterval {
        #if canImport(UIKit)
        let left = UIApplication.shared.backgroundTimeRemaining
        if left.isFinite, left < 600 { return max(0.25, min(3, left - 1)) }
        #endif
        return 3
    }

    #if canImport(UIKit)
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    #endif

    /// End the assertion, once. Called from the wind-down's normal exit
    /// AND from the expiration handler, which can arrive at any point in
    /// between, so it has to be idempotent - ending an already-ended
    /// identifier is a crash.
    private func endGrace() {
        #if canImport(UIKit)
        guard backgroundTask != .invalid else { return }
        // The QA seam's other end: everything after this line runs with
        // no assertion, which on a device means it may not run at all.
        LiveProgress.qaJournal("grace assertion-ended")
        let task = backgroundTask
        backgroundTask = .invalid
        graceTask?.cancel()
        graceTask = nil
        UIApplication.shared.endBackgroundTask(task)
        #endif
    }

    /// Playback stopped holding the process. If the app is already in
    /// the background this is the moment `didEnterBackground` was
    /// waiting for - the media ended, failed, or was paused from the
    /// lock screen, no application notification fires, and suspension
    /// follows with no further callback - so the same wind-down runs
    /// NOW (C24). Called by `AppState.setPlaybackHoldsProcess` on the
    /// true-to-false edge.
    func playbackHoldDropped() {
        #if canImport(UIKit)
        guard UIApplication.shared.applicationState == .background else { return }
        enterBackground()
        #endif
    }

    /// Playback started holding the process again while the app is still
    /// backgrounded. The INVERSE of `playbackHoldDropped`, and it was
    /// missing until 28 Aug 2026 - which is the whole bug: the lock
    /// screen has a PLAY button as well as a pause one. Pausing there
    /// ran the wind-down (correctly - the process was about to be
    /// suspended), and then nothing undid it, because
    /// `enterForeground` was the only release of the `.background` hold
    /// and the app is still backgrounded. So the download stayed paused
    /// for the whole rest of the playback session and came back only
    /// when the user next opened the app. Called by
    /// `AppState.setPlaybackHoldsProcess` on the false-to-true edge.
    ///
    /// DO NOT ADD A SNAPSHOT-PAUSED GUARD HERE. It looks like it is
    /// missing beside `enterBackground`'s one, and it is not:
    /// `AppState.hold` refuses to take the `.background` hold over a
    /// queue that already reads paused, and `AppState.release`
    /// early-returns when that hold is not in `pauseHolds` - so a pause
    /// the USER asked for was never owned, and the release this ends up
    /// performing is a no-op by construction. A check here would be a
    /// second, weaker
    /// copy of that one ownership rule, written where it cannot see the
    /// set it is guessing about, and the two would drift.
    func playbackHoldTaken() {
        #if canImport(UIKit)
        guard UIApplication.shared.applicationState == .background else { return }
        standDownFromGrace()
        #endif
    }

    /// The process is staying alive after all, so the wind-down is off
    /// and the queue comes back.
    ///
    /// SHARED by `enterForeground` and `playbackHoldTaken` rather than
    /// written twice: the two edges reach the same state for different
    /// reasons, and the second one is the one that was missing for a
    /// while. One copy is the point here, not tidiness - a second hand
    /// copy is how the next edge gets three of these four steps.
    ///
    /// CANCELLING THE GRACE TASK IS SAFE with a `pauseAll` in flight,
    /// and that is load-bearing rather than incidental. The
    /// cancellation lands on the AWAIT inside `AppState.hold`, which
    /// COMPENSATES through `undoOurPause` instead of disowning the
    /// pause, so a pause that did reach the engine is resumed rather
    /// than stranded; and `AppState.release` bumps `holdGeneration`
    /// BEFORE its own early return, so a hold still in flight cannot
    /// insert itself into the set this release just emptied (C22).
    private func standDownFromGrace() {
        graceTask?.cancel()
        graceTask = nil
        endGrace()
        LiveProgress.unhold()
        Task { await state.release(.background) }
    }

    private func enterForeground() {
        standDownFromGrace()
    }

    // MARK: - opportunistic completion

    /// Register the catch-up handler. Must run before the app finishes
    /// launching, which is what `NzbfastMobileApp.init` is for.
    static func registerTasks(state: @escaping @MainActor () -> AppState?) {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: processingTaskID,
                                        using: nil) { task in
            Task { @MainActor in
                await runCatchUp(task: task, state: state())
            }
        }
    }

    /// Resume the queue for as long as iOS is willing to let this run.
    ///
    /// NOT PROMISED ANYWHERE IN THE UI, which is a product rule and not
    /// modesty: the system decides whether this ever fires, and a
    /// feature the user has been told about that silently does not
    /// happen is worse than one they discover as a queue further along
    /// than they left it. The Settings copy states the foreground limit
    /// plainly and says nothing about this.
    private static func runCatchUp(task: BGTask, state: AppState?) async {
        // Ask for the next one FIRST. A window that returns without
        // requesting its successor is the last one there will ever be,
        // and the failure is invisible - the feature simply stops.
        scheduleCatchUpStatic()
        LiveProgress.qaJournal("catchup ENTER state=\(state != nil) source=\(String(describing: state?.source))")
        guard let state, state.source == .device else {
            task.setTaskCompleted(success: false)
            return
        }
        // A COLD delivery: iOS relaunched this process just to hand the
        // task over, so no view task has started the engine yet.
        // Without this the release below is a no-op against a nil
        // client and the window is spent polling nothing (C23).
        if state.api() == nil {
            LiveProgress.qaJournal("catchup COLD bootstrap (api was nil)")
            try? await state.useDevice()
        }
        guard state.api() != nil else {
            task.setTaskCompleted(success: false)
            return
        }
        // The window's connectivity requirement means SOME network, not
        // Wi-Fi. A cellular window against the user's hold setting is
        // refused outright, keeping the pause in place (C26).
        let cell = await currentLinkIsCellular()
        LiveProgress.qaJournal("catchup link cellular=\(cell) pauseOnCellular=\(AppSettings.pauseOnCellular)")
        if AppSettings.pauseOnCellular, cell {
            task.setTaskCompleted(success: false)
            return
        }
        let gate = CompletionGate()
        let done = Task { @MainActor in
            await state.release(.background)
            // The queue is running again, so the lock screen must stop
            // saying it is held - and the latch that keeps ordinary
            // polls from overwriting the background message has to come
            // off with it, or the activity stays frozen on "open it to
            // carry on" for the whole window while the download runs.
            // Same edge as `enterForeground`, reached without one.
            LiveProgress.unhold()
            // Run until the system takes the window back. There is no
            // useful "finished" here - the queue is as far along as it
            // got - so this ends by cancellation, which is what
            // `expirationHandler` below delivers.
            while !Task.isCancelled {
                await state.refresh()
                if state.snapshot?.queueIdle == true { return }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
        task.expirationHandler = {
            // Apple's contract: on expiration, stop quickly and
            // complete. The cancel IS the cleanup - starting the
            // wind-down's network I/O here is exactly the late work
            // the contract warns gets the app killed - and the
            // completion is unsuccessful because the window was
            // revoked (C25).
            LiveProgress.qaJournal("catchup EXPIRED")
            done.cancel()
            if gate.claim() { task.setTaskCompleted(success: false) }
        }
        await done.value
        // Claiming the gate here is what keeps the two halves apart:
        // if expiration got there first, nothing more may run.
        guard gate.claim() else { return }
        // Back to a wound-down state before the window closes, for the
        // same reason the grace exists - and under its OWN bounded
        // budget, so the completion beats the deadline rather than
        // sitting behind a request timeout (C25).
        let wind = Task { @MainActor in await state.hold(.background) }
        let budget = Task {
            try? await Task.sleep(nanoseconds: 20_000_000_000)
            wind.cancel()
        }
        await wind.value
        budget.cancel()
        LiveProgress.qaJournal("catchup COMPLETED success")
        task.setTaskCompleted(success: true)
    }

    /// One-shot read of the path this window actually arrived on.
    /// `NWPathMonitor` reports the current path on start, so the first
    /// callback is the answer; the gate is there because the handler
    /// can fire again before the cancel lands, and a continuation must
    /// resume exactly once.
    private static func currentLinkIsCellular() async -> Bool {
        let gate = CompletionGate()
        return await withCheckedContinuation { cont in
            let monitor = NWPathMonitor()
            monitor.pathUpdateHandler = { path in
                guard gate.claim() else { return }
                monitor.cancel()
                cont.resume(returning: path.status == .satisfied
                            && path.usesInterfaceType(.cellular))
            }
            monitor.start(queue: DispatchQueue(label: "nzbfast.catchup.link"))
        }
    }

    private func scheduleCatchUp() { Self.scheduleCatchUpStatic() }

    private static func scheduleCatchUpStatic() {
        let request = BGProcessingTaskRequest(identifier: processingTaskID)
        // A download needs the network, and a phone on cellular in a
        // pocket is exactly who this must not spend money for. iOS reads
        // `requiresExternalPower` as "charging", which together with its
        // own Wi-Fi preference is the overnight-on-the-nightstand case
        // the plan describes.
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = true
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        // Throws when the app is not entitled, when one is already
        // queued, or in a Simulator without the scheduler - none of
        // which is worth surfacing to a user, because none of them is
        // something a user can act on and the feature was never
        // promised.
        try? BGTaskScheduler.shared.submit(request)
    }
}

/// A once-latch that is safe off the main actor: a `BGTask`'s
/// expiration handler and `NWPathMonitor`'s callback both arrive on
/// system queues, and `setTaskCompleted` - like a continuation - must
/// run exactly once whichever side gets there first (C25). A lock and
/// not a flag, because the two sides race for real.
private final class CompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var taken = false
    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if taken { return false }
        taken = true
        return true
    }
}
