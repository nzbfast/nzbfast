// The app's half of the Live Activity (TODO 281 IO2): starting it,
// keeping it current, and - the part that matters most - saying
// something honest on the way out.
//
// WHAT A LIVE ACTIVITY IS FOR HERE. iOS suspends this app within seconds
// of the user switching away, and the download stops with it. That is a
// real limitation and the plan's answer is to state it plainly rather
// than hide it (the Settings copy does). An activity on the lock screen
// is the other half of that: it makes the resume story VISIBLE instead
// of mysterious, so a user who comes back to a queue that has not moved
// can see it was held rather than concluding the app is broken.
//
// SO IT FREEZES, DELIBERATELY, AND SAYS SO. Nothing updates it while the
// app is suspended - there is no timer that could - and an activity that
// somehow kept animating would be lying about a download that had
// stopped. `hold(reason:)` is called from the finish-in-flight grace
// while the app still has a moment to run, so the state the user finds
// frozen on their lock screen is one that says it is waiting for them.
// That is the difference between a bar that stopped and a bar that
// stopped FOR A REASON.
//
// DISPLAY ONLY. There is no button on it and no deep link that starts a
// download: an activity is a report, and every action lives in the app.
import Foundation
import ActivityKit

@MainActor
enum LiveProgress {

    /// The activity in flight, if any. At most one: the queue is one
    /// thing, and several activities for one queue would be several
    /// answers to one question.
    private static var current: Any?

    /// The lead job the running activity was started for. `leadJobName`
    /// is immutable attributes, so a changed front job is a NEW activity
    /// (the attributes say so) - which needs the identity kept here,
    /// because the state pushed every poll never carries it.
    private static var currentLead: String?

    /// Serializes every ActivityKit call this file makes. They are all
    /// async, and two unstructured Tasks can complete out of order - a
    /// 2-second poll update landing AFTER the final Held update would
    /// overwrite the one state the activity exists to show.
    private static var pipeline: Task<Void, Never>?

    /// How many calls queued on `pipeline` have not finished. `flush`
    /// waits on THIS rather than on `pipeline?.value`, and the reason is
    /// worth writing down because the obvious spelling does not work: a
    /// `Task<Void, Never>` cannot fail, so `await tail.value` is not a
    /// cancellation point, and racing it against a sleep in a task group
    /// hangs - the group implicitly awaits its remaining children at
    /// scope exit, and `cancelAll()` does not make the losing child stop
    /// waiting on the tail. A counter can be read at any moment and
    /// leaves nothing suspended behind, which is what a bounded wait on
    /// the way to suspension needs.
    private static var pending = 0

    /// The background message, once `hold` has published it. While it is
    /// set, ordinary poll updates do NOT push - see `update`.
    private static var backgroundHoldReason: String?

    private static var reconciled = false

    /// Reflect a poll. Starts the activity when work appears, updates it
    /// while work continues, ends it when the queue drains.
    static func update(from snapshot: PlaybackSnapshot?, source: JobSource) {
        guard #available(iOS 16.2, *) else { return }
        reconcile()
        // ON-DEVICE ONLY. In remote mode the downloading happens on a
        // machine elsewhere that this phone's lock screen has no
        // business reporting as if it were happening here - and the one
        // thing the activity exists to explain, the suspend, does not
        // happen to it.
        guard source == .device, let snap = snapshot, !snap.queue.isEmpty else {
            end()
            return
        }
        // HELD IS THE LAST WORD, and this line is what makes that true
        // rather than likely. The wind-down pauses the queue, so every
        // poll from that moment on builds a state whose `holdReason` is
        // the generic "Paused." - which `worthPushing` correctly calls a
        // change and pushes STRAIGHT OVER the background message the
        // grace exists to leave on the lock screen. It is not a race:
        // `windDown` waits for two consecutive quiet polls, so at least
        // two refreshes run after `hold`, and the first of them
        // overwrites. The one path that must still get through is the
        // queue draining, which the guard above already took.
        guard backgroundHoldReason == nil else { return }
        let lead = snap.queue.first?.displayName ?? "Downloading"
        let state = contentState(snap, held: snap.paused == true,
                                 reason: snap.paused == true ? "Paused." : nil)
        if current == nil {
            start(lead: lead, state: state)
        } else if let running = currentLead, running != lead {
            // The front job changed. `leadJobName` cannot be updated in
            // place, so without this every presentation keeps naming the
            // finished job for the rest of the activity.
            end()
            start(lead: lead, state: state)
        } else if worthPushing(state) {
            push(state)
        }
    }

    /// The last word before the app goes away.
    ///
    /// Called from the finish-in-flight grace, which is the only moment
    /// this can be said: once suspended there is no code of ours left to
    /// run. Without it the bar simply stops mid-progress, which reads as
    /// a broken app rather than as a held queue.
    static func hold(reason: String) {
        guard #available(iOS 16.2, *), current != nil else { return }
        guard var state = lastState else { return }
        state.held = true
        state.speedBps = 0
        state.holdReason = reason
        // Latched BEFORE the push, so the refresh that `AppState.hold`
        // runs on its way through cannot slip a poll state in between.
        backgroundHoldReason = reason
        push(state)
    }

    /// Wait for everything queued so far to actually reach ActivityKit,
    /// giving up after `timeout`.
    ///
    /// WHY A WAIT AT ALL. `push` is fire-and-forget by construction -
    /// ActivityKit's calls are async and this file is not - so `hold`
    /// returns with the one update that matters still in the air. The
    /// caller is the finish-in-flight grace, which ends its background
    /// assertion the moment it returns, and iOS suspends the process
    /// with it: an update that has not been delivered by then is one the
    /// lock screen never gets, leaving the stale progress bar the whole
    /// activity exists to replace.
    ///
    /// BOUNDED, because the alternative failure is worse than the one it
    /// fixes. An ActivityKit call that never answers would otherwise
    /// hold the assertion open to expiry, and iOS kills an app that lets
    /// one run out. Cancellation exits too, so the expiration handler
    /// never waits on this.
    static func flush(timeout: TimeInterval) async {
        let deadline = Date().addingTimeInterval(max(0, timeout))
        while pending > 0, !Task.isCancelled, Date() < deadline {
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    /// Released again on the way back in.
    static func unhold() {
        // Cleared unconditionally, ahead of the guards: a latch left set
        // because there was no activity to update would silence every
        // later poll for the life of the process.
        backgroundHoldReason = nil
        guard #available(iOS 16.2, *), current != nil, var state = lastState else { return }
        state.held = false
        state.holdReason = nil
        push(state)
    }

    static func end() {
        guard #available(iOS 16.2, *) else { return }
        reconcile()
        let activity = current as? Activity<DownloadActivityAttributes>
        current = nil
        currentLead = nil
        lastState = nil
        backgroundHoldReason = nil
        if let activity {
            enqueue {
                // `.immediate`: the queue is empty, so a bar lingering on
                // the lock screen is stale the moment this returns.
                await activity.end(nil, dismissalPolicy: .immediate)
                qaJournal("ended")
            }
        } else if !Activity<DownloadActivityAttributes>.activities.isEmpty {
            // Belt for a survivor `reconcile` did not adopt: activities
            // outlive the process, and one nothing local tracks would
            // otherwise sit stale on the lock screen forever.
            enqueue {
                for stray in Activity<DownloadActivityAttributes>.activities {
                    await stray.end(nil, dismissalPolicy: .immediate)
                }
            }
        }
    }

    /// Is this state different enough from the last one to be worth
    /// sending?
    ///
    /// The poll runs every 2 seconds and a lock-screen bar does not
    /// move visibly in 2 seconds, so pushing every one of them is a
    /// system update per poll for a picture nobody can tell apart. That
    /// matters beyond tidiness: ActivityKit budgets an app's updates,
    /// and an app that spends its allowance on invisible changes has
    /// none left for the one that counts - the HELD state on the way
    /// out, which is the whole reason a frozen activity is acceptable.
    ///
    /// Half a percent is roughly one pixel of a lock-screen bar. The
    /// HELD flag and the job count bypass the threshold entirely,
    /// because those change what the activity SAYS rather than how far
    /// along it is.
    @available(iOS 16.2, *)
    private static func worthPushing(_ next: DownloadActivityAttributes.ContentState) -> Bool {
        guard let last = lastState else { return true }
        if last.held != next.held || last.jobCount != next.jobCount { return true }
        if last.holdReason != next.holdReason { return true }
        return abs(last.fraction - next.fraction) >= 0.005
    }

    // MARK: - internals

    /// One-shot reconciliation with ActivityKit. Activities SURVIVE
    /// process termination while `current` does not, so after a jetsam
    /// kill or relaunch a live activity can be on the lock screen with
    /// nothing here tracking it: a nonempty queue would then start a
    /// duplicate, and an empty one would leave the survivor stale
    /// forever. Adopt one and end the extras.
    @available(iOS 16.2, *)
    private static func reconcile() {
        guard !reconciled else { return }
        reconciled = true
        var live = Activity<DownloadActivityAttributes>.activities
        qaJournal("reconcile survivors=\(live.count)")
        guard !live.isEmpty else { return }
        if current == nil {
            let adopted = live.removeFirst()
            current = adopted
            currentLead = adopted.attributes.leadJobName
            lastState = adopted.content.state
            qaJournal("reconcile adopted lead=\(adopted.attributes.leadJobName)")
        }
        for extra in live {
            qaJournal("reconcile ending-extra")
            enqueue { await extra.end(nil, dismissalPolicy: .immediate) }
        }
    }

    /// Chain an ActivityKit call behind every one already queued. The
    /// chain is built on the main actor, so ordering is the enqueue
    /// order - see `pipeline`.
    private static func enqueue(_ op: @escaping () async -> Void) {
        pending += 1
        let prev = pipeline
        pipeline = Task {
            await prev?.value
            await op()
            pending -= 1
        }
    }

    @available(iOS 16.2, *)
    private static var lastState: DownloadActivityAttributes.ContentState? {
        get { lastStateStorage as? DownloadActivityAttributes.ContentState }
        set { lastStateStorage = newValue }
    }

    /// Type-erased because the property above is `@available`-gated and
    /// a stored property cannot be. Reading it back through the computed
    /// accessor is what keeps the gate honest.
    private static var lastStateStorage: Any?

    @available(iOS 16.2, *)
    private static func contentState(_ snap: PlaybackSnapshot, held: Bool,
                                     reason: String?) -> DownloadActivityAttributes.ContentState {
        // BYTES, not an average of percentages, which is the same rule
        // the Home headline follows and for the same reason: a 40 GB job
        // at 10% beside a 200 MB one at 90% is not halfway done.
        let total = snap.queue.reduce(0.0) { $0 + ($1.mb ?? 0) }
        let left = snap.queue.reduce(0.0) { $0 + ($1.mbleft ?? 0) }
        let fraction = total > 0 ? max(0, min(1, (total - left) / total)) : 0
        return .init(fraction: fraction,
                     speedBps: held ? 0 : (snap.speedBps ?? 0),
                     timeLeft: snap.queue.first?.timeleft,
                     jobCount: snap.queue.count,
                     held: held,
                     holdReason: reason)
    }

    @available(iOS 16.2, *)
    private static func start(lead: String, state: DownloadActivityAttributes.ContentState) {
        // REFUSED IS NOT AN ERROR. The user can turn Live Activities off
        // for this app, and Focus modes and the Simulator can each
        // decline one. Nothing about the download depends on it, so a
        // refusal is silent rather than surfaced - a toast saying a lock
        // screen decoration could not be drawn is noise on top of a
        // choice the user made.
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            qaJournal("start-refused activities-disabled")
            return
        }
        do {
            let activity = try Activity.request(
                attributes: DownloadActivityAttributes(leadJobName: lead),
                content: .init(state: state, staleDate: staleDate()),
                pushType: nil)
            current = activity
            currentLead = lead
            lastState = state
            qaJournal("started lead=\(lead)")
        } catch {
            current = nil
            currentLead = nil
            qaJournal("start-failed \(error)")
        }
    }

    @available(iOS 16.2, *)
    private static func push(_ state: DownloadActivityAttributes.ContentState) {
        guard let activity = current as? Activity<DownloadActivityAttributes> else {
            qaJournal("push-skipped no-activity")
            return
        }
        lastState = state
        enqueue {
            await qaStall()
            await activity.update(.init(state: state, staleDate: staleDate()))
            // AFTER the call, so the line means DELIVERED and not
            // queued - which is the whole of what `flush` is for.
            qaJournal("delivered held=\(state.held ? 1 : 0) reason=\(state.holdReason ?? "-")")
        }
    }

    // MARK: - the QA seam (DEBUG only)

    /// A journal of what actually reached ActivityKit, written into the
    /// app's Documents container for the headless rig in
    /// `packaging/ios/README.md`.
    ///
    /// WHY IT HAS TO EXIST. C28's claim is about WHICH update is last
    /// before the process is suspended, and nothing outside this process
    /// can read an activity's content back: `Activity` is not shared
    /// across processes, and the Simulator has no lock screen a
    /// screenshot could catch. So the only witness available is the
    /// publisher saying what it published.
    static func qaJournal(_ line: String) {
        #if DEBUG
        guard let dir = FileManager.default.urls(for: .documentDirectory,
                                                 in: .userDomainMask).first else { return }
        let url = dir.appendingPathComponent("liveactivity-qa.log")
        // Timestamped, because the claim these lines settle is an
        // ORDER and the intervals are what say whether an ordering that
        // came out right did so on purpose.
        let stamp = String(format: "%.3f ", Date().timeIntervalSince1970)
        guard let data = (stamp + line + "\n").data(using: .utf8) else { return }
        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        } else {
            try? data.write(to: url)
        }
        #endif
    }

    /// Stall every ActivityKit call by `-qaActivityDelayMs`.
    ///
    /// THE POINT OF THE SEAM, and the reason a passing run without it
    /// proves nothing: the defect C28 names is a RACE, and the
    /// wind-down's own poll loop normally wins it by accident - the
    /// update lands during the second quiet poll whether anybody waited
    /// for it or not. Stalling delivery past that loop makes the failure
    /// deterministic, so the journal's last line answers the question
    /// instead of the scheduler answering it.
    private static func qaStall() async {
        #if DEBUG
        let ms = UserDefaults.standard.integer(forKey: "qaActivityDelayMs")
        if ms > 0 { try? await Task.sleep(nanoseconds: UInt64(ms) * 1_000_000) }
        #endif
    }

    /// When the system should start showing this as out of date.
    ///
    /// Four minutes, which is a statement about the SUSPEND rather than
    /// about the poll: the app updates every two seconds while it is
    /// running, so the only way this date is ever reached is the app
    /// having been suspended - exactly the case where the user should be
    /// told the figure is old. It is a belt for the one path `hold`
    /// cannot cover, a suspend with no `didEnterBackground` at all
    /// (a crash, a jetsam kill), where nothing gets to say why.
    @available(iOS 16.2, *)
    private static func staleDate() -> Date {
        Date().addingTimeInterval(4 * 60)
    }
}
