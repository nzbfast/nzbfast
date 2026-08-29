// The audio session, the lock-screen transport, and the one rule that
// makes the audio entitlement legitimate (TODO 281 IO2b).
//
// WHY THIS IS THE BACKGROUNDING STORY. Download and playback are ONE
// process here - the engine is linked in and serves 127.0.0.1 from a
// thread of this app - so an app that iOS keeps scheduled for playing
// audio is an app whose NNTP sockets stay open too. That is not a
// side effect being exploited: it is the shape of the product, and it
// is the only case on this platform where backgrounded downloading
// runs at full speed rather than not at all (the plan's addendum B.1).
// `Lifecycle` reads `AppState.playbackHoldsProcess` and does NOT wind
// the queue down while this is true.
//
// AND THE RULE THAT COMES WITH IT, which is not negotiable and is
// written here because this is the file where breaking it would be
// easy: THE SESSION IS ONLY EVER ACTIVE WHILE REAL MEDIA IS REALLY
// PLAYING. A silent session held open to keep a download alive is the
// single move that gets an app removed from the store, the plan bans it
// twice, and it would be one line to write. `hold` is called from the
// player's PLAYING transition and `release` from every path out of
// playback - stopped, ended, errored, dismissed - so the session's
// lifetime is the audio's lifetime and not the download's. There is no
// entry point here that a caller with no audio could use.
import Foundation
import AVFoundation
import MediaPlayer

/// What the transport controls act on. The player model implements it,
/// which keeps this file free of any particular playback library - the
/// VLCKit-versus-AVFoundation question is settled next door and does not
/// reach the lock screen.
@MainActor
protocol PlaybackTransport: AnyObject {
    func transportPlay()
    func transportPause()
    func transportSkip(by seconds: Int)
    func transportSeek(to seconds: Double)
    var transportIsPlaying: Bool { get }
    var transportPositionSeconds: Double { get }
    var transportDurationSeconds: Double { get }
    /// False while the job's tail has not landed: scrubbing into
    /// unfetched bytes stalls against a hole. The lock screen must
    /// refuse it for the same reason the on-screen slider does.
    var transportSeekable: Bool { get }
}

@MainActor
final class PlaybackSession {

    static let shared = PlaybackSession()

    private weak var transport: PlaybackTransport?
    private weak var state: AppState?
    private var active = false
    private var observers: [NSObjectProtocol] = []
    /// Set when an interruption arrived while playing, so the resume on
    /// the far side only restarts something that was actually running.
    private var wasPlayingBeforeInterruption = false

    private init() {}

    // MARK: - session

    /// Make this app's audio the audio, and tell the rest of the app the
    /// process is now held up by something real.
    ///
    /// `.playback` with `.moviePlayback` is the category pair that means
    /// "this is the point of the app": it plays with the ring switch on
    /// silent, it does not duck, and together with the `audio`
    /// `UIBackgroundModes` entry it is what keeps the process scheduled
    /// with the screen off.
    func hold(transport: PlaybackTransport, state: AppState) {
        self.transport = transport
        self.state = state
        if !active {
            let session = AVAudioSession.sharedInstance()
            do {
                try session.setCategory(.playback, mode: .moviePlayback)
                try session.setActive(true)
                active = true
            } catch {
                // A session that will not activate is a phone that will
                // not keep this process alive in the background. It is
                // not a reason to refuse playback - the video plays
                // perfectly well in the foreground - so this is reported
                // by NOT claiming the process hold rather than by
                // stopping anything.
                active = false
                LiveProgress.qaJournal("audio session-activate FAILED \(error)")
            }
            observe()
        }
        LiveProgress.qaJournal("audio hold active=\(active)")
        state.setPlaybackHoldsProcess(active)
        refreshNowPlaying()
        enableCommands(true)
    }

    /// Give the session back. Every exit from playback comes through
    /// here, including the ones that are not a user pressing stop -
    /// see the comment at the top of this file for why that matters
    /// more than it looks.
    func release() {
        enableCommands(false)
        MPNowPlayingInfoCenter.default().nowPlayingInfo = nil
        state?.setPlaybackHoldsProcess(false)
        for o in observers { NotificationCenter.default.removeObserver(o) }
        observers = []
        if active {
            // NOT an error worth surfacing: `.notifyOthersOnDeactivation`
            // is a courtesy to whatever was playing before, and a phone
            // that refuses it simply keeps the session a moment longer.
            try? AVAudioSession.sharedInstance()
                .setActive(false, options: .notifyOthersOnDeactivation)
            active = false
        }
        transport = nil
        state = nil
        wasPlayingBeforeInterruption = false
    }

    /// True while the audio session really is active with this app's
    /// audio in it. The ONLY thing `Lifecycle` is allowed to read as
    /// "the process will keep running".
    var isHolding: Bool { active }

    /// Follow the player's CONFIRMED state, which is what makes the
    /// entitlement honest in both directions (C20). Playing takes or
    /// retakes the session and the process hold - after a plain pause,
    /// after an interruption the system did not auto-resume, and after
    /// `.ended` released everything. A real pause drops both: a silent
    /// session held open is the one move the entitlement bans, and a
    /// hold left standing is what let `Lifecycle` skip the wind-down
    /// over silence. The transport and the lock-screen commands STAY
    /// bound across a pause - a paused player is still on the lock
    /// screen and its play button must work.
    func syncPlaying(_ playing: Bool, transport: PlaybackTransport, state: AppState) {
        LiveProgress.qaJournal("audio syncPlaying(\(playing)) active=\(active)")
        if playing {
            if !active || self.transport !== transport {
                hold(transport: transport, state: state)
            } else {
                state.setPlaybackHoldsProcess(true)
            }
        } else {
            state.setPlaybackHoldsProcess(false)
            if active {
                try? AVAudioSession.sharedInstance()
                    .setActive(false, options: .notifyOthersOnDeactivation)
                active = false
            }
        }
    }

    // MARK: - the phone happening to the playback

    private func observe() {
        // `hold` runs on every reactivation now (a pause deactivates
        // the session), and these observers outlive a pause on purpose
        // - so re-observing would stack duplicates.
        guard observers.isEmpty else { return }
        let nc = NotificationCenter.default
        let session = AVAudioSession.sharedInstance()

        // INTERRUPTIONS: a call, a timer, Siri. `.began` has already
        // stopped our audio by the time this arrives, so the player is
        // brought into line rather than being asked to stop.
        observers.append(nc.addObserver(forName: AVAudioSession.interruptionNotification,
                                        object: session, queue: .main) { [weak self] note in
            MainActor.assumeIsolated { self?.handleInterruption(note) }
        })

        // ROUTE CHANGES: headphones pulled out, a Bluetooth speaker
        // walking away. `.oldDeviceUnavailable` is the one that MUST
        // pause - it is the case where carrying on means the phone
        // suddenly playing a film out loud in a quiet room, which is the
        // behaviour every media app is judged on.
        observers.append(nc.addObserver(forName: AVAudioSession.routeChangeNotification,
                                        object: session, queue: .main) { [weak self] note in
            MainActor.assumeIsolated { self?.handleRouteChange(note) }
        })

        // A MEDIA SERVICES RESET wipes the session out from under us.
        // Rare, and the only correct response is to build it again -
        // without this the app keeps "playing" into nothing, and the
        // process hold it thinks it has is gone.
        observers.append(nc.addObserver(forName: AVAudioSession.mediaServicesWereResetNotification,
                                        object: session, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let transport = self.transport, let state = self.state else { return }
                self.active = false
                self.hold(transport: transport, state: state)
            }
        })
    }

    private func handleInterruption(_ note: Notification) {
        guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
        switch type {
        case .began:
            wasPlayingBeforeInterruption = transport?.transportIsPlaying ?? false
            transport?.transportPause()
            // The system has taken the session: the ACTIVATION went
            // with the process hold, so a later manual play finds
            // `active` false and reacquires both through `hold` (C20).
            active = false
            state?.setPlaybackHoldsProcess(false)
        case .ended:
            let opts = (note.userInfo?[AVAudioSessionInterruptionOptionKey] as? UInt)
                .map(AVAudioSession.InterruptionOptions.init(rawValue:)) ?? []
            // ONLY on the system's say-so AND only if we were playing.
            // Resuming a paused video because a timer went off is a
            // film starting in someone's pocket.
            guard opts.contains(.shouldResume), wasPlayingBeforeInterruption else { return }
            do {
                try AVAudioSession.sharedInstance().setActive(true)
                active = true
            } catch {
                active = false
            }
            state?.setPlaybackHoldsProcess(active)
            transport?.transportPlay()
        @unknown default:
            break
        }
        refreshNowPlaying()
    }

    private func handleRouteChange(_ note: Notification) {
        guard let raw = note.userInfo?[AVAudioSessionRouteChangeReasonKey] as? UInt,
              let reason = AVAudioSession.RouteChangeReason(rawValue: raw) else { return }
        if reason == .oldDeviceUnavailable {
            transport?.transportPause()
        }
        refreshNowPlaying()
    }

    // MARK: - lock screen and Control Centre

    private func enableCommands(_ on: Bool) {
        let c = MPRemoteCommandCenter.shared()
        c.playCommand.isEnabled = on
        c.pauseCommand.isEnabled = on
        c.togglePlayPauseCommand.isEnabled = on
        c.skipForwardCommand.isEnabled = on
        c.skipBackwardCommand.isEnabled = on
        c.skipForwardCommand.preferredIntervals = [15]
        c.skipBackwardCommand.preferredIntervals = [15]
        // The scrubber follows the same discipline as the on-screen
        // slider: a live job whose tail has not landed answers
        // seekable=false, and a seek into unfetched bytes stalls the
        // player against a hole. The lock screen is not a place where
        // that is more acceptable.
        c.changePlaybackPositionCommand.isEnabled = on && (transport?.transportSeekable ?? false)
        guard on else {
            c.playCommand.removeTarget(nil)
            c.pauseCommand.removeTarget(nil)
            c.togglePlayPauseCommand.removeTarget(nil)
            c.skipForwardCommand.removeTarget(nil)
            c.skipBackwardCommand.removeTarget(nil)
            c.changePlaybackPositionCommand.removeTarget(nil)
            return
        }
        // EVERY HANDLER BELOW GOES THROUGH `onMainActor` AND NOT THROUGH
        // `MainActor.assumeIsolated` DIRECTLY, and the difference is a
        // crash. `assumeIsolated` is a PRECONDITION: told a lie, it traps
        // and takes the app down, and nothing in MediaPlayer's
        // documentation promises which thread an `MPRemoteCommand` target
        // is called on - unlike the notification observers in `observe()`
        // above, which are registered with `queue: .main` and so are
        // genuinely on main by construction, and unlike the background
        // task expiration handler in `Lifecycle`, which Apple documents
        // as main-thread and which must stay synchronous anyway. This was
        // an undocumented bet rather than an observed failure (examined
        // 28 Aug 2026); the cheap way to stop betting is to ASK, so a
        // command delivered off main costs one main-queue turn instead of
        // hard-crashing on a lock-screen tap. Do not "simplify" these
        // back to a bare `assumeIsolated`.
        c.playCommand.removeTarget(nil)
        c.playCommand.addTarget { [weak self] _ in
            onMainActor { self?.transport?.transportPlay() }
            return .success
        }
        c.pauseCommand.removeTarget(nil)
        c.pauseCommand.addTarget { [weak self] _ in
            onMainActor { self?.transport?.transportPause() }
            return .success
        }
        c.togglePlayPauseCommand.removeTarget(nil)
        c.togglePlayPauseCommand.addTarget { [weak self] _ in
            onMainActor {
                guard let t = self?.transport else { return }
                if t.transportIsPlaying { t.transportPause() } else { t.transportPlay() }
            }
            return .success
        }
        c.skipForwardCommand.removeTarget(nil)
        c.skipForwardCommand.addTarget { [weak self] event in
            // The EVENT is read here rather than inside the hop: it is a
            // value the system hands over for the duration of the call,
            // so a deferred read would be a read of something that may
            // no longer be ours.
            let by = (event as? MPSkipIntervalCommandEvent)?.interval ?? 15
            onMainActor { self?.transport?.transportSkip(by: Int(by)) }
            return .success
        }
        c.skipBackwardCommand.removeTarget(nil)
        c.skipBackwardCommand.addTarget { [weak self] event in
            let by = (event as? MPSkipIntervalCommandEvent)?.interval ?? 15
            onMainActor { self?.transport?.transportSkip(by: -Int(by)) }
            return .success
        }
        c.changePlaybackPositionCommand.removeTarget(nil)
        c.changePlaybackPositionCommand.addTarget { [weak self] event in
            guard let e = event as? MPChangePlaybackPositionCommandEvent else { return .commandFailed }
            let to = e.positionTime
            onMainActor { self?.transport?.transportSeek(to: to) }
            return .success
        }
    }

    /// The title on the lock screen, and the position the scrubber
    /// draws.
    ///
    /// NO ARTWORK AND NO METADATA BEYOND THE FILE'S OWN NAME, which is a
    /// posture decision rather than an omission: this app has no
    /// indexer, no search and no content in it, and reaching out to
    /// fetch a poster for whatever the user is watching would be the
    /// first thing in it that did (the plan's three-point posture).
    func refreshNowPlaying(title: String? = nil) {
        guard let t = transport else { return }
        var info = MPNowPlayingInfoCenter.default().nowPlayingInfo ?? [:]
        if let title { info[MPMediaItemPropertyTitle] = title }
        info[MPNowPlayingInfoPropertyPlaybackRate] = t.transportIsPlaying ? 1.0 : 0.0
        info[MPNowPlayingInfoPropertyElapsedPlaybackTime] = t.transportPositionSeconds
        let duration = t.transportDurationSeconds
        if duration > 0 { info[MPMediaItemPropertyPlaybackDuration] = duration }
        info[MPNowPlayingInfoPropertyIsLiveStream] = false
        MPNowPlayingInfoCenter.default().nowPlayingInfo = info
        MPRemoteCommandCenter.shared().changePlaybackPositionCommand.isEnabled = t.transportSeekable
    }
}

/// Run `body` on the main actor without BETTING that the caller is
/// already there.
///
/// The lock-screen transport handlers in `enableCommands` above are the
/// one place in this app that needs this. `MainActor.assumeIsolated` is
/// the right tool wherever the thread is a documented contract - the
/// `queue: .main` notification observers in `observe()`, the background
/// task expiration handler in `Lifecycle` - because it costs nothing and
/// states the assumption. An `MPRemoteCommand` target has no such
/// documentation, and `assumeIsolated` on a lie is not a warning, it is
/// a trap: the app dies on a lock-screen tap, in the background, where
/// nobody is looking at a debugger.
///
/// SYNCHRONOUS ON THE FAST PATH on purpose. In the overwhelmingly likely
/// case the system already called us on main, and hopping there anyway
/// would put a queue turn between the tap and the pause for no reason -
/// visible as a lock screen whose button lags the audio. The hop is the
/// fallback, not the rule.
///
/// NOT a general-purpose utility, and it should not grow into one: the
/// nine notification observers in this file and next door are registered
/// with a main queue and are genuinely on main, so routing them through
/// here would replace a stated fact with a runtime check.
private func onMainActor(_ body: @escaping @Sendable @MainActor () -> Void) {
    if Thread.isMainThread {
        MainActor.assumeIsolated(body)
    } else {
        DispatchQueue.main.async { MainActor.assumeIsolated(body) }
    }
}
