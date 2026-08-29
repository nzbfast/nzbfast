// Test-preview player. VLCKit carries playback because most real
// posts are Matroska and AVPlayer refuses the container.
//
// SINCE TODO 281 IO2b IT ALSO KEEPS THE DOWNLOAD RUNNING. Playback and
// the engine are one process, so an audio session held by real audio is
// what lets iOS keep this app scheduled with the screen off - and the
// engine's sockets stay open with it. `PlaybackSession` owns that side
// (the category, the lock-screen transport, route changes and
// interruptions); this file's job is to tell it the truth about whether
// anything is actually playing, which is the whole of what makes the
// entitlement legitimate.
import SwiftUI
import UIKit
import AVFoundation
#if canImport(VLCKit)
import VLCKit
#elseif canImport(MobileVLCKit)
import MobileVLCKit
#endif

struct PlayerTarget: Identifiable {
    let jobId: String
    let url: URL
    var id: String { jobId }
}

struct PlayerView: View {
    let target: PlayerTarget
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @StateObject private var vm = PlayerModel()
    @State private var controlsVisible = true
    /// First telemetry sample seen by this player: the counters are
    /// cumulative since daemon start, so the overlay reports movement
    /// since the player opened.
    @State private var telemetryBaseline: StreamTelemetry?

    /// What the lock screen calls this. The job's own name, and
    /// nothing fetched from anywhere - see `refreshNowPlaying`.
    private var title: String {
        let job = (state.snapshot.map { $0.queue + $0.history } ?? [])
            .first { $0.nzoId == target.jobId }
        return job?.playback?.file ?? job?.displayName ?? "Playing"
    }

    /// Seek discipline: a live job whose tail has not landed answers
    /// playback.seekable=false - scrubbing into unfetched bytes stalls
    /// the player against a hole (or reads zeros mid-recovery).
    /// Finished jobs and ready tails seek freely; no snapshot yet
    /// (remote daemon between polls) errs on the permissive side for
    /// finished files, which is what the row launched from.
    private var seekAllowed: Bool {
        let job = (state.snapshot.map { $0.queue + $0.history } ?? [])
            .first { $0.nzoId == target.jobId }
        guard let p = job?.playback else { return true }
        return p.source != "live" || p.seekable == true
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color.black.ignoresSafeArea()
            VLCVideoSurface(model: vm)
                .ignoresSafeArea()
                .onTapGesture {
                    withAnimation { controlsVisible.toggle() }
                }
            if controlsVisible {
                controls
            }
            healthOverlay
                .padding(.leading, 12)
                .padding(.top, 64)
        }
        .statusBarHidden(true)
        .onAppear {
            // Through the arbiter. Writing `isIdleTimerDisabled`
            // directly is what this used to do, and the unconditional
            // `false` on the way out turned the keep-awake setting off
            // over a working queue - see ScreenAwake.
            ScreenAwake.hold(.playing)
            // Baseline BEFORE playback starts, not on the first counter
            // change: capturing in a change handler stores the
            // already-incremented snapshot, so the first wait subtracts
            // from itself and reads zero - and a change that only moves
            // zeroFilledBytes never captures at all, hiding every gap
            // byte. No snapshot yet (remote daemon between polls)
            // baselines at zero rather than hiding whatever arrives.
            telemetryBaseline = state.snapshot?.stream
                ?? StreamTelemetry(readers: nil, blockedReads: 0,
                                   zeroFilledBytes: 0, runwayMb: nil,
                                   runwayWaitMs: nil)
            vm.bind(state: state, title: title, seekable: seekAllowed)
            vm.load(url: target.url)
        }
        .onDisappear {
            ScreenAwake.release(.playing)
            vm.stop()
        }
        .onChange(of: seekAllowed) { allowed in
            // A live job's tail lands WHILE the player is open, so
            // "seekable" is not a fact settled at launch: the lock
            // screen's scrubber has to become enabled at the same moment
            // the on-screen slider does. Watched directly - blockedReads
            // is a global telemetry counter that can sit still across
            // the flip, which left the remote controls disabled while
            // the on-screen ones enabled.
            vm.setSeekable(allowed)
        }
    }

    /// Buffer/health overlay: the mode=playback poll keeps running
    /// behind the player, so `stream` telemetry (blocked_reads,
    /// zero_filled_bytes) and the job's own coverage are both live.
    @ViewBuilder private var healthOverlay: some View {
        if let tele = state.snapshot?.stream {
            let base = telemetryBaseline ?? tele
            let waits = max(0, (tele.blockedReads ?? 0) - (base.blockedReads ?? 0))
            let zeroed = max(0, (tele.zeroFilledBytes ?? 0) - (base.zeroFilledBytes ?? 0))
            let job = (state.snapshot.map { $0.queue + $0.history } ?? [])
                .first { $0.nzoId == target.jobId }
            VStack(alignment: .leading, spacing: 2) {
                Text(zeroed > 0
                     ? "Buffer waits \(waits)  ·  gaps \(Self.formatBytes(zeroed))"
                     : "Buffer waits \(waits)")
                    .foregroundStyle(zeroed > 0 ? Color(red: 1, green: 0.76, blue: 0.29) : .white)
                if let job, job.playback?.source == "live" {
                    Text(String(format: "Fetched %.0f%%  ·  %@", job.pct,
                                job.playback?.seekable == true ? "seek ready" : "seek not ready yet"))
                        .foregroundStyle(.white)
                }
            }
            .font(.caption2.monospacedDigit())
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Color.black.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
        }
    }

    private static func formatBytes(_ b: Int64) -> String {
        if b >= 1_000_000 { return String(format: "%.1f MB", Double(b) / 1e6) }
        if b >= 1_000 { return String(format: "%.0f KB", Double(b) / 1e3) }
        return "\(b) B"
    }

    private var controls: some View {
        VStack {
            HStack {
                Button {
                    vm.stop()
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .font(.title3.weight(.semibold))
                        .padding(10)
                        .background(.ultraThinMaterial, in: Circle())
                }
                Spacer()
                Text("Test preview")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(.ultraThinMaterial, in: Capsule())
            }
            .padding()
            Spacer()
            VStack(spacing: 10) {
                HStack {
                    Text(vm.positionText)
                    Slider(value: $vm.sliderPosition, in: 0...1) { editing in
                        vm.scrub(editing: editing)
                    }
                    .disabled(!seekAllowed)
                    .opacity(seekAllowed ? 1 : 0.4)
                    Text(vm.durationText)
                }
                .font(.caption.monospacedDigit())
                HStack(spacing: 40) {
                    Button { vm.skip(by: -15) } label: {
                        Image(systemName: "gobackward.15").font(.title2)
                    }
                    .disabled(!seekAllowed)
                    .opacity(seekAllowed ? 1 : 0.4)
                    Button { vm.togglePlay() } label: {
                        Image(systemName: vm.isPlaying ? "pause.fill" : "play.fill")
                            .font(.system(size: 40))
                    }
                    Button { vm.skip(by: 15) } label: {
                        Image(systemName: "goforward.15").font(.title2)
                    }
                    .disabled(!seekAllowed)
                    .opacity(seekAllowed ? 1 : 0.4)
                }
                if let note = vm.statusNote {
                    Text(note)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
            .padding()
        }
        .foregroundStyle(.white)
        .transition(.opacity)
    }
}

@MainActor
final class PlayerModel: NSObject, ObservableObject {
    @Published var isPlaying = false
    @Published var sliderPosition: Double = 0
    @Published var positionText = "0:00"
    @Published var durationText = "--:--"
    @Published var statusNote: String? = "Opening"

    let player = VLCMediaPlayer()
    private var scrubbing = false
    private weak var state: AppState?
    private var title = "Playing"
    private var seekable = true
    /// The view VLC draws into, kept so it can be handed BACK after a
    /// spell in the background - see `detachForBackground`.
    private weak var surface: UIView?
    private var lifecycleObservers: [NSObjectProtocol] = []

    /// Tell the model who to report playback state to, and what the
    /// lock screen should call this.
    func bind(state: AppState, title: String, seekable: Bool) {
        self.state = state
        self.title = title
        self.seekable = seekable
    }

    func setSeekable(_ on: Bool) {
        guard on != seekable else { return }
        seekable = on
        PlaybackSession.shared.refreshNowPlaying(title: title)
    }

    func load(url: URL) {
        player.delegate = self
        player.media = VLCMedia(url: url)
        observeLifecycle()
        player.play()
        isPlaying = true
        // The session and the process hold are NOT taken here:
        // ownership follows VLC's confirmed `.playing` transition in
        // `syncFromPlayer`, so a load that never reaches playing never
        // claims background audio over silence (C20).
    }

    func stop() {
        player.stop()
        isPlaying = false
        // EVERY exit from playback releases the session, which is the
        // rule the audio entitlement rests on: the session's lifetime is
        // the audio's lifetime, never the download's.
        PlaybackSession.shared.release()
        for o in lifecycleObservers { NotificationCenter.default.removeObserver(o) }
        lifecycleObservers = []
    }

    func togglePlay() {
        if player.isPlaying {
            player.pause()
            isPlaying = false
        } else {
            player.play()
            isPlaying = true
        }
        PlaybackSession.shared.refreshNowPlaying(title: title)
    }

    func skip(by seconds: Int) {
        if seconds >= 0 {
            player.jumpForward(Int32(seconds))
        } else {
            player.jumpBackward(Int32(-seconds))
        }
        PlaybackSession.shared.refreshNowPlaying(title: title)
    }

    func scrub(editing: Bool) {
        scrubbing = editing
        if !editing {
            player.position = Float(sliderPosition)
        }
    }

    /// Keep a note of the view VLC is drawing into.
    func attach(surface: UIView) {
        self.surface = surface
        player.drawable = surface
    }

    /// GIVE THE DRAWABLE BACK WHEN THE APP GOES AWAY, and take it again
    /// on the way in.
    ///
    /// This is the one thing background audio needs from the VIDEO side
    /// and it is not optional: iOS terminates an app that touches the
    /// GPU while backgrounded, so a video layer still being rendered
    /// into is not a glitch, it is the app being killed - and killed
    /// silently, since the report arrives as a crash log rather than as
    /// anything the app can catch. With no drawable, VLC keeps decoding
    /// audio and stops rendering frames, which is exactly the behaviour
    /// wanted: the sound continues, the process stays scheduled, and the
    /// engine keeps downloading.
    ///
    /// PiP would be the case where the video legitimately DOES keep
    /// rendering in the background, and MobileVLCKit 3.6 cannot do it -
    /// `drawable` takes a view or a layer and there is no
    /// sample-buffer output to feed an `AVPictureInPictureController`.
    /// See TODO 281 IO2b for the measurement and the route.
    private func observeLifecycle() {
        guard lifecycleObservers.isEmpty else { return }
        let nc = NotificationCenter.default
        lifecycleObservers.append(nc.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.player.drawable = nil }
            })
        lifecycleObservers.append(nc.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, let surface = self.surface else { return }
                    self.player.drawable = surface
                }
            })
    }

    fileprivate func syncFromPlayer() {
        isPlaying = player.isPlaying
        if !scrubbing {
            sliderPosition = Double(player.position)
        }
        positionText = Self.format(ms: player.time.intValue)
        if let len = player.media?.length.intValue, len > 0 {
            durationText = Self.format(ms: len)
        }
        switch player.state {
        case .buffering:
            statusNote = "Buffering"
        case .error:
            statusNote = "Playback failed. The file may not be ready yet."
            // A player that has failed is not playing, so the process
            // hold has to go with it. Left standing, the app would be
            // claiming an audio session over silence - the one thing
            // this feature must never do.
            PlaybackSession.shared.release()
        case .ended:
            statusNote = "Finished"
            isPlaying = false
            PlaybackSession.shared.release()
        case .playing:
            statusNote = nil
            // Ownership follows the CONFIRMED state, not the play
            // intent: this is what reacquires the session and the
            // process hold after a pause, after an interruption the
            // system did not auto-resume, and after a replay once
            // `.ended` released everything (C20).
            if let state {
                PlaybackSession.shared.syncPlaying(true, transport: self, state: state)
            }
        case .paused, .stopped:
            statusNote = nil
            // A real pause: the hold and the session go with it, the
            // transport and the lock-screen commands stay bound. This
            // is the arm that lets `Lifecycle` wind the queue down
            // over a paused preview instead of trusting a stale hold.
            if let state {
                PlaybackSession.shared.syncPlaying(false, transport: self, state: state)
            }
        default:
            statusNote = nil
        }
        PlaybackSession.shared.refreshNowPlaying(title: title)
    }

    private static func format(ms: Int32) -> String {
        let total = Int(ms) / 1000
        let h = total / 3600, m = (total % 3600) / 60, s = total % 60
        if h > 0 { return String(format: "%d:%02d:%02d", h, m, s) }
        return String(format: "%d:%02d", m, s)
    }
}

extension PlayerModel: VLCMediaPlayerDelegate {
    nonisolated func mediaPlayerStateChanged(_ aNotification: Notification) {
        Task { @MainActor in self.syncFromPlayer() }
    }

    nonisolated func mediaPlayerTimeChanged(_ aNotification: Notification) {
        Task { @MainActor in self.syncFromPlayer() }
    }
}

/// The transport the lock screen and Control Centre drive.
///
/// A protocol rather than the model being reached for directly, so
/// `PlaybackSession` names no playback library: the choice between
/// VLCKit and AVFoundation is this file's business and does not belong
/// on the lock screen's side of the wall.
extension PlayerModel: PlaybackTransport {
    func transportPlay() {
        guard !player.isPlaying else { return }
        player.play()
        isPlaying = true
    }

    func transportPause() {
        guard player.isPlaying else { return }
        player.pause()
        isPlaying = false
    }

    func transportSkip(by seconds: Int) { skip(by: seconds) }

    func transportSeek(to seconds: Double) {
        guard seekable, seconds >= 0 else { return }
        let total = transportDurationSeconds
        guard total > 0 else { return }
        player.position = Float(min(seconds / total, 1))
    }

    var transportIsPlaying: Bool { player.isPlaying }

    var transportPositionSeconds: Double { Double(player.time.intValue) / 1000 }

    var transportDurationSeconds: Double {
        Double(player.media?.length.intValue ?? 0) / 1000
    }

    var transportSeekable: Bool { seekable }
}

struct VLCVideoSurface: UIViewRepresentable {
    let model: PlayerModel

    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        view.backgroundColor = .black
        // Through `attach` rather than straight at `player.drawable`:
        // the model has to keep a reference so it can give the drawable
        // back after a spell in the background - see
        // `observeLifecycle`.
        model.attach(surface: view)
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {}
}
