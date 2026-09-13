import SwiftUI
import ParfastCore

/// The progress sheet, plan 5.3, for every job kind. It runs INSIDE the queue
/// even when the job was started directly, so the Queue tab always shows the
/// truth and closing this sheet never cancels anything.
struct ProgressSheet: View {
    @EnvironmentObject var app: AppModel
    var job: JobSnapshot

    @State private var notify = true
    @State private var confirmingCancel = false

    /// The last two minutes of the job's read rate (chart (b) of the 12 Sep 2026
    /// prettiness review section 4).
    ///
    /// A `@StateObject` because this sheet is a STRUCT rebuilt on every snapshot
    /// and the ring buffer is the one thing here that has to survive that. It is
    /// fed from `onChange(of:)` below rather than from `body`: a push inside a
    /// render pass would mutate state during layout and, worse, would push again
    /// on every unrelated redraw - a window resize would fill the chart with
    /// phantom samples the job never reported.
    @StateObject private var rates = RateHistory()

    var body: some View {
        VStack(alignment: .leading, spacing: T.spacingL) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(job.title ?? app.displayKind(job.kind))
                        .font(.system(size: 15, weight: .semibold))
                    Text(app.displayKind(job.kind))
                        .font(.system(size: 11))
                        .foregroundStyle(T.textSecondary)
                }
                Spacer()
                StatusPill(text: Fmt.progressPercent(job.progress),
                           tone: tone, busy: job.state == .running)
            }

            SmoothBar(value: job.progress, height: 8)

            HStack(alignment: .top, spacing: T.spacingXxl) {
                Figure(label: S.progressElapsed, value: Fmt.duration(ms: job.elapsed_ms))
                Figure(label: S.progressRemaining,
                       value: job.eta_ms.map { Fmt.duration(ms: $0) } ?? "-")
                VStack(alignment: .leading, spacing: 2) {
                    Figure(label: S.progressRate,
                           value: job.rate_bytes_per_s.map { Fmt.rate($0) } ?? "-")
                    // "Is it slowing down" is also a SENTENCE, and that is what
                    // earns the shape its place twice. The trend says nothing for
                    // the first fifteen seconds - a comparison over three samples
                    // flaps while the engine's own estimate settles, and a figure
                    // that flickers reads as the app being confused.
                    Text(rates.trendText)
                        .font(.system(size: 11))
                        .monospacedDigit()
                        .foregroundStyle(T.textTertiary)
                        .lineLimit(1)
                }
                Spacer(minLength: T.spacingM)
                if rates.hasShape {
                    SparklineView(history: rates)
                        .frame(width: 170, height: 34)
                }
            }

            Text(job.phase_text)
                .font(.system(size: 12))
                .foregroundStyle(T.textSecondary)
                .lineLimit(1)

            LogPane(lines: job.log_tail, height: 170)

            if let error = job.error, job.state == .failed {
                Label(error.message, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(T.statusBad)
            }

            HStack(spacing: T.spacingM) {
                if app.capabilities.low_priority {
                    Toggle(S.progressBackground, isOn: Binding(
                        get: { job.low_priority },
                        set: { app.setLowPriority(job.id, $0) }))
                        .help(S.progressBackgroundTip)
                }
                Toggle(S.progressNotify, isOn: $notify)
                Spacer()
                if job.state.isFinished {
                    Button(S.commonClose) { app.progressJob = nil }
                        .keyboardShortcut(.defaultAction)
                } else {
                    if app.capabilities.pause {
                        // Shown DISABLED with the reason rather than enabled
                        // and inert, in the one case `canPause` still says no:
                        // an engine without `pause_in_fold` stops a create only
                        // before it starts, and a button that does nothing on
                        // press is worse than one that explains.
                        Button(job.state == .paused ? S.progressResume : S.progressPause) {
                            job.state == .paused ? app.resume(job.id) : app.pause(job.id)
                        }
                        .disabled(!canPause)
                        .help(canPause ? "" : S.progressPauseNotAfterStart)
                    }
                    Button(S.commonCancel) { confirmingCancel = true }
                        .keyboardShortcut(.cancelAction)
                }
            }
        }
        .padding(T.spacingXl)
        .frame(width: 560)
        .onAppear { notify = app.settings.general.notifications }
        // THE HISTORY IS FED HERE AND ONLY HERE, once per snapshot the sheet is
        // handed, and every rule about WHICH snapshots count is in
        // `RateHistory.apply(_:)` rather than in this modifier - a finished job's
        // repeat snapshots, and a second job opened in the same sheet. Fed from
        // `onChange` and never from `body`: a push during a render pass would
        // mutate state mid-layout and would fire again on every unrelated redraw,
        // so a window resize would fill the chart with samples the job never
        // reported.
        //
        // `onAppear` as well as `onChange`, because the sheet opens on a snapshot
        // that has already arrived and `onChange` does not fire for it.
        .onAppear { rates.apply(job) }
        .onChange(of: job) { _, latest in rates.apply(latest) }
        .onChange(of: notify) { _, newValue in
            var settings = app.settings
            settings.general.notifications = newValue
            app.apply(settings: settings)
        }
        .confirmationDialog(S.progressCancelConfirm, isPresented: $confirmingCancel) {
            Button(S.progressCancelConfirmStop, role: .destructive) {
                app.cancel(job.id)
                app.progressJob = nil
            }
            Button(S.progressCancelConfirmKeep, role: .cancel) {}
        } message: {
            // API.md: `cancel_in_fold` says whether the engine polls the
            // cancel under its fold, solve and write loops or only BETWEEN
            // members. It has been true since 12 Sep 2026, for a create as
            // well as a repair, so the extra sentence is the fallback rather
            // than the usual case - but a dialog that implies a cancel is
            // instant is a promise an older engine cannot keep, and the
            // capability says which one is underneath rather than this
            // guessing.
            Text(app.capabilities.cancel_in_fold
                 ? S.progressCancelConfirmBody
                 : S.progressCancelConfirmBody + " " + S.progressCancelNotInstant)
        }
    }

    /// `pause_in_fold`, not the job kind - which is the whole change here.
    /// This hard-coded `job.kind == .create` to "queued only", so the mac app
    /// disabled Pause on a running create whatever the engine reported, while
    /// Windows `ProgressViewModel.CanPause` already gated the same rule on the
    /// same capability. API.md's create row has said since 12 Sep 2026 that a
    /// create parks inside the engine, so that hard-code was an under-claim.
    ///
    /// The create branch STAYS, because the capability is what separates the
    /// two cases: a create the engine drives with no control still stops only
    /// before it starts, and hard-coding today's answer would be the same
    /// under-claim pointing the other way.
    ///
    /// WHAT THE CAPABILITY PROMISES IS NOT WHAT THE SHIPPED ENGINE DOES, as of
    /// 12 Sep 2026, and this comment is the only place a mac reader will see
    /// it. Measured on an M3 Ultra against the real staticlib, three times: a
    /// create paused within half a second of starting goes to Paused, parks
    /// some of its threads, and then RUNS TO COMPLETION and writes the whole
    /// set.
    ///
    /// WHERE, named off the timing trace rather than off which arm is
    /// configured as default - the first version of this comment blamed
    /// `stripe_first.rs` on exactly that bad reasoning and was wrong, because
    /// that arm refuses a single-batch or fused create and never ran.
    /// `NZBFAST_REPAIR_TIMING=1` on a 27 GiB `-b2000 -r20` create reports one
    /// batch and `create ntt rows 0+396 (... mapped ...)`: the mapped
    /// SINGLE-WINDOW transform in `par2gen/ntt.rs`, 10.73 s of a 12.85 s run.
    /// That attempt holds no `control.gate()` at all, and its stripe workers
    /// poll cancel only, on purpose - "Cancel only, never a park", ntt.rs:299.
    /// One window means there is no between-windows park point either. So 83%
    /// of a create has nowhere for a Pause to land, and API.md's stated
    /// exception - a pause during a transform takes effect at the END of it -
    /// is honoured to the letter while swallowing the whole operation.
    ///
    /// Cancel is sound: a SIGINT five seconds into a twelve-second CLI create
    /// left nothing on disk. The gate below is still right, because the fix is
    /// the engine's or the capability's and not a second per-app hard-code.
    /// Owned as claim `par2gen-create-pause-and-bar`; measurements in
    /// the maintainer notes.
    private var canPause: Bool {
        guard app.capabilities.pause else { return false }
        if job.kind == .create && !app.capabilities.pause_in_fold {
            return job.state == .queued
        }
        return true
    }

    private var tone: StatusPill.Tone {
        switch job.state {
        case .done: return .good
        case .failed: return .bad
        case .cancelled, .interrupted: return .warn
        case .paused, .queued: return .neutral
        case .running: return .working
        }
    }
}

/// The transcript, in the CLI's own words (5.2). Monospace, copyable, and it
/// follows the tail unless the user has scrolled away from it.
struct LogPane: View {
    var lines: [String]
    var height: CGFloat

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    if lines.isEmpty {
                        Text(S.logEmpty)
                            .font(.system(size: 11))
                            .foregroundStyle(T.textTertiary)
                    }
                    ForEach(Array(lines.enumerated()), id: \.offset) { index, line in
                        Text(line.isEmpty ? " " : line)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(T.textSecondary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id(index)
                    }
                }
                .padding(T.spacingM)
            }
            .frame(height: height)
            .background(
                RoundedRectangle(cornerRadius: T.radiusControl, style: .continuous)
                    .fill(T.surfaceWell)
            )
            .onChange(of: lines.count) { _, count in
                withAnimation(.easeOut(duration: 0.15)) {
                    proxy.scrollTo(max(0, count - 1), anchor: .bottom)
                }
            }
        }
    }
}

/// The log drawer, available in every mode (5.2).
struct LogDrawer: View {
    @EnvironmentObject var app: AppModel
    var lines: [String]
    var command: String?

    var body: some View {
        VStack(alignment: .leading, spacing: T.spacingM) {
            HStack {
                Text(S.logTitle)
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                if let command, app.settings.advanced.show_command {
                    Button(S.commonCopyCommand) { app.copyToPasteboard(command) }
                        .controlSize(.small)
                }
                Button(S.logCopy) { app.copyToPasteboard(lines.joined(separator: "\n")) }
                    .controlSize(.small)
                Button {
                    app.logOpen = false
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(T.textTertiary)
                }
                .buttonStyle(.plain)
            }
            LogPane(lines: lines, height: 200)
        }
        .padding(T.spacingL)
        .background(.regularMaterial)
        .overlay(alignment: .top) { Divider().overlay(T.surfaceGridLine) }
    }
}
