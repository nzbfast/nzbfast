// TODO 281 IO0: Home is the DOWNLOADER, not the player.
//
// The iOS twin of AN1 (packaging/android/.../ui/HomeScreen.kt), against
// the same CONTRACT.md rows, because the plan's risk 5 is the two shells
// drifting apart. What changed here, and why each is a change rather
// than a preference:
//
//   - The headline is what the install is DOING - how much is left, how
//     fast, how long, how much room. This shell was built in the
//     playback-first era and its list led with a Play button, which is a
//     demo affordance sitting where the product is. Play is still on
//     every row that can serve one; it is just not the point.
//   - The aggregate is weighted by BYTES and not by averaging the
//     per-job percentages: a 40 GB job at 10% beside a 200 MB job at
//     90% is not halfway done.
//   - Pause, resume and cancel are BUTTONS. They were swipe-only, which
//     is a gesture with no discoverable name, and for delete an
//     irreversible one a pocket can perform. The swipe survives for
//     pause and resume, where the worst a stray one costs is a tap.
//   - Cancel asks first, and asks the question a phone actually has:
//     whether the bytes go too.
//   - History moved to its own tab (HistoryView), which is the shape
//     the plan's addendum A names: Queue, Add, History, one Settings
//     sheet, and the player.
import SwiftUI

struct HomeView: View {
    @EnvironmentObject var state: AppState
    @State private var actionError: String?
    @State private var confirming: DeleteRequest?

    var body: some View {
        List {
            if let since = state.offlineSince {
                Section {
                    Label {
                        Text("Not answering since \(since.formatted(date: .omitted, time: .shortened)). Retrying.")
                    } icon: {
                        Image(systemName: "wifi.exclamationmark")
                    }
                    .foregroundStyle(.orange)
                    .font(.footnote)
                }
            }
            if let note = state.holdNote {
                Section {
                    Label(note, systemImage: "pause.circle")
                        .foregroundStyle(.orange)
                        .font(.footnote)
                }
            }
            statusSection
            queueSection
        }
        .navigationTitle("Downloads")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if let snap = state.snapshot {
                    Button {
                        run {
                            try await (snap.paused == true
                                       ? state.api()?.resumeAll()
                                       : state.api()?.pauseAll())
                        }
                    } label: {
                        Image(systemName: snap.paused == true ? "play.fill" : "pause.fill")
                    }
                    .accessibilityLabel(snap.paused == true ? "Resume everything" : "Pause everything")
                }
            }
        }
        .refreshable { await state.refresh() }
        .alert("That did not work", isPresented: .init(
            get: { actionError != nil },
            set: { if !$0 { actionError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(actionError ?? "")
        }
        .confirmationDialogForDelete($confirming) { req, withFiles in
            run {
                try await state.api()?.deleteJob(req.nzoId, deleteFiles: withFiles)
            }
        }
    }

    // MARK: sections

    /// What the whole install is doing, above the list.
    @ViewBuilder private var statusSection: some View {
        if let snap = state.snapshot {
            Section {
                StatusCard(snapshot: snap,
                           samples: state.speedHistory,
                           freeGB: state.freeSpaceGB)
            }
        } else {
            Section { ProgressView() }
        }
    }

    @ViewBuilder private var queueSection: some View {
        if let jobs = state.snapshot?.queue, !jobs.isEmpty {
            Section("Active") {
                ForEach(jobs) { job in
                    QueueRow(job: job,
                             onPlay: { play(job) },
                             onPause: { run { try await state.api()?.pauseJob(job.id) } },
                             onResume: { run { try await state.api()?.resumeJob(job.id) } },
                             onCancel: { confirming = DeleteRequest(nzoId: job.id, name: job.displayName) })
                    // Pause and resume keep the gesture; cancel does not.
                    .swipeActions(edge: .leading, allowsFullSwipe: false) {
                        if job.isPaused {
                            Button {
                                run { try await state.api()?.resumeJob(job.id) }
                            } label: { Label("Resume", systemImage: "play") }
                            .tint(.green)
                        } else {
                            Button {
                                run { try await state.api()?.pauseJob(job.id) }
                            } label: { Label("Pause", systemImage: "pause") }
                            .tint(.orange)
                        }
                    }
                }
            }
        } else if state.snapshot != nil {
            Section {
                Text(state.snapshot?.history.isEmpty == false
                     ? "Nothing downloading."
                     : "Nothing here yet. Add an NZB from the Add tab.")
                    .foregroundStyle(.secondary)
                    .font(.footnote)
            }
        }
    }

    // MARK: helpers

    private func run(_ op: @escaping () async throws -> Void) {
        Task {
            do {
                try await op()
                await state.refresh()
            } catch {
                actionError = (error as? LocalizedError)?.errorDescription
                    ?? "The engine refused that."
            }
        }
    }

    private func play(_ job: PlaybackJob) {
        Task {
            do {
                try await state.requestPlay(job: job)
            } catch {
                actionError = (error as? LocalizedError)?.errorDescription
                    ?? "Could not open that file."
            }
        }
    }
}

/// Which row is asking to be removed, and from which list.
///
/// Held by the SCREEN rather than by the row so the dialog survives the
/// list recomposing under it when the next poll lands, two seconds away.
struct DeleteRequest: Identifiable, Equatable {
    let nzoId: String
    let name: String
    var fromHistory = false

    var id: String { (fromHistory ? "h-" : "q-") + nzoId }
}

extension View {
    /// The one destructive confirmation in the app.
    ///
    /// The checkbox default differs by list and that is the whole reason
    /// for asking: a queue row's bytes are part-downloaded articles that
    /// are worth nothing once the job is gone, so they default to going
    /// with it, while a history row's bytes are the finished download
    /// and default to staying. Getting that backwards in either
    /// direction is a silent disk leak on a phone, or a deleted film.
    func confirmationDialogForDelete(
        _ request: Binding<DeleteRequest?>,
        onConfirm: @escaping (DeleteRequest, Bool) -> Void
    ) -> some View {
        modifier(DeleteConfirmation(request: request, onConfirm: onConfirm))
    }
}

private struct DeleteConfirmation: ViewModifier {
    @Binding var request: DeleteRequest?
    let onConfirm: (DeleteRequest, Bool) -> Void

    func body(content: Content) -> some View {
        content.sheet(item: $request) { req in
            DeleteSheet(request: req) { withFiles in
                request = nil
                onConfirm(req, withFiles)
            } onCancel: {
                request = nil
            }
            .presentationDetents([.medium])
        }
    }
}

private struct DeleteSheet: View {
    let request: DeleteRequest
    let onConfirm: (Bool) -> Void
    let onCancel: () -> Void
    @State private var withFiles: Bool

    init(request: DeleteRequest,
         onConfirm: @escaping (Bool) -> Void,
         onCancel: @escaping () -> Void) {
        self.request = request
        self.onConfirm = onConfirm
        self.onCancel = onCancel
        _withFiles = State(initialValue: !request.fromHistory)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(request.name)
                        .font(.subheadline)
                        .lineLimit(3)
                }
                Section {
                    Toggle(request.fromHistory
                           ? "Delete the downloaded files too"
                           : "Delete the part-downloaded files too",
                           isOn: $withFiles)
                }
                Section {
                    Button(request.fromHistory ? "Remove" : "Cancel this download",
                           role: .destructive) {
                        onConfirm(withFiles)
                    }
                }
            }
            .navigationTitle(request.fromHistory ? "Remove from history?" : "Cancel this download?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Keep") { onCancel() }
                }
            }
        }
    }
}

/// The aggregate, above the list: what the notification would say if
/// this platform had one to show.
struct StatusCard: View {
    let snapshot: PlaybackSnapshot
    let samples: [Double]
    let freeGB: Double

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(headline)
                    .font(.title2.weight(.semibold))
                Spacer()
                Text(String(format: "%.1f GB free", freeGB))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            let active = snapshot.queue
            if !active.isEmpty {
                ProgressView(value: min(max(bytePct / 100, 0), 1))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            // Two samples minimum: with fewer the canvas cannot draw a
            // line and the card is an empty stub for the first polls.
            if !active.isEmpty, samples.count >= 2 {
                ThroughputChart(samples: samples,
                                linkPeakMBps: (snapshot.linkPeak ?? 0) / 1e6,
                                linkPeakSrc: snapshot.linkPeakSrc ?? "")
            }
        }
        .padding(.vertical, 4)
    }

    private var headline: String {
        if snapshot.paused == true { return "Paused" }
        if snapshot.queue.isEmpty { return "Idle" }
        return String(format: "%.1f MB/s", (snapshot.speedBps ?? 0) / 1e6)
    }

    /// Byte-weighted, not the mean of the per-job percentages - see the
    /// file header.
    private var bytePct: Double {
        let total = snapshot.queue.reduce(0.0) { $0 + ($1.mb ?? 0) }
        let left = snapshot.queue.reduce(0.0) { $0 + ($1.mbleft ?? 0) }
        guard total > 0 else { return 0 }
        return (total - left) / total * 100
    }

    private var detail: String {
        let active = snapshot.queue
        var parts: [String] = ["\(active.count) \(active.count == 1 ? "job" : "jobs")"]
        parts.append(String(format: "%.0f%%", bytePct))
        let left = active.reduce(0.0) { $0 + ($1.mbleft ?? 0) }
        if left > 0 { parts.append(String(format: "%.0f MB to go", left)) }
        if snapshot.paused != true,
           let eta = active.first(where: { $0.status == "Downloading" })?.timeleft,
           !eta.isEmpty, eta != "0:00:00" {
            parts.append("\(eta) left")
        }
        return parts.joined(separator: "   ")
    }
}

struct ThroughputChart: View {
    let samples: [Double]
    let linkPeakMBps: Double
    let linkPeakSrc: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if linkPeakMBps > 0 {
                let pct = max((samples.last ?? 0) / linkPeakMBps * 100, 0)
                Text(String(format: "%.0f%% of %.1f MB/s %@", pct, linkPeakMBps,
                            linkPeakSrc == "line" ? "line speed" : "peak"))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Canvas { ctx, size in
                guard samples.count >= 2 else { return }
                // The anchor pins the scale's lower bound; the window
                // max can still push past it, so an over-peak blip pokes
                // above the rule instead of squashing the history.
                let floor = linkPeakMBps > 0 ? linkPeakMBps * 1.04 : 0
                let maxV = max(samples.max() ?? 0, floor, 0.001)
                let pad: CGFloat = 2
                let stepX = size.width / CGFloat(samples.count - 1)
                func y(_ v: Double) -> CGFloat {
                    size.height - pad - CGFloat(v / maxV) * (size.height - pad * 2)
                }
                var line = Path()
                for (i, v) in samples.enumerated() {
                    let p = CGPoint(x: CGFloat(i) * stepX, y: y(v))
                    if i == 0 { line.move(to: p) } else { line.addLine(to: p) }
                }
                var area = line
                area.addLine(to: CGPoint(x: size.width, y: size.height))
                area.addLine(to: CGPoint(x: 0, y: size.height))
                area.closeSubpath()
                ctx.fill(area, with: .color(.accentColor.opacity(0.18)))
                ctx.stroke(line, with: .color(.accentColor), lineWidth: 2)
                if linkPeakMBps > 0 {
                    var rule = Path()
                    rule.move(to: CGPoint(x: 0, y: y(linkPeakMBps)))
                    rule.addLine(to: CGPoint(x: size.width, y: y(linkPeakMBps)))
                    ctx.stroke(rule, with: .color(.accentColor.opacity(0.55)),
                               style: StrokeStyle(lineWidth: 1, dash: [6, 4]))
                }
            }
            .frame(height: 52)
        }
    }
}

struct QueueRow: View {
    let job: PlaybackJob
    let onPlay: () -> Void
    let onPause: () -> Void
    let onResume: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(job.displayName)
                .font(.subheadline.weight(.medium))
                .lineLimit(2)
            ProgressView(value: min(max(job.pct / 100, 0), 1))
                .tint(job.isPaused ? .orange : .accentColor)
            Text(detail)
                .font(.caption2)
                .foregroundStyle(.secondary)
            HStack(spacing: 16) {
                if job.isPaused {
                    Button("Resume", action: onResume)
                } else {
                    Button("Pause", action: onPause)
                }
                Button("Cancel", role: .destructive, action: onCancel)
                Spacer()
                // playback.ready on the row replaces the per-job probe:
                // reason "live" (or "disk") means the file is readable
                // now. Play is an affordance here, never the headline.
                if job.ready {
                    Button(action: onPlay) {
                        Label("Play", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }
            }
            .font(.footnote)
            .buttonStyle(.borderless)
        }
        .padding(.vertical, 4)
    }

    private var detail: String {
        var parts: [String] = [job.status ?? ""]
        parts.append(String(format: "%.0f%%", job.pct))
        if let left = job.mbleft, left > 0 {
            parts.append(String(format: "%.0f MB to go", left))
        }
        if job.status == "Downloading", let tl = job.timeleft, !tl.isEmpty, tl != "0:00:00" {
            parts.append("\(tl) left")
        }
        // The activity token names the phase a tail is in - repairing,
        // extracting, moving - which is the part of a download that
        // otherwise looks like a stall.
        if let act = job.activity, !act.isEmpty, act != "fetching" {
            parts.append(act)
        }
        return parts.filter { !$0.isEmpty }.joined(separator: "   ")
    }
}
