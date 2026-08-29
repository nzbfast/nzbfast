// TODO 281 IO0: History, on its own tab.
//
// It was a section under Home in the playback-first shell. The plan's
// addendum A names the phone app as Queue, Add, History, one Settings
// sheet and the player, and a queue-centred Home earns that split twice
// over: the queue is what the screen is for, and a finished job's row
// carries different actions from a running one's.
//
// WHAT A FAILURE SAYS IS THE POINT OF THIS SCREEN. `fail_message` is the
// daemon's own sentence and it is passed through unedited. The
// alternative is a phone-side translation table, which goes stale the
// first time a new refusal is written on the engine side, and a wrong
// explanation of a failure is worse than a blunt one.
import SwiftUI

struct HistoryView: View {
    @EnvironmentObject var state: AppState
    @State private var actionError: String?
    @State private var confirming: DeleteRequest?

    var body: some View {
        List {
            if let jobs = state.snapshot?.history, !jobs.isEmpty {
                ForEach(jobs) { job in
                    HistoryRow(job: job,
                               onPlay: { play(job) },
                               onRemove: {
                                   confirming = DeleteRequest(nzoId: job.id,
                                                              name: job.displayName,
                                                              fromHistory: true)
                               })
                }
            } else if state.snapshot != nil {
                Text("Nothing finished yet.")
                    .foregroundStyle(.secondary)
                    .font(.footnote)
            } else {
                ProgressView()
            }
        }
        .navigationTitle("History")
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
            Task {
                do {
                    try await state.api()?.deleteHistory(req.nzoId, deleteFiles: withFiles)
                    await state.refresh()
                } catch {
                    actionError = (error as? LocalizedError)?.errorDescription
                        ?? "The engine refused that."
                }
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

struct HistoryRow: View {
    let job: PlaybackJob
    let onPlay: () -> Void
    let onRemove: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(job.displayName)
                .font(.subheadline.weight(.medium))
                .lineLimit(2)
            Text(detail)
                .font(.caption2)
                .foregroundStyle(job.isFailed ? .red : .secondary)
                .lineLimit(3)
            HStack(spacing: 16) {
                Button("Remove", role: .destructive, action: onRemove)
                Spacer()
                // reason "disk" = the file is really still there; a row
                // whose media has been cleaned away ("no_media") gets no
                // Play, and one being relocated ("moving") is asked to
                // wait rather than written off - see `detail`.
                if job.ready {
                    Button(action: onPlay) {
                        Label("Play", systemImage: "play.fill")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
            .font(.footnote)
            .buttonStyle(.borderless)
        }
        .padding(.vertical, 4)
    }

    /// The subtitle, which is where a failure has to say what went
    /// wrong. Branches on the closed `reason` token set from
    /// packaging/android/compose-app/CONTRACT.md, never on prose.
    private var detail: String {
        if job.isFailed {
            let msg = job.failMessage ?? ""
            return msg.isEmpty ? "Failed" : msg
        }
        // The move window: the payload is whole and in flight to its
        // final folder. That used to read `no_media`, which tells a
        // client the file is gone when it is about to be readable again.
        if job.playback?.reason == "moving" { return "Moving to its folder" }
        if let b = job.bytes, b > 0 {
            return String(format: "%@   %.0f MB", job.status ?? "Completed", Double(b) / 1e6)
        }
        return job.status ?? ""
    }
}
