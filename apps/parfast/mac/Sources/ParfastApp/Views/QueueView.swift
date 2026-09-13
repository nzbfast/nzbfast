import SwiftUI
import ParfastCore

/// Queue, plan 5.5.
struct QueueView: View {
    @EnvironmentObject var app: AppModel
    @State private var selection: Set<Int64> = []

    var body: some View {
        FillingScroll { body_ }
    }

    @ViewBuilder
    private var body_: some View {
        if app.queue.jobs.isEmpty {
            DropZone(symbol: "list.bullet.rectangle", title: S.emptyQueueTitle,
                     body1: S.emptyQueueBody) {
                Button(S.modeCreate) { app.mode = .create }
                    .buttonStyle(.borderedProminent)
            }
        } else {
            VStack(spacing: T.spacingL) {
                Card(accessory: AnyView(toolbar)) {
                    Table(app.queue.jobs, selection: $selection) {
                        TableColumn(S.commonKind) { job in
                            HStack(spacing: T.spacingS) {
                                Image(systemName: symbol(job.kind))
                                    .foregroundStyle(T.textSecondary)
                                Text(app.displayKind(job.kind))
                            }
                        }
                        .width(130)

                        TableColumn(S.commonName) { job in
                            VStack(alignment: .leading, spacing: 1) {
                                Text(job.title ?? "")
                                if !job.phase_text.isEmpty && job.state == .running {
                                    Text(job.phase_text)
                                        .font(.system(size: 10))
                                        .foregroundStyle(T.textSecondary)
                                }
                            }
                        }
                        .width(min: 180, ideal: 300)

                        TableColumn(S.commonStatus) { job in
                            Text(stateText(job))
                                .foregroundStyle(stateColour(job))
                        }
                        .width(120)

                        TableColumn(S.commonProgress) { job in
                            if job.state == .running || job.state == .paused {
                                HStack(spacing: T.spacingS) {
                                    SmoothBar(value: job.progress, height: 5).frame(width: 90)
                                    Text(Fmt.progressPercent(job.progress))
                                        .font(.system(size: 11))
                                        .monospacedDigit()
                                        .foregroundStyle(T.textSecondary)
                                }
                            } else {
                                Text(job.state == .done ? Fmt.duration(ms: job.elapsed_ms) : "-")
                                    .font(.system(size: 11))
                                    .monospacedDigit()
                                    .foregroundStyle(T.textSecondary)
                            }
                        }
                        .width(150)

                        TableColumn(S.commonAdded) { job in
                            Text(Fmt.date(iso: job.added_at))
                                .font(.system(size: 11))
                                .monospacedDigit()
                                .foregroundStyle(T.textSecondary)
                        }
                        .width(160)
                    }
                    .tableStyle(.inset)
                    .frame(height: min(460, max(120, CGFloat(app.queue.jobs.count) * 32 + 44)))
                    .contextMenu(forSelectionType: Int64.self) { ids in
                        Button(S.progressPause) { ids.forEach { app.pause($0) } }
                        Button(S.progressResume) { ids.forEach { app.resume($0) } }
                        Divider()
                        Button(S.commonRemove) { ids.forEach { app.remove($0) } }
                    } primaryAction: { ids in
                        if let id = ids.first { app.progressJob = id }
                    }
                }

                Card {
                    HStack(spacing: T.spacingXl) {
                        Row(label: S.queueWhenFinished) {
                            Picker("", selection: Binding(
                                get: { app.queue.post_action },
                                set: { app.setPostAction($0) })) {
                                Text(S.queueFinishNone).tag(PostAction.none)
                                Text(S.queueFinishNotify).tag(PostAction.notify)
                                Text(S.queueFinishSleep).tag(PostAction.sleep)
                                Text(S.queueFinishShutdown).tag(PostAction.shutdown)
                            }
                            .labelsHidden()
                            .frame(width: 180)
                        }
                        Row(label: S.queueConcurrency) {
                            Picker("", selection: Binding(
                                get: { app.queue.concurrency },
                                set: { app.setConcurrency($0) })) {
                                Text(S.queueConcurrencyOne).tag(1)
                                ForEach([2, 3, 4], id: \.self) { n in
                                    Text(S.queueConcurrencyN(n: Fmt.count(n))).tag(n)
                                }
                            }
                            .labelsHidden()
                            .frame(width: 180)
                        }
                        Spacer()
                    }
                }
            }
            .padding(T.spacingL)
        }
    }

    private var toolbar: some View {
        HStack(spacing: T.spacingS) {
            Button(app.queue.paused ? S.queueResume : S.queuePause) {
                app.setQueuePaused(!app.queue.paused)
            }
            // `pf_job_run_next` landed 12 Sep (7fdfcece16), so this does
            // what the label always said. It is NOT resume - resuming only
            // lets the scheduler reach the job in its own turn - and it is
            // not a concurrency bump, which would start everything queued
            // ahead of it too.
            Button(S.queueRunNow) {
                selection.forEach { app.runNext($0) }
            }
            .disabled(selection.isEmpty)
            .help(S.queueRunNowTip)
            Button(S.commonRemove) {
                selection.forEach { app.remove($0) }
                selection = []
            }
            .disabled(selection.isEmpty)
            Button(S.queueClearFinished) {
                for job in app.queue.jobs where job.state.isFinished { app.remove(job.id) }
            }
        }
        .controlSize(.small)
    }

    private func symbol(_ kind: JobKind) -> String {
        switch kind {
        case .create: return "plus.square.on.square"
        case .verify: return "checkmark.shield"
        case .repairSet: return "wrench.and.screwdriver"
        case .checksumCreate, .checksumVerify: return "number.square"
        }
    }

    private func stateText(_ job: JobSnapshot) -> String {
        switch job.state {
        case .queued: return S.queueStateQueued
        case .running: return S.queueStateRunning
        case .paused: return S.queueStatePaused
        case .done: return S.queueStateDone
        case .failed: return S.queueStateFailed
        case .cancelled: return S.queueStateCancelled
        case .interrupted: return S.queueStateInterrupted
        }
    }

    private func stateColour(_ job: JobSnapshot) -> Color {
        switch job.state {
        case .done: return T.statusGood
        case .failed: return T.statusBad
        case .running: return T.statusWorking
        case .cancelled, .interrupted: return T.statusWarn
        case .queued, .paused: return T.textSecondary
        }
    }
}
