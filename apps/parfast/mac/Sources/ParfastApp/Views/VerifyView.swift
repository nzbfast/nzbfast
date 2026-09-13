import SwiftUI
import ParfastCore

/// Verify & Repair, plan 5.2: header card, status pill, block map, file
/// table, action bar, post-repair summary.
struct VerifyView: View {
    @EnvironmentObject var app: AppModel
    @ObservedObject var model: VerifyModel

    var body: some View {
        FillingScroll {
            if model.par2Path == nil {
                emptyState
            } else {
                content
            }
        }
    }

    // MARK: - Empty

    private var emptyState: some View {
        DropZone(symbol: "checkmark.shield", title: S.emptyVerifyTitle, body1: S.emptyVerifyBody) {
            Button(S.emptyVerifyOpen) {
                if let path = FilePicker.choose(directory: false, extensions: ["par2"],
                                                save: false, suggestion: "") {
                    app.openPar2(path)
                }
            }
            .keyboardShortcut("o")
            .buttonStyle(.borderedProminent)
            // GATED ON THE DEMO BUILD, like the banner at the top of the
            // window, and for the same reason. `AppModel.isDemoBuild`'s own doc
            // comment has said since it was written that linking `FfiCore`
            // "turns the banner and the demo menu off in one place" - the
            // banner was wired to it and this site never was, so the comment
            // described a behaviour the code did not have.
            //
            // It was correct when it was written (`3546116b09`), because every
            // build was a mock build then and there was no engine to link. What
            // it became once there was one is six menu items pointing at
            // `/Volumes/Mock/parfast/...`, which does not exist on a user's
            // machine: six dead entries in the first thing a release build
            // shows. Windows never had the affordance at all - its empty verify
            // state is Open file / Open folder, and its scenarios are reached by
            // a `--scenario` command line flag rather than by a control.
            //
            // The safety half matters more than the tidiness half. The demo
            // banner - "every figure here is made up" - is HIDDEN in a release
            // build, so an affordance that can load a scripted scenario must be
            // hidden by the SAME switch or the one guard against a demo being
            // mistaken for a verify is decoupled from the thing it guards.
            if app.isDemoBuild {
                Menu(S.appName + " demo") {
                    ForEach(MockScenario.all) { scenario in
                        Button(scenario.title) { app.openPar2(scenario.par2Path) }
                    }
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
        }
    }

    // MARK: - Content

    private var content: some View {
        VStack(spacing: T.spacingL) {
            headerCard
            if let survey = model.survey {
                mapCard(survey)
                fileCard(survey)
            } else {
                Card {
                    HStack(spacing: T.spacingM) {
                        ProgressView().controlSize(.small)
                        Text(S.createPreviewRecomputing)
                            .font(.system(size: 12))
                            .foregroundStyle(T.textSecondary)
                    }
                }
            }
            if let repair = model.finishedRepair(in: app.queue) {
                summaryCard(repair)
            }
        }
        .padding(T.spacingL)
    }

    private var headerCard: some View {
        Card {
            HStack(alignment: .top, spacing: T.spacingL) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.survey?.set_name ?? ((model.par2Path ?? "") as NSString).lastPathComponent)
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(T.textPrimary)
                    Button {
                        app.reveal(model.survey?.folder ?? (model.par2Path ?? ""))
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "folder")
                            Text(model.survey?.folder ?? "")
                                .lineLimit(1)
                                .truncationMode(.head)
                        }
                        .font(.system(size: 11))
                        .foregroundStyle(T.textSecondary)
                    }
                    .buttonStyle(.plain)
                    .help(S.commonReveal)
                }
                Spacer(minLength: T.spacingM)
                StatusPill(text: pillText, tone: pillTone, busy: model.isBusy)
            }

            Divider().overlay(T.surfaceGridLine)

            HStack(alignment: .top, spacing: T.spacingXxl) {
                Figure(label: S.verifyHeaderFiles,
                       value: Fmt.count(model.survey?.files.filter { $0.status != .extra }.count ?? 0))
                Figure(label: S.verifyHeaderBlockSize,
                       value: Fmt.blockSize(model.survey?.block_size ?? 0))
                Figure(label: S.verifyHeaderSourceBlocks,
                       value: Fmt.count(model.survey?.source_blocks ?? 0))
                Figure(label: S.verifyHeaderRecoveryBlocks,
                       value: Fmt.count(model.survey?.recovery_available ?? 0))
                Spacer(minLength: 0)
                actionBar
            }
        }
    }

    private func mapCard(_ survey: Survey) -> some View {
        Card(S.verifyMapTitle) {
            BlockMapView(
                states: survey.expandedStates(),
                recoveryAvailable: survey.recovery_available,
                recoveryNeeded: survey.recovery_needed,
                verdict: survey.verdict,
                hover: $model.hoverCell)
        }
    }

    private func fileCard(_ survey: Survey) -> some View {
        Card(accessory: AnyView(
            Picker("", selection: $model.filter) {
                ForEach(VerifyModel.Filter.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 170)
        )) {
            Table(model.rows(), selection: $model.selection, sortOrder: $model.sort) {
                TableColumn(S.commonName, value: \.name) { file in
                    HStack(spacing: T.spacingS) {
                        Image(systemName: symbol(file.status))
                            .foregroundStyle(colour(file.status))
                            .font(.system(size: 12))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(file.name)
                                .strikethrough(model.excluded.contains(file.name))
                                .foregroundStyle(T.textPrimary)
                            if let foundAs = file.found_as {
                                Text(S.verifyFileFoundAs(path: (foundAs as NSString).lastPathComponent))
                                    .font(.system(size: 10))
                                    .foregroundStyle(T.blockMisnamed)
                            }
                            if model.excluded.contains(file.name) {
                                Text(S.verifyRowExcluded)
                                    .font(.system(size: 10))
                                    .foregroundStyle(T.textTertiary)
                            }
                        }
                    }
                }
                .width(min: 220, ideal: 340)

                TableColumn(S.commonSize, value: \.size) { file in
                    Text(Fmt.bytes(file.size))
                        .monospacedDigit()
                        .foregroundStyle(T.textSecondary)
                }
                .width(110)

                TableColumn(S.commonStatus, value: \.status.rawValue) { file in
                    if file.status == .hashing, let progress = file.progress {
                        SmoothBar(value: progress, tint: T.blockHashing, height: 4)
                            .frame(width: 90)
                    } else {
                        Text(model.statusText(file))
                            .foregroundStyle(colour(file.status))
                    }
                }
                .width(150)

                TableColumn(S.commonBlocks, value: \.blocks_total) { file in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(file.blocks_total == 0 ? "-"
                             : S.verifyFileBlocksOf(ok: Fmt.count(file.blocks_ok),
                                                    total: Fmt.count(file.blocks_total)))
                            .monospacedDigit()
                            .foregroundStyle(T.textSecondary)
                        // The row's own slice of the map above, or NOTHING. A
                        // missing strip is an extra file, or a survey whose block
                        // totals did not reconcile - and in both cases the honest
                        // answer is to draw none and leave the figure to speak.
                        // Looked up BY NAME: see `VerifyModel.strips` for why an
                        // index into the filtered rows is the one thing that must
                        // never reach this chart.
                        if let strip = model.strips[file.name] {
                            MiniBlockStripView(strip: strip)
                        }
                    }
                }
                // 132 rather than 100: a strip needs the width to be a picture
                // rather than a dash, and this is the same widening the Windows
                // app made to the same column for the same control.
                .width(132)
            }
            .tableStyle(.inset)
            // Height follows the row count up to a cap: a five-file set under
            // an inset table stretched to fill the window is ten empty striped
            // rows, which reads as a list that failed to load.
            .frame(height: min(460, max(120, CGFloat(model.rows().count) * 30 + 44)))
            .contextMenu(forSelectionType: String.self) { names in
                Button(S.commonReveal) {
                    if let name = names.first, let folder = model.survey?.folder {
                        app.reveal(folder + "/" + name)
                    }
                }
                Button(S.verifyRowRename) {
                    // Rename-only is an engine mode, not a file operation the
                    // app does behind the engine's back: setting it here and
                    // repairing is what MultiPar's rename button does too.
                    model.options.rename_only = true
                    app.startRepair()
                }
                .disabled(!names.contains { name in
                    model.survey?.files.first { $0.name == name }?.status == .misnamed
                })
                Divider()
                Button(S.verifyRowExclude) { model.toggleExcluded(names) }
            }
        }
    }

    private func summaryCard(_ job: JobSnapshot) -> some View {
        Card {
            HStack(spacing: T.spacingL) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 22))
                    .foregroundStyle(T.statusGood)
                VStack(alignment: .leading, spacing: 2) {
                    Text(summaryText(job))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(T.textPrimary)
                    if job.result?.purged == true {
                        Text(S.verifySummaryPurged)
                            .font(.system(size: 11))
                            .foregroundStyle(T.textSecondary)
                    }
                }
                Spacer(minLength: T.spacingM)
                Button(S.commonReveal) { app.reveal(model.survey?.folder ?? "") }
                if job.result?.purged != true {
                    Button(S.verifySummaryPurge) {
                        model.purge = true
                        app.startRepair()
                    }
                }
                Toggle(S.commonLog, isOn: $app.logOpen)
                    .toggleStyle(.button)
            }
        }
    }

    private func summaryText(_ job: JobSnapshot) -> String {
        let count = job.result?.repaired_files ?? 0
        let time = Fmt.duration(ms: job.elapsed_ms)
        if count == 0 { return S.verifySummaryNothing }
        return count == 1
            ? S.verifySummaryRepairedOne(time: time)
            : S.verifySummaryRepaired(files: Fmt.count(count), time: time)
    }

    // MARK: - Action bar

    private var actionBar: some View {
        HStack(spacing: T.spacingS) {
            Button(S.verifyActionVerifyAgain) { app.startVerify() }
                .disabled(model.isBusy)

            Button(S.verifyActionScanOther) {
                let picked = FilePicker.chooseMany(directories: true)
                if !picked.isEmpty {
                    model.extraDirs.append(contentsOf: picked)
                    app.startVerify()
                }
            }
            .help(model.extraDirs.isEmpty ? "" :
                    S.verifyScanAdded(count: Fmt.count(model.extraDirs.count)))

            optionsMenu

            if model.isBusy {
                Button(S.verifyActionStop) {
                    if let id = model.jobId { app.cancel(id) }
                }
            } else {
                Button(S.verifyActionRepair) { app.startRepair() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canRepair)
            }
        }
    }

    private var optionsMenu: some View {
        Menu {
            Toggle(S.verifyOptionsPurge, isOn: $model.purge)
            Toggle(S.verifyOptionsKeepDamaged, isOn: $model.keepDamaged)
            Toggle(S.verifyOptionsRenameOnly, isOn: $model.options.rename_only)
            if app.capabilities.data_skipping {
                Divider()
                Toggle(S.verifyOptionsDataSkipping, isOn: $model.options.data_skipping)
                if model.options.data_skipping {
                    // The leaway only means anything with data skipping on, so
                    // it appears with it rather than sitting inert beside it.
                    Picker(S.verifyOptionsSkipLeaway, selection: $model.options.skip_leaway) {
                        ForEach([16, 64, 256, 1024], id: \.self) { Text(Fmt.count($0)).tag($0) }
                    }
                }
            }
            if app.capabilities.fast_solver {
                Divider()
                Toggle(S.verifyOptionsFastSolver, isOn: Binding(
                    get: { model.options.fast_solver ?? true },
                    set: { model.options.fast_solver = $0 }))
            }
            if !model.extraDirs.isEmpty {
                Divider()
                Button(S.verifyScanClear) { model.extraDirs = [] }
            }
        } label: {
            Label(S.commonOptions, systemImage: "slider.horizontal.3")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    // MARK: - The pill

    private var pillText: String {
        guard let snapshot = model.snapshot else { return S.verifyPillQueued }
        if snapshot.state == .paused { return S.verifyPillPaused }
        if snapshot.state == .cancelled { return S.verifyPillCancelled }
        if snapshot.state == .queued { return S.verifyPillQueued }
        let percent = Fmt.progressPercent(snapshot.progress)
        if snapshot.state == .running {
            return snapshot.kind == .repairSet
                ? S.verifyPillRepairing(percent: percent)
                : S.verifyPillVerifying(percent: percent)
        }
        if snapshot.kind == .repairSet {
            if snapshot.state == .failed {
                return S.verifyPillRepairFailed(reason: snapshot.error?.message ?? "")
            }
            return S.verifyPillRepaired
        }
        guard let survey = model.survey else { return S.verifyPillQueued }
        switch survey.verdict {
        case .complete: return S.verifyPillComplete
        case .repaired: return S.verifyPillRepaired
        case .repairable:
            return S.verifyPillRepairable(needed: Fmt.count(survey.recovery_needed),
                                          available: Fmt.count(survey.recovery_available))
        case .unrepairable:
            return S.verifyPillUnrepairable(
                short: Fmt.count(max(0, survey.recovery_needed - survey.recovery_available)))
        case .failed:
            return S.verifyPillRepairFailed(reason: snapshot.error?.message ?? "")
        case .verifying:
            return S.verifyPillVerifying(percent: percent)
        }
    }

    private var pillTone: StatusPill.Tone {
        guard let snapshot = model.snapshot else { return .neutral }
        if snapshot.state == .running || snapshot.state == .queued { return .working }
        if snapshot.state == .failed { return .bad }
        if snapshot.state == .cancelled || snapshot.state == .paused { return .neutral }
        switch model.survey?.verdict {
        case .complete, .repaired: return .good
        case .repairable: return .warn
        case .unrepairable, .failed: return .bad
        default: return .neutral
        }
    }

    private func symbol(_ status: FileStatus) -> String {
        switch status {
        case .complete: return "checkmark.circle.fill"
        case .damaged: return "exclamationmark.triangle.fill"
        case .missing: return "xmark.circle.fill"
        case .misnamed: return "arrow.triangle.branch"
        case .extra: return "questionmark.circle"
        case .hashing: return "circle.dotted"
        case .pending: return "circle"
        }
    }

    private func colour(_ status: FileStatus) -> Color {
        switch status {
        case .complete: return T.blockPresent
        case .damaged: return T.blockDamaged
        case .missing: return T.blockMissing
        case .misnamed: return T.blockMisnamed
        case .extra: return T.textTertiary
        case .hashing: return T.blockHashing
        case .pending: return T.textTertiary
        }
    }
}
