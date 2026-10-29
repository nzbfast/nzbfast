import SwiftUI
import ParfastCore

/// "Create a posting set" (plan B1). Sources on the left; the archive and its
/// PAR2 half on the right; the route and the actions pinned below, the way
/// Create pins its preview bar. Once a job of this pane has run, a result
/// card at the top says which route it took and lists the RAR and PAR2 files.
///
/// It carried a Beta badge while it lived on a branch; the 25 Oct 2026
/// decision ships it as a full feature of the app's first stable release,
/// so the badge went with the app's own stage.
struct PostingView: View {
    @EnvironmentObject var app: AppModel
    @ObservedObject var model: PostingModel

    var body: some View {
        Group {
            if model.sources.isEmpty && model.finished == nil {
                FillingScroll { emptyState }
            } else {
                VStack(spacing: 0) {
                    FillingScroll { content }
                    actionBar
                }
            }
        }
    }

    private var emptyState: some View {
        DropZone(symbol: "shippingbox", title: S.postingEmptyTitle, body1: S.postingEmptyBody) {
            Button(S.emptyCreateAddFiles) {
                model.addSources(FilePicker.chooseMany(directories: false))
            }
            .buttonStyle(.borderedProminent)
            Button(S.emptyCreateAddFolder) {
                model.addSources(FilePicker.chooseMany(directories: true))
            }
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: T.spacingL) {
            header
            if let job = model.finished { resultCard(job) }
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: T.spacingL) {
                    VStack(spacing: T.spacingL) { sourcesCard }
                        .frame(minWidth: 420)
                    VStack(spacing: T.spacingL) {
                        archiveCard
                        par2Card
                    }
                    .frame(minWidth: 420, maxWidth: 520)
                }
                VStack(spacing: T.spacingL) {
                    sourcesCard
                    archiveCard
                    par2Card
                }
            }
        }
        .padding(T.spacingL)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(S.postingTitle)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(T.textPrimary)
            Text(S.postingIntro)
                .font(.system(size: 12))
                .foregroundStyle(T.textSecondary)
        }
    }

    // MARK: - Sources

    private var sourcesCard: some View {
        Card(S.createSources, accessory: AnyView(
            HStack(spacing: T.spacingS) {
                Button(S.createSourcesAddFiles) {
                    model.addSources(FilePicker.chooseMany(directories: false))
                }
                Button(S.createSourcesAddFolder) {
                    model.addSources(FilePicker.chooseMany(directories: true))
                }
                Button(S.commonRemove) { model.removeSelected() }
                    .disabled(model.selection.isEmpty)
            }
            .controlSize(.small)
        )) {
            Table(model.sources, selection: $model.selection) {
                TableColumn(S.commonName) { row in
                    HStack(spacing: T.spacingS) {
                        Image(systemName: row.isDirectory ? "folder" : "doc")
                            .foregroundStyle(T.textSecondary)
                        Text(row.name)
                    }
                }
                TableColumn(S.commonSize) { row in
                    Text(row.isDirectory ? "-" : Fmt.bytes(row.size))
                        .foregroundStyle(T.textSecondary)
                        .monospacedDigit()
                }
                .width(110)
            }
            .tableStyle(.inset)
            .frame(height: min(360, max(120, CGFloat(model.sources.count) * 30 + 44)))

            Text(S.createSourcesFooter(files: Fmt.fileCount(model.sources.count),
                                       size: Fmt.bytes(model.totalBytes)))
                .font(.system(size: 11))
                .monospacedDigit()
                .foregroundStyle(T.textSecondary)

            Divider().overlay(T.surfaceGridLine)

            Row(label: S.createPathsLabel) {
                Picker("", selection: $model.pathMode) {
                    Text(S.createPathsBasename).tag(PathMode.basename)
                    Text(S.createPathsRelative).tag(PathMode.relative)
                }
                .labelsHidden()
                .frame(width: 220)
            }
            if model.pathMode == .relative {
                Row(label: S.createBaseFolder) {
                    PathField(path: $model.basePath, chooseDirectory: true) {
                        model.baseEdited = true
                    }
                }
            }
        }
    }

    // MARK: - The archive

    private var archiveCard: some View {
        Card(S.postingOutputRar) {
            Row(label: S.postingOutputFolder) {
                PathField(path: $model.outputDir, chooseDirectory: true) {
                    model.outputEdited = true
                }
            }
            Row(label: S.postingName, help: S.postingNameTip(name: displayName)) {
                TextField("", text: Binding(
                    get: { model.name },
                    set: { model.name = $0; model.nameEdited = true }))
                    .textFieldStyle(.roundedBorder)
            }

            Divider().overlay(T.surfaceGridLine)

            // Segmented, like the PAR2 half's block and recovery choices: three
            // answers that change which rows follow read better side by side
            // than behind a menu.
            Text(S.postingVolumesTitle)
                .font(.system(size: 12))
                .foregroundStyle(T.textSecondary)
            Picker("", selection: $model.split) {
                ForEach(PostingModel.Split.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            switch model.split {
            case .none: EmptyView()
            case .size:
                Row(label: S.postingVolumesSizeLabel, help: S.postingVolumesMinSize) {
                    SizeField(bytes: $model.volumeSize)
                }
            case .count:
                Row(label: S.postingVolumesCountLabel) {
                    NumberField(value: $model.volumeCount, range: 1...9999)
                }
            }

            Row(label: S.postingCompressionTitle, help: S.postingCompressionNote) {
                Picker("", selection: $model.compression) {
                    ForEach(PostingModel.compressionLevels, id: \.0) { level in
                        Text(level.1).tag(level.0)
                    }
                }
                .labelsHidden()
                .frame(width: 250)
            }
            if model.compression > 0 {
                Toggle(S.postingSolid, isOn: $model.solid)
                    .padding(.leading, 144)
                    .help(S.postingSolidTip)
            }

            Row(label: S.postingPasswordTitle) {
                SecureField(S.postingPasswordPlaceholder, text: $model.password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 250)
            }
            if !model.password.isEmpty {
                Toggle(S.postingPasswordEncryptHeaders, isOn: $model.encryptHeaders)
                    .padding(.leading, 144)
            }

            Row(label: S.postingRecoveryRecord) {
                HStack(spacing: T.spacingS) {
                    NumberField(value: $model.recoveryRecord, range: 0...100, width: 60)
                    Text(S.postingRecoveryRecordValue(percent: "%"))
                        .font(.system(size: 12))
                        .foregroundStyle(T.textSecondary)
                }
            }

            Toggle(S.postingOverwrite, isOn: $model.overwrite)
                .padding(.leading, 144)
                .help(S.postingOverwriteTip)
        }
    }

    private var displayName: String {
        let trimmed = model.name.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? "name" : trimmed
    }

    // MARK: - The PAR2 half

    private var par2Card: some View {
        Card(S.postingPar2Title) {
            Picker("", selection: $model.blockMode) {
                ForEach(CreateModel.BlockMode.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            if model.blockMode == .size {
                Row(label: S.createBlocksBySize) {
                    SizeField(bytes: $model.blockSize, multipleOfFour: true)
                }
            } else {
                Row(label: S.createBlocksByCount) {
                    NumberField(value: $model.blockCount, range: 1...MockPlanner.maxSourceBlocks)
                }
            }

            Picker("", selection: $model.recoveryMode) {
                ForEach(CreateModel.RecoveryMode.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            switch model.recoveryMode {
            case .percent:
                Row(label: S.createRecoveryPercent) {
                    HStack(spacing: T.spacingS) {
                        TextField("", value: $model.recoveryPercent, format: .number)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 70)
                            .multilineTextAlignment(.trailing)
                            .monospacedDigit()
                        Text("%").foregroundStyle(T.textSecondary)
                        // The Create pane's four chips, for the reason its
                        // comment gives: a fifth ellipsises at this width.
                        ForEach([5.0, 10.0, 20.0, 30.0], id: \.self) { value in
                            Button(Fmt.percent(value)) { model.recoveryPercent = value }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                        }
                    }
                }
            case .count:
                Row(label: S.createRecoveryCount) {
                    NumberField(value: $model.recoveryCount, range: 0...65535)
                }
            case .size:
                Row(label: S.createRecoverySize) {
                    SizeField(bytes: $model.recoverySize)
                }
            }

            Row(label: S.createOutputVolumes) {
                Picker("", selection: $model.par2Volumes) {
                    ForEach(PostingModel.Par2Volumes.allCases) { Text($0.title).tag($0) }
                }
                .labelsHidden()
                .frame(width: 250)
            }
            if model.par2Volumes == .uniform {
                Row(label: S.createOutputUniformFiles) {
                    NumberField(value: $model.uniformFiles, range: 1...MockPlanner.maxRecoveryFiles)
                }
            }
        }
    }

    // MARK: - The result

    private func resultCard(_ job: JobSnapshot) -> some View {
        // A set that failed or was stopped wrote nothing that survives, so
        // its card carries no "Files written" title.
        Card(job.state == .done ? S.postingOutputTitle : nil, accessory: AnyView(
            Group {
                if job.state == .done, let first = job.result?.written?.first {
                    Button(S.commonReveal) {
                        app.reveal(model.outputDir + "/" + first.name)
                    }
                    .controlSize(.small)
                }
            }
        )) {
            if job.state == .done, let posting = job.result?.posting {
                Label(routeSentence(posting), systemImage: posting.route == .onePass
                      ? "bolt.fill" : "arrow.triangle.2.circlepath")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(T.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                fileList(S.postingOutputRar, posting.rar)
                fileList(S.postingOutputPar2, posting.par2)
            } else if let error = job.error {
                Label(model.errorText(error), systemImage: "xmark.octagon")
                    .font(.system(size: 12))
                    .foregroundStyle(T.statusBad)
                    .fixedSize(horizontal: false, vertical: true)
                Text(S.postingCancelNote)
                    .font(.system(size: 11))
                    .foregroundStyle(T.textSecondary)
            } else {
                Text(S.postingCancelNote)
                    .font(.system(size: 11))
                    .foregroundStyle(T.textSecondary)
            }
        }
    }

    private func routeSentence(_ posting: PostingResult) -> String {
        switch posting.route {
        case .onePass: return S.postingRouteOnePass
        case .twoPass:
            let reason = posting.route_reason ?? ""
            return reason.isEmpty ? S.postingRouteExpectTwoPass : S.postingRouteTwoPassBecause(reason: reason)
        }
    }

    private func fileList(_ title: String, _ files: [WrittenFile]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(T.textSecondary)
                Spacer()
                Text(S.createPreviewTotal(files: Fmt.count(files.count),
                                          size: Fmt.bytes(files.reduce(0) { $0 + $1.size })))
                    .font(.system(size: 11))
                    .monospacedDigit()
                    .foregroundStyle(T.textSecondary)
            }
            ForEach(files) { file in
                HStack {
                    Image(systemName: title == S.postingOutputRar ? "shippingbox" : "cross.case")
                        .font(.system(size: 11))
                        .foregroundStyle(T.textTertiary)
                    Text(file.name)
                        .font(.system(size: 12))
                        .textSelection(.enabled)
                    Spacer()
                    Text(Fmt.bytes(file.size))
                        .font(.system(size: 12))
                        .monospacedDigit()
                        .foregroundStyle(T.textSecondary)
                }
            }
        }
    }

    // MARK: - Route and actions

    private var actionBar: some View {
        VStack(spacing: 0) {
            Divider().overlay(T.surfaceGridLine)
            HStack(spacing: T.spacingM) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(S.postingRouteTitle)
                        .font(.system(size: 13, weight: .semibold))
                    // Two lines at most, and first claim on the width: an
                    // unbounded wrap here was proposed a sliver beside the
                    // buttons and grew the bar off the bottom of the window.
                    Text(model.expectsOnePass ? S.postingRouteExpectOnePass : S.postingRouteExpectTwoPass)
                        .font(.system(size: 12))
                        .foregroundStyle(T.textSecondary)
                        .lineLimit(2)
                }
                .layoutPriority(1)
                Spacer()
                Button(S.createActionQueue) { app.startPosting(queueOnly: true) }
                    .disabled(!model.canSubmit)
                Button(S.postingActionCreate) { app.startPosting() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canSubmit)
            }
            .padding(T.spacingL)
            .background(.regularMaterial)
        }
    }
}
