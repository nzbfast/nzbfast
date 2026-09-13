import SwiftUI
import ParfastCore

/// Create, plan 5.3. Two columns on a wide window, stacked on a narrow one:
/// sources on the left, the set on the right, output and preview below.
struct CreateView: View {
    @EnvironmentObject var app: AppModel
    @ObservedObject var model: CreateModel

    var body: some View {
        Group {
            if model.sources.isEmpty {
                FillingScroll { emptyState }
            } else {
                VStack(spacing: 0) {
                    FillingScroll { content }
                    previewBar
                }
            }
        }
        .onChange(of: model.previewKey) { _, _ in model.recompute(with: app.core) }
        .onAppear { model.recompute(with: app.core) }
    }

    private var emptyState: some View {
        DropZone(symbol: "plus.square.on.square", title: S.emptyCreateTitle,
                 body1: S.emptyCreateBody) {
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
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: T.spacingL) {
                VStack(spacing: T.spacingL) { sourcesCard }
                    .frame(minWidth: 420)
                VStack(spacing: T.spacingL) {
                    blocksCard
                    recoveryCard
                    outputCard
                }
                .frame(minWidth: 420, maxWidth: 520)
            }
            VStack(spacing: T.spacingL) {
                sourcesCard
                blocksCard
                recoveryCard
                outputCard
            }
        }
        .padding(T.spacingL)
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
                Button(S.createSourcesRefresh) { model.refreshSources() }
            }
            .controlSize(.small)
        )) {
            Table(model.sources, selection: $model.selection) {
                TableColumn(S.commonName) { row in
                    HStack(spacing: T.spacingS) {
                        Image(systemName: row.isDirectory ? "folder" : "doc")
                            .foregroundStyle(T.textSecondary)
                        Text(row.name)
                        if row.isDirectory && row.recursive {
                            Text(S.createSourcesRecursive)
                                .font(.system(size: 10))
                                .foregroundStyle(T.textTertiary)
                        }
                    }
                }
                TableColumn(S.commonModified) { row in
                    Text(row.modified.map { Fmt.modified.string(from: $0) } ?? "-")
                        .foregroundStyle(T.textSecondary)
                        .monospacedDigit()
                }
                .width(160)
                TableColumn(S.commonSize) { row in
                    Text(row.isDirectory ? "-" : Fmt.bytes(row.size))
                        .foregroundStyle(T.textSecondary)
                        .monospacedDigit()
                }
                .width(110)
            }
            .tableStyle(.inset)
            .frame(height: min(420, max(120, CGFloat(model.sources.count) * 30 + 44)))

            HStack {
                Text(S.createSourcesFooter(files: Fmt.fileCount(model.sources.count),
                                           size: Fmt.bytes(model.totalBytes)))
                    .font(.system(size: 11))
                    .monospacedDigit()
                    .foregroundStyle(T.textSecondary)
                Spacer()
            }

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

    // MARK: - Source blocks

    private var blocksCard: some View {
        Card(S.createBlocksTitle) {
            Picker("", selection: $model.blockMode) {
                ForEach(CreateModel.BlockMode.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if model.blockMode == .size {
                Row(label: S.createBlocksBySize) {
                    SizeField(bytes: $model.blockSize, multipleOfFour: true)
                }
                Row(label: S.createBlocksByCount) {
                    readout(Fmt.count(model.preview?.block_count ?? 0))
                }
            } else {
                Row(label: S.createBlocksByCount) {
                    NumberField(value: $model.blockCount, range: 1...MockPlanner.maxSourceBlocks)
                }
                Row(label: S.createBlocksBySize) {
                    readout(Fmt.blockSize(model.preview?.block_size ?? 0))
                }
            }
            Row(label: S.createBlocksPadding) {
                readout(S.createBlocksPaddingValue(
                    bytes: Fmt.bytes(model.preview?.padding_bytes ?? 0),
                    percent: Fmt.percent(model.preview?.padding_pct ?? 0, decimals: 2)))
            }
            Row(label: S.createBlocksEfficiency) {
                readout(Fmt.percent(model.preview?.efficiency_pct ?? 0, decimals: 2))
            }
        }
    }

    // MARK: - Recovery

    private var recoveryCard: some View {
        Card(S.createRecoveryTitle) {
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
                        // 30 added and 15 dropped, 12 Sep 2026. The set stopped
                        // at 20, which read as a ceiling and is not one -
                        // recoveryPercent is unclamped here, so 30 has always been
                        // typeable; what was missing was the one click, and this
                        // project's round book publishes 25 and 30 percent parity
                        // rows.
                        //
                        // FOUR, AND THE COUNT IS LOAD-BEARING. This row is
                        // width-constrained: a six-chip set
                        // (5/10/15/20/25/30) came back from the screenshot
                        // harness with the middle labels ellipsised -
                        // "5% 10... 15... 2... 25% 30%" - and four render in
                        // full. Anyone adding a fifth must CHECK THE
                        // SCREENSHOT; no test here can see a truncated label.
                        // DUPLICATED: the Windows app keeps the same numbers in
                        // CreateViewModel.PercentChips and the two can drift.
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

            Row(label: S.commonTotal) {
                readout(S.createRecoveryReadout(
                    blocks: Fmt.count(model.preview?.recovery_blocks ?? 0),
                    size: Fmt.bytes(model.preview?.recovery_bytes ?? 0)))
            }
        }
    }

    // MARK: - Output

    private var outputCard: some View {
        Card(S.createOutputTitle) {
            Row(label: S.createOutputIndex) {
                PathField(path: $model.output, allowedExtensions: ["par2"], isSave: true) {
                    model.outputEdited = true
                }
            }
            Row(label: S.createOutputVolumes) {
                Picker("", selection: $model.schemeFamily) {
                    Text(S.createOutputSchemeNone).tag(VolumeScheme.Family.none)
                    Text(S.createOutputSchemeUniform).tag(VolumeScheme.Family.uniform)
                    Text(S.createOutputSchemePow2).tag(VolumeScheme.Family.pow2)
                    Text(S.createOutputSchemePow2Limit).tag(VolumeScheme.Family.pow2Limit)
                }
                .labelsHidden()
                .frame(width: 280)
            }

            switch model.schemeFamily {
            case .uniform:
                Row(label: S.createOutputUniformBy) {
                    Picker("", selection: $model.uniformBy) {
                        ForEach(CreateModel.UniformBy.allCases) { Text($0.title).tag($0) }
                    }
                    .labelsHidden()
                    .frame(width: 190)
                }
                switch model.uniformBy {
                case .files:
                    Row(label: S.createOutputUniformFiles) {
                        NumberField(value: $model.uniformFiles, range: 1...MockPlanner.maxRecoveryFiles)
                    }
                case .blocks:
                    Row(label: S.createOutputUniformBlocks) {
                        NumberField(value: $model.uniformBlocks, range: 1...65535)
                    }
                case .size:
                    Row(label: S.createOutputUniformSize) { SizeField(bytes: $model.uniformSize) }
                }
            case .pow2Limit:
                Row(label: S.createOutputLimitBy) {
                    Picker("", selection: $model.limitBy) {
                        ForEach(CreateModel.LimitBy.allCases) { Text($0.title).tag($0) }
                    }
                    .labelsHidden()
                    .frame(width: 210)
                }
                switch model.limitBy {
                case .largest: EmptyView()
                case .blocks:
                    Row(label: S.createOutputLimitBlocks) {
                        NumberField(value: $model.limitBlocks, range: 1...65535)
                    }
                case .size:
                    Row(label: S.createOutputLimitSize) { SizeField(bytes: $model.limitSize) }
                }
            case .none, .pow2:
                EmptyView()
            }

            Row(label: S.createOutputFirstBlock, help: S.createOutputFirstBlockTip) {
                NumberField(value: $model.firstRecoveryBlock, range: 0...65535, width: 80)
            }
            Row(label: S.createOutputComment) {
                TextField("", text: $model.comment)
                    .textFieldStyle(.roundedBorder)
            }
            Toggle(S.createOutputOverwrite, isOn: $model.overwrite)
                .padding(.leading, 144)

            DisclosureGroup(S.commonAdvanced, isExpanded: $model.showAdvanced) {
                VStack(alignment: .leading, spacing: T.spacingM) {
                    if app.capabilities.std_naming {
                        Toggle(S.createOutputStdNaming, isOn: $model.stdNaming)
                    }
                    if app.capabilities.unicode_policy {
                        Row(label: S.createOutputUnicode) {
                            Picker("", selection: $model.unicode) {
                                Text(S.createOutputUnicodeAuto).tag(UnicodePolicy.auto)
                                Text(S.createOutputUnicodeNever).tag(UnicodePolicy.never)
                                Text(S.createOutputUnicodeAlways).tag(UnicodePolicy.always)
                            }
                            .labelsHidden()
                            .frame(width: 160)
                        }
                    }
                    if !app.capabilities.std_naming && !app.capabilities.unicode_policy {
                        Text(S.settingsCapabilityHidden)
                            .font(.system(size: 11))
                            .foregroundStyle(T.textTertiary)
                    }
                }
                .padding(.top, T.spacingS)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .font(.system(size: 12))
        }
    }

    // MARK: - Preview

    private var previewBar: some View {
        VStack(spacing: 0) {
            Divider().overlay(T.surfaceGridLine)
            VStack(alignment: .leading, spacing: T.spacingM) {
                DisclosureGroup(isExpanded: $model.showPreview) {
                    previewTable
                        .padding(.top, T.spacingS)
                } label: {
                    HStack(spacing: T.spacingM) {
                        Text(S.createPreviewTitle)
                            .font(.system(size: 13, weight: .semibold))
                        if let preview = model.preview {
                            Text(S.createPreviewTotal(files: Fmt.count(preview.files.count),
                                                      size: Fmt.bytes(preview.total_bytes)))
                                .font(.system(size: 12))
                                .monospacedDigit()
                                .foregroundStyle(T.textSecondary)
                        }
                        Spacer()
                        if app.settings.advanced.show_command, let command = model.preview?.command {
                            Button(S.commonCopyCommand) { app.copyToPasteboard(command) }
                                .controlSize(.small)
                        }
                        Button(S.createActionQueue) { app.startCreate(queueOnly: true) }
                        Button(S.createActionCreate) { app.startCreate() }
                            .buttonStyle(.borderedProminent)
                            .keyboardShortcut(.defaultAction)
                    }
                }

                // The cost bar sits UNDER the disclosure's label and outside the
                // group, so it is on screen whether or not the file table is
                // expanded: it is the answer to "what will this cost me" and the
                // table is the detail behind it. The Windows equivalent had to be
                // given a screenshot state of its own because that app's preview
                // card is below the fold; here the preview is a pinned bottom bar,
                // so `--shot create` already frames it.
                CostBarView(model: model.cost)

                if let warnings = model.preview?.warnings, !warnings.isEmpty {
                    ForEach(warnings, id: \.self) { warning in
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .font(.system(size: 11))
                            .foregroundStyle(T.statusWarn)
                    }
                }
            }
            .padding(T.spacingL)
            .background(.regularMaterial)
        }
    }

    private var previewTable: some View {
        Group {
            if let preview = model.preview, !preview.files.isEmpty {
                Table(preview.files) {
                    TableColumn(S.createPreviewFile) { Text($0.name) }
                    TableColumn(S.commonSize) {
                        Text(Fmt.bytes($0.size)).monospacedDigit().foregroundStyle(T.textSecondary)
                    }
                    .width(110)
                    TableColumn(S.commonBlocks) {
                        Text(Fmt.count($0.blocks)).monospacedDigit().foregroundStyle(T.textSecondary)
                    }
                    .width(80)
                    TableColumn(S.createPreviewEfficiency) {
                        Text($0.blocks == 0 ? "-" : Fmt.percent($0.efficiency_pct, decimals: 1))
                            .monospacedDigit().foregroundStyle(T.textSecondary)
                    }
                    .width(100)
                }
                .tableStyle(.inset)
                .frame(height: min(196, max(92, CGFloat(preview.files.count) * 28 + 40)))
            } else {
                Text(S.createPreviewRecomputing)
                    .font(.system(size: 12))
                    .foregroundStyle(T.textSecondary)
                    .frame(height: 40)
            }
        }
    }

    private func readout(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 12, weight: .medium))
            .monospacedDigit()
            .foregroundStyle(T.textPrimary)
    }
}
