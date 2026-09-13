import SwiftUI
import ParfastCore

/// Checksums, plan 5.4: two sub-modes over one table, a pass/fail bar instead
/// of the block map.
struct ChecksumsView: View {
    @EnvironmentObject var app: AppModel
    @ObservedObject var model: ChecksumsModel

    var body: some View {
        FillingScroll {
            body_
        }
    }

    private var body_: some View {
        VStack(spacing: T.spacingL) {
            Picker("", selection: $model.subMode) {
                ForEach(ChecksumsModel.SubMode.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 220)
            .padding(.top, T.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)

            if model.subMode == .create {
                createSide
            } else {
                verifySide
            }
        }
        .padding(.horizontal, T.spacingL)
        .padding(.bottom, T.spacingL)
    }

    // MARK: - Create

    @ViewBuilder
    private var createSide: some View {
        if model.sources.isEmpty {
            DropZone(symbol: "number.square", title: S.emptyChecksumsTitle,
                     body1: S.emptyChecksumsBody) {
                Button(S.emptyCreateAddFiles) {
                    model.addSources(FilePicker.chooseMany(directories: false))
                }
                .buttonStyle(.borderedProminent)
                Button(S.emptyChecksumsOpen) {
                    if let path = FilePicker.choose(
                        directory: false, extensions: AppModel.checksumExtensions,
                        save: false, suggestion: "") {
                        app.openChecksumFile(path)
                    }
                }
            }
        } else {
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
                            .monospacedDigit()
                            .foregroundStyle(T.textSecondary)
                    }
                    .width(110)
                }
                .tableStyle(.inset)
                .frame(height: min(420, max(120, CGFloat(model.sources.count) * 30 + 44)))

                Row(label: S.checksumsFormat) {
                    Picker("", selection: $model.format) {
                        ForEach(ChecksumFormat.allCases) { Text($0.display).tag($0) }
                    }
                    .labelsHidden()
                    .frame(width: 160)
                    .onChange(of: model.format) { _, _ in model.autofillOutput() }
                }
                Row(label: S.checksumsOutput) {
                    PathField(path: $model.output,
                              allowedExtensions: [model.format.fileExtension], isSave: true) {
                        model.outputEdited = true
                    }
                }
                Toggle(S.checksumsRelative, isOn: $model.relative)
                    .padding(.leading, 144)

                HStack {
                    Spacer()
                    Button(S.checksumsCreate) { app.startChecksumCreate() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
    }

    // MARK: - Verify

    @ViewBuilder
    private var verifySide: some View {
        if model.file.isEmpty {
            DropZone(symbol: "checkmark.seal", title: S.emptyChecksumsTitle,
                     body1: S.emptyChecksumsBody) {
                Button(S.emptyChecksumsOpen) {
                    if let path = FilePicker.choose(
                        directory: false, extensions: AppModel.checksumExtensions,
                        save: false, suggestion: "") {
                        app.openChecksumFile(path)
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        } else {
            Card {
                HStack(alignment: .firstTextBaseline, spacing: T.spacingL) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text((model.file as NSString).lastPathComponent)
                            .font(.system(size: 15, weight: .semibold))
                        Text((model.file as NSString).deletingLastPathComponent)
                            .font(.system(size: 11))
                            .foregroundStyle(T.textSecondary)
                            .lineLimit(1)
                            .truncationMode(.head)
                    }
                    Spacer()
                    if let result = model.result {
                        StatusPill(
                            text: S.checksumsResult(ok: Fmt.count(result.ok),
                                                    mismatch: Fmt.count(result.mismatch),
                                                    missing: Fmt.count(result.missing)),
                            tone: result.mismatch + result.missing == 0 ? .good : .bad,
                            busy: model.isBusy)
                    }
                    Button(S.checksumsVerifyAgain) { app.startChecksumVerify() }
                        .disabled(model.isBusy)
                }

                // The pass/fail bar the plan asks for instead of the block map.
                passFailBar

                if model.entries.isEmpty, model.result != nil, !model.isBusy {
                    // `result.checksum.entries` landed 12 Sep (7fdfcece16), so
                    // this is now the EXCEPTION rather than the rule: an older
                    // core, or a checksum file the engine read as having no
                    // rows. It stays because an empty table is indistinguishable
                    // from a checksum file with nothing in it, and a Windows
                    // lane shipped exactly that against a field that did not
                    // exist.
                    HStack(spacing: T.spacingS) {
                        Image(systemName: "info.circle")
                        Text(S.checksumsNoDetail)
                        Spacer(minLength: 0)
                    }
                    .font(.system(size: 11))
                    .foregroundStyle(T.textTertiary)
                    .padding(.top, T.spacingXs)
                } else {
                    Table(model.entries) {
                        TableColumn(S.commonName) { Text($0.name) }
                        TableColumn(S.checksumsExpected) { entry in
                            VStack(alignment: .leading, spacing: 1) {
                                Text(entry.expected)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundStyle(T.textSecondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                // On a mismatch the two digests side by side
                                // are the whole story; `actual` is empty when
                                // the file is not there, and then there is
                                // nothing to show.
                                if entry.status == .mismatch, !entry.actual.isEmpty {
                                    Text(entry.actual)
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundStyle(T.blockDamaged)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }
                            }
                        }
                        .width(min: 120, ideal: 260)
                        TableColumn(S.commonStatus) { entry in
                            HStack(spacing: 5) {
                                Image(systemName: symbol(entry.status))
                                    .foregroundStyle(colour(entry.status))
                                Text(statusText(entry.status))
                                    .foregroundStyle(colour(entry.status))
                            }
                        }
                        .width(120)
                    }
                    .tableStyle(.inset)
                    .frame(height: min(460, max(120, CGFloat(model.entries.count) * 30 + 44)))
                }
            }
        }
    }

    /// Drawn from the COUNTS, not from per-entry rows: the contract carries
    /// only totals, and a bar that needed rows would be an empty bar.
    private var passFailBar: some View {
        GeometryReader { geo in
            let result = model.result
            let ok = result?.ok ?? 0
            let mismatch = result?.mismatch ?? 0
            let missing = result?.missing ?? 0
            let total = max(1, ok + mismatch + missing)
            HStack(spacing: 0) {
                ForEach([(ok, ChecksumEntry.Status.ok),
                         (mismatch, .mismatch),
                         (missing, .missing)], id: \.1) { count, status in
                    if count > 0 {
                        Rectangle()
                            .fill(colour(status))
                            .frame(width: geo.size.width * CGFloat(count) / CGFloat(total))
                    }
                }
            }
        }
        .frame(height: 14)
        .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
        .accessibilityLabel(S.checksumsResult(
            ok: Fmt.count(model.result?.ok ?? 0),
            mismatch: Fmt.count(model.result?.mismatch ?? 0),
            missing: Fmt.count(model.result?.missing ?? 0)))
    }

    private func statusText(_ status: ChecksumEntry.Status) -> String {
        switch status {
        case .ok: return S.checksumsStatusOk
        case .mismatch: return S.checksumsStatusMismatch
        case .missing: return S.checksumsStatusMissing
        case .pending: return S.verifyFilePending
        }
    }

    private func symbol(_ status: ChecksumEntry.Status) -> String {
        switch status {
        case .ok: return "checkmark.circle.fill"
        case .mismatch: return "exclamationmark.triangle.fill"
        case .missing: return "xmark.circle.fill"
        case .pending: return "circle"
        }
    }

    private func colour(_ status: ChecksumEntry.Status) -> Color {
        switch status {
        case .ok: return T.blockPresent
        case .mismatch: return T.blockDamaged
        case .missing: return T.blockMissing
        case .pending: return T.blockPending
        }
    }
}
