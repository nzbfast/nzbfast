import Foundation
import SwiftUI
import ParfastCore

/// "Create a posting set" (plan B1, API.md `posting_set`): files in, a RAR 5
/// archive or volume set plus a PAR2 set over it out, as one job. Every
/// control is a property here and the spec is derived in one place, the way
/// `CreateModel` does it.
///
/// THE PASSWORD LIVES HERE AND NOWHERE ELSE. It is held in memory for the
/// life of the pane, goes to the core inside the spec, and the core never
/// sends it back (`{"withheld":true}` on every echo). Nothing in this file
/// logs it, and `RarPassword`'s description says "withheld" so a stray
/// interpolation cannot either. `previewKey` carries whether there IS one,
/// never the bytes.
@MainActor
final class PostingModel: ObservableObject {

    enum Split: String, CaseIterable, Identifiable {
        case none, size, count
        var id: String { rawValue }
        var title: String {
            switch self {
            case .none: return S.postingVolumesNone
            case .size: return S.postingVolumesSize
            case .count: return S.postingVolumesCount
            }
        }
    }

    /// The PAR2 half's volume choice. The posting set offers the three a post
    /// actually uses; the Create pane keeps the rest of the scheme family.
    enum Par2Volumes: String, CaseIterable, Identifiable {
        case none, uniform, pow2
        var id: String { rawValue }
        var title: String {
            switch self {
            case .none: return S.createOutputSchemeNone
            case .uniform: return S.createOutputSchemeUniform
            case .pow2: return S.createOutputSchemePow2
            }
        }
    }

    /// rar's `-m0` to `-m5`, in the engine's order from store to smallest.
    static let compressionLevels: [(Int, String)] = [
        (0, S.postingCompressionStore), (1, S.postingCompressionFastest),
        (2, S.postingCompressionFast), (3, S.postingCompressionNormal),
        (4, S.postingCompressionGood), (5, S.postingCompressionBest),
    ]

    /// The least volume the core accepts (rar's own floor).
    static let minVolumeSize: Int64 = 65_536

    @Published var sources: [CreateModel.Row] = []
    @Published var selection: Set<String> = []
    @Published var pathMode: PathMode = .basename
    @Published var basePath: String = ""
    @Published var baseEdited = false

    @Published var outputDir: String = ""
    @Published var outputEdited = false
    @Published var name: String = ""
    @Published var nameEdited = false

    @Published var split: Split = .none
    @Published var volumeSize: Int64 = 104_857_600
    @Published var volumeCount: Int = 20
    @Published var compression: Int = 0
    @Published var solid = false
    @Published var password: String = ""
    @Published var encryptHeaders = true
    @Published var recoveryRecord: Int = 0

    @Published var blockMode: CreateModel.BlockMode = .count
    @Published var blockSize: Int64 = 1_048_576
    @Published var blockCount: Int = 2000
    @Published var recoveryMode: CreateModel.RecoveryMode = .percent
    @Published var recoveryPercent: Double = 10
    @Published var recoveryCount: Int = 200
    @Published var recoverySize: Int64 = 104_857_600
    @Published var par2Volumes: Par2Volumes = .pow2
    @Published var uniformFiles: Int = 7

    @Published var overwrite = false

    @Published var jobId: Int64?
    @Published var snapshot: JobSnapshot?

    /// The PAR2 half starts from the same Settings defaults a fresh Create
    /// pane does, which is what the core would use for a field left out.
    func applyDefaults(_ settings: CoreSettings) {
        blockMode = settings.create.block_allocation == .size ? .size : .count
        if settings.create.block_size > 0 { blockSize = settings.create.block_size }
        if settings.create.block_count > 0 { blockCount = settings.create.block_count }
        switch settings.create.recovery_allocation {
        case .percent: recoveryMode = .percent
        case .count: recoveryMode = .count
        case .size: recoveryMode = .size
        }
        if settings.create.recovery_percent > 0 { recoveryPercent = settings.create.recovery_percent }
        if settings.create.recovery_count > 0 { recoveryCount = settings.create.recovery_count }
        if settings.create.recovery_size > 0 { recoverySize = settings.create.recovery_size }
        switch settings.create.scheme {
        case "none": par2Volumes = .none
        case "uniform": par2Volumes = .uniform
        default: par2Volumes = .pow2
        }
    }

    func apply(queue: QueueSnapshot) {
        guard let id = jobId else { return }
        snapshot = queue.jobs.first { $0.id == id }
    }

    // MARK: - Sources

    func addSources(_ paths: [String]) {
        let fm = FileManager.default
        for path in paths where !sources.contains(where: { $0.path == path }) {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir) || path.hasPrefix(MockScenario.mockRoot) else {
                continue
            }
            let attrs = try? fm.attributesOfItem(atPath: path)
            let size = (attrs?[.size] as? NSNumber)?.int64Value
                ?? MockScenario.mockSize(forPath: path) ?? 0
            sources.append(CreateModel.Row(
                path: path,
                name: (path as NSString).lastPathComponent,
                size: isDir.boolValue ? 0 : size,
                modified: attrs?[.modificationDate] as? Date,
                isDirectory: isDir.boolValue,
                recursive: true))
        }
        autofillFromSources()
    }

    func removeSelected() {
        sources.removeAll { selection.contains($0.path) }
        selection = []
        autofillFromSources()
    }

    /// Folder, base and name come from the sources until the user touches
    /// them, and are left alone after that.
    func autofillFromSources() {
        guard let first = sources.first else { return }
        let parent = commonParent(of: sources.map(\.path)) ?? ""
        if !baseEdited { basePath = parent }
        if !outputEdited {
            outputDir = parent.isEmpty ? (first.path as NSString).deletingLastPathComponent : parent
        }
        if !nameEdited { name = suggestedName() }
    }

    func suggestedName() -> String {
        guard let first = sources.first else { return "" }
        if sources.count == 1 {
            return first.isDirectory ? first.name : (first.name as NSString).deletingPathExtension
        }
        var prefix = (first.name as NSString).deletingPathExtension
        for row in sources.dropFirst() {
            let other = (row.name as NSString).deletingPathExtension
            prefix = String(zip(prefix, other).prefix { $0 == $1 }.map(\.0))
        }
        let trimmed = prefix.trimmingCharacters(in: CharacterSet(charactersIn: " .-_"))
        return trimmed.isEmpty ? "posting" : trimmed
    }

    func commonParent(of paths: [String]) -> String? {
        guard let first = paths.first else { return nil }
        var parts = (first as NSString).deletingLastPathComponent.components(separatedBy: "/")
        for path in paths.dropFirst() {
            let other = (path as NSString).deletingLastPathComponent.components(separatedBy: "/")
            parts = Array(zip(parts, other).prefix { $0 == $1 }.map(\.0))
        }
        let joined = parts.joined(separator: "/")
        return joined.isEmpty ? "/" : joined
    }

    var totalBytes: Int64 { sources.reduce(0) { $0 + $1.size } }

    // MARK: - Spec

    var rarOptions: RarOptions {
        RarOptions(
            volumes: {
                switch split {
                case .none: return .none
                case .size: return .size(max(Self.minVolumeSize, volumeSize))
                case .count: return .count(max(1, volumeCount))
                }
            }(),
            compression: compression,
            // Solid is meaningless when stored, so a stored set never sends it.
            solid: compression > 0 && solid,
            password: password.isEmpty ? nil : .given(password),
            encrypt_headers: encryptHeaders,
            recovery_percent: max(0, recoveryRecord))
    }

    func spec() -> PostingSetSpec {
        PostingSetSpec(
            sources: sources.map { SourceItem(path: $0.path, recursive: $0.isDirectory ? $0.recursive : nil) },
            path_mode: pathMode,
            base_path: pathMode == .relative ? basePath : nil,
            output_dir: outputDir,
            name: name.trimmingCharacters(in: .whitespaces),
            rar: rarOptions,
            par2: PostingPar2(
                block: blockMode == .size ? .size(blockSize) : .count(blockCount),
                recovery: {
                    switch recoveryMode {
                    case .percent: return .percent(recoveryPercent)
                    case .count: return .count(recoveryCount)
                    case .size: return .size(recoverySize)
                    }
                }(),
                volumes: {
                    switch par2Volumes {
                    case .none: return VolumeScheme.none
                    case .uniform: return .uniformFiles(max(1, uniformFiles))
                    case .pow2: return .pow2
                    }
                }()),
            overwrite: overwrite)
    }

    /// The route the form predicts. The finished job's `result.posting.route`
    /// replaces it on screen, because that is what actually happened.
    var expectsOnePass: Bool { rarOptions.expectsOnePass }

    var canSubmit: Bool {
        !sources.isEmpty && !outputDir.isEmpty && !name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// A job of this pane that has finished, for the result card.
    var finished: JobSnapshot? {
        guard let job = snapshot, job.kind == .postingSet, job.state.isFinished else { return nil }
        return job
    }

    /// The core's refusal for a posting set, in this table's words where the
    /// table has them. `exists` keeps the core's sentence, which names the
    /// file in the way; the shared "turn on overwrite" line names a control
    /// this pane calls something else.
    func errorText(_ error: CoreError) -> String {
        switch error.code {
        case "password_required": return S.errorPasswordRequired
        case "rar_failed": return S.errorRarFailed(reason: error.message)
        default: return error.message
        }
    }
}
