import Foundation
import SwiftUI
import ParfastCore

/// Create (plan 5.3). Every control on the screen is a property here, the
/// spec is derived from them in one place, and the preview is whatever
/// `pf_plan_preview` last answered - the app never computes a figure the core
/// would also compute, so the two cannot disagree.
@MainActor
final class CreateModel: ObservableObject {

    struct Row: Identifiable, Hashable {
        var path: String
        var name: String
        var size: Int64
        var modified: Date?
        var isDirectory: Bool
        var recursive: Bool
        var id: String { path }
    }

    enum BlockMode: String, CaseIterable, Identifiable {
        case size, count
        var id: String { rawValue }
        var title: String { self == .size ? S.createBlocksBySize : S.createBlocksByCount }
    }

    enum RecoveryMode: String, CaseIterable, Identifiable {
        case percent, count, size
        var id: String { rawValue }
        var title: String {
            switch self {
            case .percent: return S.createRecoveryPercent
            case .count: return S.createRecoveryCount
            case .size: return S.createRecoverySize
            }
        }
    }

    enum UniformBy: String, CaseIterable, Identifiable {
        case files, blocks, size
        var id: String { rawValue }
        var title: String {
            switch self {
            case .files: return S.createOutputUniformFiles
            case .blocks: return S.createOutputUniformBlocks
            case .size: return S.createOutputUniformSize
            }
        }
    }

    enum LimitBy: String, CaseIterable, Identifiable {
        case largest, blocks, size
        var id: String { rawValue }
        var title: String {
            switch self {
            case .largest: return S.createOutputLimitLargest
            case .blocks: return S.createOutputLimitBlocks
            case .size: return S.createOutputLimitSize
            }
        }
    }

    @Published var sources: [Row] = []
    @Published var selection: Set<String> = []
    @Published var pathMode: PathMode = .basename
    @Published var basePath: String = ""

    @Published var blockMode: BlockMode = .count
    @Published var blockSize: Int64 = 1_048_576
    @Published var blockCount: Int = 2000

    @Published var recoveryMode: RecoveryMode = .percent
    @Published var recoveryPercent: Double = 10
    @Published var recoveryCount: Int = 200
    @Published var recoverySize: Int64 = 104_857_600

    @Published var output: String = ""
    @Published var schemeFamily: VolumeScheme.Family = .pow2
    @Published var uniformBy: UniformBy = .files
    @Published var uniformFiles: Int = 7
    @Published var uniformBlocks: Int = 100
    @Published var uniformSize: Int64 = 10_485_760
    @Published var limitBy: LimitBy = .largest
    @Published var limitBlocks: Int = 512
    @Published var limitSize: Int64 = 10_485_760

    @Published var firstRecoveryBlock: Int = 0
    @Published var comment: String = ""
    @Published var overwrite = false
    @Published var stdNaming = false
    @Published var unicode: UnicodePolicy = .auto
    @Published var showAdvanced = false
    @Published var showPreview = true

    @Published var preview: PlanPreview?
    @Published var previewing = false
    /// What the create will cost on disk, derived from `preview` and nothing
    /// else. Rebuilt in `recompute`, in the SAME assignment as the preview it
    /// reads, so the bar and the figures beside it can never be a recompute out
    /// of step with each other.
    @Published var cost = CostBarModel()
    @Published var jobId: Int64?
    @Published var snapshot: JobSnapshot?

    func applyDefaults(_ settings: CoreSettings) {
        blockMode = settings.create.block_allocation == .size ? .size : .count
        blockSize = settings.create.block_size
        blockCount = settings.create.block_count
        switch settings.create.recovery_allocation {
        case .percent: recoveryMode = .percent
        case .count: recoveryMode = .count
        case .size: recoveryMode = .size
        }
        recoveryPercent = settings.create.recovery_percent
        recoveryCount = settings.create.recovery_count
        recoverySize = settings.create.recovery_size
        stdNaming = settings.create.std_naming
        unicode = UnicodePolicy(rawValue: settings.create.unicode) ?? .auto
        overwrite = settings.create.overwrite
        switch settings.create.scheme {
        case "none": schemeFamily = .none
        case "uniform": schemeFamily = .uniform
        case "pow2_limit": schemeFamily = .pow2Limit
        default: schemeFamily = .pow2
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
            sources.append(Row(
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

    func refreshSources() {
        let paths = sources.map(\.path)
        sources = []
        addSources(paths)
    }

    /// Base folder and output name are derived from the sources the first
    /// time, and left alone once the user has touched them: an autofill that
    /// overwrites a typed name is worse than no autofill.
    @Published var outputEdited = false
    @Published var baseEdited = false

    func autofillFromSources() {
        guard !sources.isEmpty else { return }
        if !baseEdited {
            basePath = commonParent(of: sources.map(\.path)) ?? ""
        }
        if !outputEdited {
            let folder = basePath.isEmpty
                ? (sources[0].path as NSString).deletingLastPathComponent : basePath
            output = folder + "/" + suggestedStem() + ".par2"
        }
    }

    func suggestedStem() -> String {
        guard let first = sources.first else { return "recovery" }
        if sources.count == 1 {
            return first.isDirectory
                ? first.name
                : (first.name as NSString).deletingPathExtension
        }
        // The longest shared prefix of the names, trimmed of separators. It is
        // what every tool in this family does and it is right nearly always.
        var prefix = (sources[0].name as NSString).deletingPathExtension
        for row in sources.dropFirst() {
            let name = (row.name as NSString).deletingPathExtension
            prefix = String(zip(prefix, name).prefix { $0 == $1 }.map(\.0))
        }
        let trimmed = prefix.trimmingCharacters(in: CharacterSet(charactersIn: " .-_"))
        return trimmed.isEmpty ? "recovery" : trimmed
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

    var volumes: VolumeScheme {
        switch schemeFamily {
        case .none: return .none
        case .uniform:
            switch uniformBy {
            case .files: return .uniformFiles(max(1, uniformFiles))
            case .blocks: return .uniformBlocksPerFile(max(1, uniformBlocks))
            case .size: return .uniformFileSize(max(1, uniformSize))
            }
        case .pow2: return .pow2
        case .pow2Limit:
            switch limitBy {
            case .largest: return .pow2LimitLargestSource
            case .blocks: return .pow2LimitBlocks(max(1, limitBlocks))
            case .size: return .pow2LimitSize(max(1, limitSize))
            }
        }
    }

    func spec() -> CreateSpec {
        CreateSpec(
            sources: sources.map { SourceItem(path: $0.path, recursive: $0.isDirectory ? $0.recursive : nil) },
            path_mode: pathMode,
            base_path: pathMode == .relative ? basePath : nil,
            block: blockMode == .size ? .size(blockSize) : .count(blockCount),
            recovery: {
                switch recoveryMode {
                case .percent: return .percent(recoveryPercent)
                case .count: return .count(recoveryCount)
                case .size: return .size(recoverySize)
                }
            }(),
            output: output,
            volumes: volumes,
            first_recovery_block: firstRecoveryBlock,
            comment: comment,
            overwrite: overwrite,
            std_naming: stdNaming,
            unicode: unicode)
    }

    /// Everything the preview depends on, as one comparable value, so the
    /// screen recomputes on a change and not on every keystroke that changed
    /// nothing. `pf_plan_preview` does no I/O beyond stat, but it is still a
    /// call across the FFI and this is a live-typing surface.
    var previewKey: String {
        [
            sources.map(\.path).joined(separator: "|"),
            pathMode.rawValue, basePath, output, comment,
            blockMode.rawValue, "\(blockSize)", "\(blockCount)",
            recoveryMode.rawValue, "\(recoveryPercent)", "\(recoveryCount)", "\(recoverySize)",
            schemeFamily.rawValue, uniformBy.rawValue, "\(uniformFiles)", "\(uniformBlocks)",
            "\(uniformSize)", limitBy.rawValue, "\(limitBlocks)", "\(limitSize)",
            "\(firstRecoveryBlock)", "\(overwrite)", "\(stdNaming)", unicode.rawValue,
        ].joined(separator: "/")
    }

    func recompute(with core: CoreClient) {
        guard !sources.isEmpty else {
            preview = nil
            cost.update(nil)
            return
        }
        previewing = true
        defer { previewing = false }
        preview = try? core.planPreview(spec())
        cost.update(preview)
    }
}
