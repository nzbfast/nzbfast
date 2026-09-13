import Foundation
import SwiftUI
import ParfastCore

/// Checksums (plan 5.4): two sub-modes over the same table.
@MainActor
final class ChecksumsModel: ObservableObject {

    enum SubMode: String, CaseIterable, Identifiable {
        case create, verify
        var id: String { rawValue }
        var title: String { self == .create ? S.checksumsCreate : S.checksumsVerify }
    }

    @Published var subMode: SubMode = .create
    @Published var sources: [CreateModel.Row] = []
    @Published var selection: Set<String> = []
    @Published var format: ChecksumFormat = .sfv
    @Published var output: String = ""
    @Published var relative = true
    @Published var outputEdited = false

    @Published var file: String = ""
    @Published var jobId: Int64?
    @Published var snapshot: JobSnapshot?

    func applyDefaults(_ settings: CoreSettings) {
        _ = settings
    }

    func apply(queue: QueueSnapshot) {
        guard let id = jobId else { return }
        snapshot = queue.jobs.first { $0.id == id }
    }

    func addSources(_ paths: [String]) {
        let fm = FileManager.default
        for path in paths where !sources.contains(where: { $0.path == path }) {
            var isDir: ObjCBool = false
            _ = fm.fileExists(atPath: path, isDirectory: &isDir)
            let attrs = try? fm.attributesOfItem(atPath: path)
            sources.append(CreateModel.Row(
                path: path,
                name: (path as NSString).lastPathComponent,
                size: (attrs?[.size] as? NSNumber)?.int64Value
                    ?? MockScenario.mockSize(forPath: path) ?? 0,
                modified: attrs?[.modificationDate] as? Date,
                isDirectory: isDir.boolValue,
                recursive: true))
        }
        autofillOutput()
    }

    func removeSelected() {
        sources.removeAll { selection.contains($0.path) }
        selection = []
    }

    func autofillOutput() {
        guard !outputEdited, let first = sources.first else { return }
        let folder = (first.path as NSString).deletingLastPathComponent
        let stem = (first.name as NSString).deletingPathExtension
        output = "\(folder)/\(stem).\(format.fileExtension)"
    }

    func createSpec() -> ChecksumCreateSpec {
        ChecksumCreateSpec(
            sources: sources.map { SourceItem(path: $0.path, recursive: $0.isDirectory ? $0.recursive : nil) },
            format: format,
            output: output,
            relative: relative)
    }

    var entries: [ChecksumEntry] { snapshot?.result?.checksum?.entries ?? [] }

    var result: ChecksumResult? { snapshot?.result?.checksum }

    var isBusy: Bool {
        guard let s = snapshot else { return false }
        return !s.state.isFinished
    }
}
