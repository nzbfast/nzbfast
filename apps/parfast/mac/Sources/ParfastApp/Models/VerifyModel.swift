import Foundation
import SwiftUI
import ParfastCore

/// Verify & Repair (plan 5.2). Holds what the user chose; the survey itself
/// is always the CORE's, read out of the latest snapshot, never cached and
/// edited here - a UI that keeps its own copy of a verdict is a UI that shows
/// a stale one.
@MainActor
final class VerifyModel: ObservableObject {

    enum Filter: String, CaseIterable, Identifiable {
        case all, problems
        var id: String { rawValue }
        var title: String { self == .all ? S.verifyFilterAll : S.verifyFilterProblems }
    }

    @Published var par2Path: String?
    @Published var jobId: Int64?
    @Published var lastRepairJobId: Int64?
    @Published var snapshot: JobSnapshot?
    @Published var extraDirs: [String] = []
    @Published var options = VerifyOptions()
    @Published var purge = false
    @Published var keepDamaged = false
    @Published var filter: Filter = .all
    @Published var excluded: Set<String> = []
    @Published var selection: Set<String> = []
    @Published var sort: [KeyPathComparator<SurveyFile>] = [
        KeyPathComparator(\SurveyFile.name)
    ]
    /// Block index the pointer is over, for the hover readout.
    @Published var hoverCell: BlockMapHover?

    /// Each member's own slice of the block map, keyed by file name (chart (c) of
    /// the 12 Sep 2026 prettiness review section 4). Empty when the survey's block
    /// totals do not reconcile with the strip, which is `FileStripModel`'s refusal
    /// arm and leaves every row with the `29 / 32` figure it had before this
    /// existed.
    ///
    /// CUT HERE, FROM `survey.files`, AND NEVER FROM `rows()`. The offsets are a
    /// running sum over the members in survey order, so the Problems only filter
    /// and the table's sort must not come near them: cutting over the rows the
    /// table draws would slide every surviving strip onto another file's blocks
    /// and draw a confident picture of the wrong file. A dictionary rather than an
    /// array is what makes that mistake unavailable at the call site - the table
    /// looks a row up BY NAME, so no index survives the filter to be got wrong.
    @Published private(set) var strips: [String: FileStripModel] = [:]

    /// The survey the strips were cut from, so a settled table at ten snapshots a
    /// second does not re-expand a ten-thousand-block strip on every one of them.
    private var stripSource: Survey?

    func applyDefaults(_ settings: CoreSettings) {
        purge = settings.general.purge_after_repair
        keepDamaged = settings.general.keep_damaged_copies
        options.fast_solver = settings.performance.fast_solver
        options.threads = settings.performance.threads
    }

    func setTarget(_ path: String) {
        par2Path = path
        excluded = []
        selection = []
        snapshot = nil
        jobId = nil
        lastRepairJobId = nil
        // The strips belong to the set being dropped, and the next snapshot of
        // the NEW set may not arrive for a moment. Left standing they would be
        // another set's damage under this set's file names, which is exactly the
        // lie `FileStripModel`'s reconciliation guard exists to prevent - and one
        // the guard cannot catch, because both surveys reconcile with themselves.
        strips = [:]
        stripSource = nil
    }

    func apply(queue: QueueSnapshot) {
        guard let id = jobId else { return }
        snapshot = queue.jobs.first { $0.id == id }
        rebuildStrips()
    }

    /// Recuts the row strips, and only when the survey actually moved.
    private func rebuildStrips() {
        let survey = snapshot?.survey
        guard survey != stripSource else { return }
        stripSource = survey
        guard let survey else {
            strips = [:]
            return
        }
        strips = FileStripModel.build(setStates: survey.expandedStates(),
                                      files: survey.files)
    }

    var survey: Survey? { snapshot?.survey }

    var isBusy: Bool {
        guard let s = snapshot else { return false }
        return s.state == .running || s.state == .queued || s.state == .paused
    }

    /// The repair that just finished, for the summary card. Nil while a verify
    /// is the current job, so the card cannot outlive its subject.
    func finishedRepair(in queue: QueueSnapshot) -> JobSnapshot? {
        guard let id = lastRepairJobId,
              let job = queue.jobs.first(where: { $0.id == id }),
              job.state == .done else { return nil }
        return job
    }

    var canRepair: Bool {
        guard let survey, !isBusy else { return false }
        return survey.verdict == .repairable
    }

    /// Rows after the filter and the sort, which is what the table draws.
    func rows() -> [SurveyFile] {
        guard let survey else { return [] }
        var files = survey.files
        if filter == .problems {
            files = files.filter {
                switch $0.status {
                case .complete, .pending, .hashing: return false
                case .damaged, .missing, .misnamed, .extra: return true
                }
            }
        }
        return files.sorted(using: sort)
    }

    func statusText(_ file: SurveyFile) -> String {
        switch file.status {
        case .complete: return S.verifyFileComplete
        case .damaged:
            let bad = max(0, file.blocks_total - file.blocks_ok)
            return bad > 0 ? S.verifyFileDamagedN(bad: Fmt.count(bad)) : S.verifyFileDamaged
        case .missing: return S.verifyFileMissing
        case .misnamed: return S.verifyFileMisnamed
        case .extra: return S.verifyFileExtra
        case .hashing: return S.verifyFileHashing
        case .pending: return S.verifyFilePending
        }
    }

    func toggleExcluded(_ names: some Collection<String>) {
        for name in names {
            if excluded.contains(name) { excluded.remove(name) } else { excluded.insert(name) }
        }
    }
}

/// What the block map reports under the pointer (5.2: "blocks 2,048-2,303:
/// 4 damaged").
struct BlockMapHover: Equatable {
    var first: Int
    var last: Int
    var counts: [BlockState: Int]

    var isSingle: Bool { first == last }
}
