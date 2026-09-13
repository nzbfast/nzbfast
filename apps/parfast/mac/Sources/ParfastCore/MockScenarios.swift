import Foundation

/// A scripted PAR2 set the mock core can play.
///
/// These are the scenarios plan section 7 names as the acceptance corpus -
/// clean, one damaged, one missing, one misnamed, one moved to a sibling
/// folder, unrepairable, unicode names, a ten-thousand-block set - written as
/// data so every screen and state in section 5 is reachable with no PAR2
/// files on disk and no engine. Chip D's `make-corpus.py` generates the same
/// list as REAL sets; when it lands, `FfiCore` plays those and this file
/// stays as the UI test harness (plan 3.3).
public struct MockScenario: Hashable, Identifiable {

    public enum Outcome: Hashable {
        case complete
        case damaged(bad: Int)
        case missing
        /// The data is there under another name, in this folder or a sibling.
        case misnamed(foundAs: String)
        /// A file in the folder that the set does not describe.
        case extra
    }

    public struct File: Hashable {
        public var name: String
        public var size: Int64
        public var outcome: Outcome

        public init(name: String, size: Int64, outcome: Outcome = .complete) {
            self.name = name
            self.size = size
            self.outcome = outcome
        }
    }

    public var id: String
    public var title: String
    public var detail: String
    public var setName: String
    public var folder: String
    public var blockSize: Int64
    public var recoveryAvailable: Int
    public var files: [File]
    /// Nominal wall time of a verify at speed 1. The mock scales it.
    public var verifySeconds: Double
    public var repairSeconds: Double

    public init(id: String, title: String, detail: String, setName: String, folder: String,
                blockSize: Int64, recoveryAvailable: Int, files: [File],
                verifySeconds: Double = 6, repairSeconds: Double = 5) {
        self.id = id
        self.title = title
        self.detail = detail
        self.setName = setName
        self.folder = folder
        self.blockSize = blockSize
        self.recoveryAvailable = recoveryAvailable
        self.files = files
        self.verifySeconds = verifySeconds
        self.repairSeconds = repairSeconds
    }

    /// Blocks a file occupies. An `extra` file is not in the set and occupies
    /// none, which is why it cannot simply be `ceil(size / blockSize)`.
    public func blocks(of file: File) -> Int {
        if case .extra = file.outcome { return 0 }
        return max(1, Int((file.size + blockSize - 1) / blockSize))
    }

    public var sourceBlocks: Int { files.reduce(0) { $0 + blocks(of: $1) } }

    /// Blocks that repair would have to rebuild.
    public var blocksNeeded: Int {
        files.reduce(0) { acc, f in
            switch f.outcome {
            case .complete, .extra, .misnamed: return acc
            case .missing: return acc + blocks(of: f)
            case .damaged(let bad): return acc + min(bad, blocks(of: f))
            }
        }
    }

    public var finalVerdict: SurveyVerdict {
        let needed = blocksNeeded
        if needed == 0 { return .complete }
        return needed <= recoveryAvailable ? .repairable : .unrepairable
    }

    /// The path a `.par2` drop would carry. The mock routes on this, so the
    /// demo menu and a real Finder drop take exactly the same code path.
    public var par2Path: String { folder + "/" + setName }
}

extension MockScenario {

    public static let all: [MockScenario] = [
        clean, damagedRepairable, unrepairable, misnamedAndMoved, unicodeNames, tenThousandBlocks,
    ]

    public static func named(_ id: String) -> MockScenario? {
        all.first { $0.id == id }
    }

    /// Route a dropped or opened `.par2` path to a scenario. A path under the
    /// mock folder picks that scenario by name; anything else gets the
    /// damaged set, because a demo that always says "complete" proves nothing.
    public static func routing(path: String) -> MockScenario {
        if let hit = all.first(where: { path == $0.par2Path }) { return hit }
        let stem = ((path as NSString).lastPathComponent as NSString).deletingPathExtension.lowercased()
        if let hit = all.first(where: { stem.contains($0.id.lowercased()) }) { return hit }
        var adopted = damagedRepairable
        adopted.setName = (path as NSString).lastPathComponent
        adopted.folder = (path as NSString).deletingLastPathComponent
        return adopted
    }

    public static let mockRoot = "/Volumes/Mock/parfast"

    public static let clean = MockScenario(
        id: "clean",
        title: "Clean set",
        detail: "Every file intact. The verdict lands on complete and Repair stays off.",
        setName: "holiday-video.par2",
        folder: "\(mockRoot)/clean",
        blockSize: 1_048_576,
        recoveryAvailable: 120,
        files: [
            File(name: "holiday-video.part01.rar", size: 419_430_400),
            File(name: "holiday-video.part02.rar", size: 419_430_400),
            File(name: "holiday-video.part03.rar", size: 419_430_400),
            File(name: "holiday-video.part04.rar", size: 268_435_456),
            File(name: "holiday-video.nfo", size: 4_096),
        ],
        verifySeconds: 5)

    public static let damagedRepairable = MockScenario(
        id: "damaged",
        title: "Damaged, repairable",
        detail: "One file with bad blocks, one gone. 46 blocks needed against 120 available.",
        setName: "archive-set.par2",
        folder: "\(mockRoot)/damaged",
        blockSize: 1_048_576,
        recoveryAvailable: 120,
        files: [
            File(name: "archive-set.part01.rar", size: 419_430_400),
            File(name: "archive-set.part02.rar", size: 419_430_400, outcome: .damaged(bad: 14)),
            File(name: "archive-set.part03.rar", size: 33_554_432, outcome: .missing),
            File(name: "archive-set.part04.rar", size: 268_435_456),
            File(name: "archive-set.nfo", size: 2_048),
        ],
        verifySeconds: 7,
        repairSeconds: 6)

    public static let unrepairable = MockScenario(
        id: "unrepairable",
        title: "Not repairable",
        detail: "Two files missing and thin recovery. Repair is refused with the shortfall named.",
        setName: "thin-recovery.par2",
        folder: "\(mockRoot)/unrepairable",
        blockSize: 1_048_576,
        recoveryAvailable: 16,
        files: [
            File(name: "thin-recovery.part01.rar", size: 209_715_200),
            File(name: "thin-recovery.part02.rar", size: 209_715_200, outcome: .missing),
            File(name: "thin-recovery.part03.rar", size: 209_715_200, outcome: .damaged(bad: 30)),
            File(name: "thin-recovery.part04.rar", size: 104_857_600),
        ],
        verifySeconds: 6)

    public static let misnamedAndMoved = MockScenario(
        id: "misnamed",
        title: "Misnamed and moved",
        detail: "Obfuscated names in this folder and one file in a sibling, plus an extra file the set does not know.",
        setName: "renamed-set.par2",
        folder: "\(mockRoot)/misnamed",
        blockSize: 524_288,
        recoveryAvailable: 80,
        files: [
            File(name: "renamed-set.part01.rar", size: 104_857_600,
                 outcome: .misnamed(foundAs: "\(mockRoot)/misnamed/a4f9c2e18b7d0356.bin")),
            File(name: "renamed-set.part02.rar", size: 104_857_600,
                 outcome: .misnamed(foundAs: "\(mockRoot)/misnamed/elsewhere/b81e07da49cf2215.bin")),
            File(name: "renamed-set.part03.rar", size: 104_857_600),
            File(name: "renamed-set.part04.rar", size: 52_428_800, outcome: .damaged(bad: 6)),
            File(name: "readme-from-the-poster.txt", size: 1_200, outcome: .extra),
        ],
        verifySeconds: 6,
        repairSeconds: 4)

    public static let unicodeNames = MockScenario(
        id: "unicode",
        title: "Unicode names",
        detail: "Non-ASCII file names, one of them damaged, to prove the tables and the log carry them.",
        setName: "Sommerferien Öresund.par2",
        folder: "\(mockRoot)/unicode",
        blockSize: 262_144,
        recoveryAvailable: 64,
        files: [
            File(name: "Sommerferien Öresund.mkv", size: 83_886_080),
            File(name: "日本語のメモ.txt", size: 8_192),
            File(name: "café résumé.pdf", size: 2_097_152, outcome: .damaged(bad: 3)),
            File(name: "Ελληνικά-σημειώσεις.md", size: 4_096),
            File(name: "Здравствуйте.srt", size: 16_384, outcome: .missing),
        ],
        verifySeconds: 5,
        repairSeconds: 3)

    public static let tenThousandBlocks = MockScenario(
        id: "bigset",
        title: "Ten thousand blocks",
        detail: "Past the block map's merge threshold, with damage scattered so the merged cells have something to show.",
        setName: "big-set.par2",
        folder: "\(mockRoot)/bigset",
        blockSize: 1_048_576,
        recoveryAvailable: 900,
        files: (1...20).map { i in
            let damaged = [3, 7, 12, 18].contains(i)
            return File(
                name: String(format: "big-set.part%02d.rar", i),
                size: 524_288_000,
                outcome: damaged ? .damaged(bad: 37 + i) : .complete)
        },
        verifySeconds: 12,
        repairSeconds: 10)

    /// A create job the progress sheet can be demonstrated on: long enough to
    /// pause, cancel and watch the phases change (plan's "30-second create").
    public static func longCreateSpec(outputFolder: String = "\(mockRoot)/create") -> CreateSpec {
        CreateSpec(
            sources: (1...6).map { SourceItem(path: "\(outputFolder)/source.part0\($0).rar") },
            path_mode: .basename,
            base_path: outputFolder,
            block: .count(2000),
            recovery: .percent(10),
            output: "\(outputFolder)/new-set.par2",
            volumes: .pow2,
            comment: "Made with parfast")
    }

    /// Sizes the mock reports for the long create's synthetic sources, so the
    /// preview has real arithmetic to do without touching the disk.
    public static func mockSize(forPath path: String) -> Int64? {
        guard path.hasPrefix(mockRoot) else { return nil }
        let name = (path as NSString).lastPathComponent
        if let hit = all.flatMap({ s in s.files.map { ($0, s) } })
            .first(where: { $0.0.name == name }) {
            return hit.0.size
        }
        if name.hasPrefix("source.part") { return 314_572_800 }
        return 52_428_800
    }
}
