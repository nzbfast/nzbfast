import Foundation

// The FFI contract, plan section 4.5, as Swift types.
//
// These shapes are the DECOUPLING POINT of the whole GUI plan: chip A
// implements them in crates/parfast-ffi, this app codes against them before
// that crate exists. Chip A may ADD a field or an enum case and never rename
// or remove one, so every enum here decodes an unknown case rather than
// throwing - a core built tomorrow must not make this app refuse to run.
//
// Units, from the plan: every string UTF-8, every path absolute, every size
// bytes, every duration milliseconds, every JSON an object at the top level.

// MARK: - Enumerations that must survive an unknown case

/// An enum that decodes an unknown wire value into `.unknown(raw)` instead of
/// throwing. The UI treats an unknown the way it treats the least surprising
/// neighbour, and the raw string stays available for the log.
public protocol LenientRawEnum: RawRepresentable, Codable, Hashable where RawValue == String {
    static var unknownFallback: Self { get }
}

extension LenientRawEnum {
    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = Self(rawValue: raw) ?? Self.unknownFallback
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }
}

public enum JobKind: String, LenientRawEnum, CaseIterable {
    case create
    case verify
    case repairSet = "repair"
    case checksumCreate = "checksum_create"
    case checksumVerify = "checksum_verify"
    public static var unknownFallback: JobKind { .verify }
}

public enum JobState: String, LenientRawEnum {
    case queued, running, paused, done, failed, cancelled
    /// `interrupted` is the app's own state for a job that was running when
    /// the app quit (plan 5.5). The core never sends it.
    case interrupted
    public static var unknownFallback: JobState { .queued }

    public var isFinished: Bool {
        switch self {
        case .done, .failed, .cancelled, .interrupted: return true
        case .queued, .running, .paused: return false
        }
    }
}

public enum JobPhase: String, LenientRawEnum {
    case scanning, hashing, solving, writing, finishing
    public static var unknownFallback: JobPhase { .scanning }
}

public enum SurveyVerdict: String, LenientRawEnum {
    case verifying, complete, repairable, unrepairable, repaired, failed
    public static var unknownFallback: SurveyVerdict { .verifying }
}

public enum FileStatus: String, LenientRawEnum {
    case complete, damaged, missing, misnamed, extra, hashing, pending
    public static var unknownFallback: FileStatus { .pending }
}

public enum PostAction: String, LenientRawEnum, CaseIterable {
    case none, notify, sleep, shutdown
    public static var unknownFallback: PostAction { .none }
}

public enum PathMode: String, LenientRawEnum, CaseIterable {
    case basename, relative
    public static var unknownFallback: PathMode { .basename }
}

public enum UnicodePolicy: String, LenientRawEnum, CaseIterable {
    case auto, never, always
    public static var unknownFallback: UnicodePolicy { .auto }
}

public enum ChecksumFormat: String, LenientRawEnum, CaseIterable, Identifiable {
    public var id: String { rawValue }

    case sfv, md5, sha1, sha256
    public static var unknownFallback: ChecksumFormat { .sfv }

    public var display: String {
        switch self {
        case .sfv: return "SFV"
        case .md5: return "MD5"
        case .sha1: return "SHA-1"
        case .sha256: return "SHA-256"
        }
    }

    public var fileExtension: String { rawValue }
}

/// Block-map cell states. The numbers are the wire codes in
/// `survey.block_runs` and the indices into `T.blockPalette` - one order,
/// generated from the token file, so a palette edit cannot desynchronise
/// from the wire.
public enum BlockState: UInt8, Codable, CaseIterable {
    case pending = 0
    case present = 1
    case damaged = 2
    case missing = 3
    case misnamed = 4
    case hashing = 5
}

// MARK: - Job specifications

public struct SourceItem: Codable, Hashable, Identifiable {
    public var path: String
    public var recursive: Bool?

    public var id: String { path }

    public init(path: String, recursive: Bool? = nil) {
        self.path = path
        self.recursive = recursive
    }
}

/// `{"size":N}` or `{"count":N}` on the wire; one or the other, never both.
public enum BlockChoice: Codable, Hashable {
    case size(Int64)
    case count(Int)

    private enum Key: String, CodingKey { case size, count }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        if let s = try c.decodeIfPresent(Int64.self, forKey: .size) {
            self = .size(s)
        } else if let n = try c.decodeIfPresent(Int.self, forKey: .count) {
            self = .count(n)
        } else {
            throw DecodingError.dataCorruptedError(
                forKey: .size, in: c, debugDescription: "block needs size or count")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        switch self {
        case .size(let s): try c.encode(s, forKey: .size)
        case .count(let n): try c.encode(n, forKey: .count)
        }
    }
}

/// `{"percent":P}`, `{"count":N}` or `{"size":B}`.
public enum RecoveryChoice: Codable, Hashable {
    case percent(Double)
    case count(Int)
    case size(Int64)

    private enum Key: String, CodingKey { case percent, count, size }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        if let p = try c.decodeIfPresent(Double.self, forKey: .percent) {
            self = .percent(p)
        } else if let n = try c.decodeIfPresent(Int.self, forKey: .count) {
            self = .count(n)
        } else if let b = try c.decodeIfPresent(Int64.self, forKey: .size) {
            self = .size(b)
        } else {
            throw DecodingError.dataCorruptedError(
                forKey: .percent, in: c, debugDescription: "recovery needs percent, count or size")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        switch self {
        case .percent(let p): try c.encode(p, forKey: .percent)
        case .count(let n): try c.encode(n, forKey: .count)
        case .size(let b): try c.encode(b, forKey: .size)
        }
    }
}

/// The volume scheme union from 4.5. `pow2_limit`'s `limit` is either the
/// string "largest_source" or an object with `blocks` or `size`, which is why
/// this is hand-coded rather than derived.
public enum VolumeScheme: Codable, Hashable {
    case none
    case uniformFiles(Int)
    case uniformBlocksPerFile(Int)
    case uniformFileSize(Int64)
    case pow2
    case pow2LimitLargestSource
    case pow2LimitBlocks(Int)
    case pow2LimitSize(Int64)

    private enum Key: String, CodingKey {
        case scheme, files, blocks_per_file, file_size, limit
    }

    private enum LimitKey: String, CodingKey { case blocks, size }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        let scheme = try c.decode(String.self, forKey: .scheme)
        switch scheme {
        case "none":
            self = .none
        case "uniform":
            if let f = try c.decodeIfPresent(Int.self, forKey: .files) {
                self = .uniformFiles(f)
            } else if let b = try c.decodeIfPresent(Int.self, forKey: .blocks_per_file) {
                self = .uniformBlocksPerFile(b)
            } else if let s = try c.decodeIfPresent(Int64.self, forKey: .file_size) {
                self = .uniformFileSize(s)
            } else {
                self = .uniformFiles(1)
            }
        case "pow2":
            self = .pow2
        case "pow2_limit":
            if let s = try? c.decode(String.self, forKey: .limit), s == "largest_source" {
                self = .pow2LimitLargestSource
            } else {
                let l = try c.nestedContainer(keyedBy: LimitKey.self, forKey: .limit)
                if let b = try l.decodeIfPresent(Int.self, forKey: .blocks) {
                    self = .pow2LimitBlocks(b)
                } else {
                    self = .pow2LimitSize(try l.decode(Int64.self, forKey: .size))
                }
            }
        default:
            self = .none
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        switch self {
        case .none:
            try c.encode("none", forKey: .scheme)
        case .uniformFiles(let f):
            try c.encode("uniform", forKey: .scheme); try c.encode(f, forKey: .files)
        case .uniformBlocksPerFile(let b):
            try c.encode("uniform", forKey: .scheme); try c.encode(b, forKey: .blocks_per_file)
        case .uniformFileSize(let s):
            try c.encode("uniform", forKey: .scheme); try c.encode(s, forKey: .file_size)
        case .pow2:
            try c.encode("pow2", forKey: .scheme)
        case .pow2LimitLargestSource:
            try c.encode("pow2_limit", forKey: .scheme)
            try c.encode("largest_source", forKey: .limit)
        case .pow2LimitBlocks(let b):
            try c.encode("pow2_limit", forKey: .scheme)
            var l = c.nestedContainer(keyedBy: LimitKey.self, forKey: .limit)
            try l.encode(b, forKey: .blocks)
        case .pow2LimitSize(let s):
            try c.encode("pow2_limit", forKey: .scheme)
            var l = c.nestedContainer(keyedBy: LimitKey.self, forKey: .limit)
            try l.encode(s, forKey: .size)
        }
    }

    /// Which of the four popup rows this scheme sits on, so the UI can keep
    /// the sub-panel and the popup in step without a second enum.
    public enum Family: String, CaseIterable, Hashable { case none, uniform, pow2, pow2Limit }

    public var family: Family {
        switch self {
        case .none: return .none
        case .uniformFiles, .uniformBlocksPerFile, .uniformFileSize: return .uniform
        case .pow2: return .pow2
        case .pow2LimitLargestSource, .pow2LimitBlocks, .pow2LimitSize: return .pow2Limit
        }
    }
}

public struct PerfSpec: Codable, Hashable {
    public var threads: Int?
    public var memory_mb: Int?
    public var low_priority: Bool

    public init(threads: Int? = nil, memory_mb: Int? = nil, low_priority: Bool = false) {
        self.threads = threads
        self.memory_mb = memory_mb
        self.low_priority = low_priority
    }
}

public struct CreateSpec: Codable, Hashable {
    public var sources: [SourceItem]
    public var path_mode: PathMode
    public var base_path: String?
    public var block: BlockChoice
    public var recovery: RecoveryChoice
    public var output: String
    public var volumes: VolumeScheme
    public var first_recovery_block: Int
    public var comment: String
    public var overwrite: Bool
    public var std_naming: Bool
    public var unicode: UnicodePolicy
    public var perf: PerfSpec

    public init(
        sources: [SourceItem] = [],
        path_mode: PathMode = .basename,
        base_path: String? = nil,
        block: BlockChoice = .count(2000),
        recovery: RecoveryChoice = .percent(10),
        output: String = "",
        volumes: VolumeScheme = .pow2,
        first_recovery_block: Int = 0,
        comment: String = "",
        overwrite: Bool = false,
        std_naming: Bool = false,
        unicode: UnicodePolicy = .auto,
        perf: PerfSpec = PerfSpec()
    ) {
        self.sources = sources
        self.path_mode = path_mode
        self.base_path = base_path
        self.block = block
        self.recovery = recovery
        self.output = output
        self.volumes = volumes
        self.first_recovery_block = first_recovery_block
        self.comment = comment
        self.overwrite = overwrite
        self.std_naming = std_naming
        self.unicode = unicode
        self.perf = perf
    }
}

public struct VerifyOptions: Codable, Hashable {
    public var rename_only: Bool
    public var data_skipping: Bool
    public var skip_leaway: Int
    public var fast_solver: Bool?
    public var threads: Int?

    public init(
        rename_only: Bool = false,
        data_skipping: Bool = false,
        skip_leaway: Int = 64,
        fast_solver: Bool? = nil,
        threads: Int? = nil
    ) {
        self.rename_only = rename_only
        self.data_skipping = data_skipping
        self.skip_leaway = skip_leaway
        self.fast_solver = fast_solver
        self.threads = threads
    }
}

public struct VerifySpec: Codable, Hashable {
    public var par2: String
    public var extra_dirs: [String]
    public var options: VerifyOptions

    public init(par2: String, extra_dirs: [String] = [], options: VerifyOptions = VerifyOptions()) {
        self.par2 = par2
        self.extra_dirs = extra_dirs
        self.options = options
    }
}

public struct RepairSpec: Codable, Hashable {
    public var par2: String
    public var extra_dirs: [String]
    public var options: VerifyOptions
    public var purge: Bool
    public var keep_damaged: Bool
    /// Files the user excluded from repair by the row context menu (5.2).
    public var exclude: [String]

    public init(
        par2: String,
        extra_dirs: [String] = [],
        options: VerifyOptions = VerifyOptions(),
        purge: Bool = false,
        keep_damaged: Bool = false,
        exclude: [String] = []
    ) {
        self.par2 = par2
        self.extra_dirs = extra_dirs
        self.options = options
        self.purge = purge
        self.keep_damaged = keep_damaged
        self.exclude = exclude
    }
}

public struct ChecksumCreateSpec: Codable, Hashable {
    public var sources: [SourceItem]
    public var format: ChecksumFormat
    public var output: String
    public var relative: Bool

    public init(sources: [SourceItem] = [], format: ChecksumFormat = .sfv,
                output: String = "", relative: Bool = true) {
        self.sources = sources
        self.format = format
        self.output = output
        self.relative = relative
    }
}

public struct ChecksumVerifySpec: Codable, Hashable {
    public var file: String
    public init(file: String) { self.file = file }
}

/// The tagged union `pf_job_submit` takes. Encoded exactly as 4.5 shows it:
/// a `kind` plus ONE payload key named for that kind.
public enum JobSpec: Codable, Hashable {
    case create(CreateSpec)
    case verify(VerifySpec)
    case repairSet(RepairSpec)
    case checksumCreate(ChecksumCreateSpec)
    case checksumVerify(ChecksumVerifySpec)

    private enum Key: String, CodingKey {
        case kind, create, verify
        case repairSet = "repair"
        case checksumCreate = "checksum_create"
        case checksumVerify = "checksum_verify"
    }

    public var kind: JobKind {
        switch self {
        case .create: return .create
        case .verify: return .verify
        case .repairSet: return .repairSet
        case .checksumCreate: return .checksumCreate
        case .checksumVerify: return .checksumVerify
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        switch try c.decode(JobKind.self, forKey: .kind) {
        case .create: self = .create(try c.decode(CreateSpec.self, forKey: .create))
        case .verify: self = .verify(try c.decode(VerifySpec.self, forKey: .verify))
        case .repairSet: self = .repairSet(try c.decode(RepairSpec.self, forKey: .repairSet))
        case .checksumCreate:
            self = .checksumCreate(try c.decode(ChecksumCreateSpec.self, forKey: .checksumCreate))
        case .checksumVerify:
            self = .checksumVerify(try c.decode(ChecksumVerifySpec.self, forKey: .checksumVerify))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(kind, forKey: .kind)
        switch self {
        case .create(let s): try c.encode(s, forKey: .create)
        case .verify(let s): try c.encode(s, forKey: .verify)
        case .repairSet(let s): try c.encode(s, forKey: .repairSet)
        case .checksumCreate(let s): try c.encode(s, forKey: .checksumCreate)
        case .checksumVerify(let s): try c.encode(s, forKey: .checksumVerify)
        }
    }
}

// MARK: - Snapshots

public struct SurveyFile: Codable, Hashable, Identifiable {
    public var name: String
    public var size: Int64
    public var status: FileStatus
    public var blocks_ok: Int
    public var blocks_total: Int
    public var found_as: String?
    public var progress: Double?

    public var id: String { name }

    public init(name: String, size: Int64, status: FileStatus, blocks_ok: Int,
                blocks_total: Int, found_as: String? = nil, progress: Double? = nil) {
        self.name = name
        self.size = size
        self.status = status
        self.blocks_ok = blocks_ok
        self.blocks_total = blocks_total
        self.found_as = found_as
        self.progress = progress
    }
}

public struct Survey: Codable, Hashable {
    public var set_name: String
    public var folder: String
    public var block_size: Int64
    public var source_blocks: Int
    public var recovery_available: Int
    public var recovery_needed: Int
    public var verdict: SurveyVerdict
    public var files: [SurveyFile]
    /// ADDED by the core: the padding percentage is unreadable without them.
    public var source_bytes: Int64?
    public var source_files: Int?
    /// Run-length encoded over source blocks in set order: pairs of
    /// [state code, run length]. The block map draws this and nothing else.
    public var block_runs: [[Int]]

    public init(set_name: String, folder: String, block_size: Int64, source_blocks: Int,
                recovery_available: Int, recovery_needed: Int, verdict: SurveyVerdict,
                files: [SurveyFile], block_runs: [[Int]],
                source_bytes: Int64? = nil, source_files: Int? = nil) {
        self.set_name = set_name
        self.folder = folder
        self.block_size = block_size
        self.source_blocks = source_blocks
        self.recovery_available = recovery_available
        self.recovery_needed = recovery_needed
        self.verdict = verdict
        self.files = files
        self.block_runs = block_runs
        self.source_bytes = source_bytes
        self.source_files = source_files
    }

    /// The run-length array expanded, capped so a ten-million-block set
    /// cannot allocate the app to death. The map merges above
    /// `T.sizeBlockMergeThreshold` anyway, so the cap is never reached by a
    /// drawing path - it is here for the text summary and the tests.
    public func expandedStates(cap: Int = 2_000_000) -> [BlockState] {
        var out: [BlockState] = []
        out.reserveCapacity(min(source_blocks, cap))
        for run in block_runs where run.count == 2 {
            let state = BlockState(rawValue: UInt8(clamping: run[0])) ?? .pending
            let length = min(max(run[1], 0), cap - out.count)
            if length <= 0 { break }
            out.append(contentsOf: repeatElement(state, count: length))
        }
        return out
    }

    /// Files the set describes that are sitting under a different name.
    ///
    /// Kept as a plain accessor. It was briefly load-bearing: between
    /// 12 Sep 06:20Z and the fix later that morning the core returned
    /// `verdict: complete` alongside `exit_code: 1` on a renamed member, and
    /// the pill read "Complete - no repair needed" over a set `parfast v`
    /// said needed repairing. The workaround read THESE rows rather than
    /// re-deriving the verdict, which API.md forbids and which would have
    /// hidden the defect. The core now books a misnamed member's blocks as
    /// owed, so that state is unreachable and the workaround is gone.
    public var misnamedFiles: [SurveyFile] {
        files.filter { $0.status == .misnamed }
    }

    public func counts() -> [BlockState: Int] {
        var out: [BlockState: Int] = [:]
        for run in block_runs where run.count == 2 {
            guard let state = BlockState(rawValue: UInt8(clamping: run[0])) else { continue }
            out[state, default: 0] += max(run[1], 0)
        }
        return out
    }
}

public struct WrittenFile: Codable, Hashable, Identifiable {
    public var name: String
    public var size: Int64
    public var id: String { name }
    public init(name: String, size: Int64) {
        self.name = name
        self.size = size
    }
}

public struct ChecksumResult: Codable, Hashable {
    public var ok: Int
    public var mismatch: Int
    public var missing: Int
    /// One row per entry, in the file's own order. Landed 12 Sep 2026
    /// (`7fdfcece16`) NESTED inside the checksum result, not beside it - the
    /// Windows lane guessed `result.checksum_entries` at the result level and
    /// was wrong, so the nesting is worth stating.
    ///
    /// Empty for a checksum CREATE, which has nothing to compare, and empty
    /// while a verify is still running. The screen says so rather than
    /// drawing a blank table.
    public var entries: [ChecksumEntry]?

    public init(ok: Int, mismatch: Int, missing: Int, entries: [ChecksumEntry]? = nil) {
        self.ok = ok
        self.mismatch = mismatch
        self.missing = missing
        self.entries = entries
    }
}

/// One row of the Checksums verify table: `parfast_session::checksum::Row`.
public struct ChecksumEntry: Codable, Hashable, Identifiable {
    public enum Status: String, LenientRawEnum {
        case ok, mismatch, missing
        /// The core has no `pending`; it is this app's own state for a row it
        /// has not been told about yet, which is every row while a verify is
        /// still running.
        case pending
        public static var unknownFallback: Status { .pending }
    }

    public var name: String
    public var expected: String
    /// What the file on disk actually came to. Empty when it is not there.
    public var actual: String
    public var status: Status
    public var id: String { name }

    public init(name: String, expected: String, actual: String = "", status: Status) {
        self.name = name
        self.expected = expected
        self.actual = actual
        self.status = status
    }
}

public struct JobResult: Codable, Hashable {
    public var repaired_files: Int?
    public var purged: Bool?
    public var written: [WrittenFile]?
    public var checksum: ChecksumResult?
    /// ADDED by the core: the exit code the equivalent `parfast` line would
    /// have returned. The CLI's dialect is the one thing a script user already
    /// knows, so hiding it makes the GUI unreproducible from a terminal.
    public var exit_code: Int?

    public init(repaired_files: Int? = nil, purged: Bool? = nil,
                written: [WrittenFile]? = nil, checksum: ChecksumResult? = nil) {
        self.repaired_files = repaired_files
        self.purged = purged
        self.written = written
        self.checksum = checksum
    }
}

public struct CoreError: Codable, Hashable, Error {
    public var code: String
    public var message: String
    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }
}

public struct JobSnapshot: Codable, Hashable, Identifiable {
    public var id: Int64
    public var kind: JobKind
    public var state: JobState
    public var phase: JobPhase?
    public var phase_text: String
    public var progress: Double
    public var elapsed_ms: Int64
    public var eta_ms: Int64?
    public var rate_bytes_per_s: Int64?
    public var low_priority: Bool
    public var added_at: String
    public var log_tail: [String]
    public var survey: Survey?
    public var result: JobResult?
    public var error: CoreError?
    /// ADDED by the core: the `parfast` command line equivalent to this job,
    /// for the Advanced pane's "show the equivalent command". Empty for the
    /// two checksum kinds, which have no CLI equivalent.
    public var command: String?
    /// The title the UI puts on the job: a set name, an output name, a file.
    /// Derived by the core from the spec; the app never has to re-derive it.
    public var title: String?

    public init(id: Int64, kind: JobKind, state: JobState, phase: JobPhase? = nil,
                phase_text: String = "", progress: Double = 0, elapsed_ms: Int64 = 0,
                eta_ms: Int64? = nil, rate_bytes_per_s: Int64? = nil,
                low_priority: Bool = false, added_at: String = "",
                log_tail: [String] = [], survey: Survey? = nil, result: JobResult? = nil,
                error: CoreError? = nil, command: String? = nil, title: String? = nil) {
        self.id = id
        self.kind = kind
        self.state = state
        self.phase = phase
        self.phase_text = phase_text
        self.progress = progress
        self.elapsed_ms = elapsed_ms
        self.eta_ms = eta_ms
        self.rate_bytes_per_s = rate_bytes_per_s
        self.low_priority = low_priority
        self.added_at = added_at
        self.log_tail = log_tail
        self.survey = survey
        self.result = result
        self.error = error
        self.command = command
        self.title = title
    }
}

public struct QueueSnapshot: Codable, Hashable {
    public var paused: Bool
    public var concurrency: Int
    public var post_action: PostAction
    /// ADDED by the core: the queue has drained and the action has not been
    /// carried out. The session REPORTS it; the HOST performs it, because
    /// sleeping a machine is a platform call and a decision a human must be
    /// able to stop. Clear it with `clearQueuePostAction()`.
    public var post_action_due: Bool
    public var jobs: [JobSnapshot]

    public init(paused: Bool = false, concurrency: Int = 1,
                post_action: PostAction = .none, post_action_due: Bool = false,
                jobs: [JobSnapshot] = []) {
        self.paused = paused
        self.concurrency = concurrency
        self.post_action = post_action
        self.post_action_due = post_action_due
        self.jobs = jobs
    }

    public var running: Int { jobs.filter { $0.state == .running }.count }
    public var waiting: Int { jobs.filter { $0.state == .queued || $0.state == .paused }.count }
}

// MARK: - Plan preview, capabilities, settings

public struct PreviewFile: Codable, Hashable, Identifiable {
    public var name: String
    public var size: Int64
    public var blocks: Int
    public var efficiency_pct: Double
    public var id: String { name }

    public init(name: String, size: Int64, blocks: Int, efficiency_pct: Double) {
        self.name = name
        self.size = size
        self.blocks = blocks
        self.efficiency_pct = efficiency_pct
    }
}

public struct PlanPreview: Codable, Hashable {
    public var block_size: Int64
    public var block_count: Int
    public var padding_bytes: Int64
    public var padding_pct: Double
    public var efficiency_pct: Double
    public var recovery_blocks: Int
    public var recovery_percent: Double
    public var recovery_bytes: Int64
    public var total_bytes: Int64
    public var files: [PreviewFile]
    public var command: String
    public var warnings: [String]
    /// ADDED by the core, for the same reason as the survey's pair.
    public var source_bytes: Int64?
    public var source_files: Int?

    public init(block_size: Int64, block_count: Int, padding_bytes: Int64, padding_pct: Double,
                efficiency_pct: Double, recovery_blocks: Int, recovery_percent: Double,
                recovery_bytes: Int64, total_bytes: Int64, files: [PreviewFile],
                command: String, warnings: [String],
                source_bytes: Int64? = nil, source_files: Int? = nil) {
        self.block_size = block_size
        self.block_count = block_count
        self.padding_bytes = padding_bytes
        self.padding_pct = padding_pct
        self.efficiency_pct = efficiency_pct
        self.recovery_blocks = recovery_blocks
        self.recovery_percent = recovery_percent
        self.recovery_bytes = recovery_bytes
        self.total_bytes = total_bytes
        self.files = files
        self.command = command
        self.warnings = warnings
        self.source_bytes = source_bytes
        self.source_files = source_files
    }
}

/// What this build of the core can do. A UI HIDES any control whose
/// capability is false - that is the mechanism that lets this app ship
/// against a core whose engine switches are not all built yet (4.5).
public struct Capabilities: Codable, Hashable {
    public var version: String
    public var engine: String
    public var cpu: String
    public var kernel: String
    public var std_naming: Bool
    public var unicode_policy: Bool
    public var data_skipping: Bool
    public var fast_solver: Bool
    public var pause: Bool
    public var low_priority: Bool
    /// ADDED by the core, and TRUE in the engine since 12 Sep 2026: par2gen
    /// writes the spec's comment packet, so the Comment field is live rather
    /// than hidden. The `false` here is the DECODING default - what an older
    /// core that does not send the key gets - and never a statement about
    /// today's engine.
    public var comment: Bool = false
    /// ADDED by the core, TRUE since 12 Sep 2026: an explicit per-volume
    /// ceiling in blocks or bytes reaches the engine through parfast's own
    /// `--volume-blocks=N`. Against a core that answers false, only
    /// `limit: "largest_source"` is offered. Decoding default, as above.
    public var volume_limit_explicit: Bool = false
    /// ADDED by the core, ALL THREE TRUE since 12 Sep 2026 - the repair half
    /// first, then the create's in `b33b56199b`. They are not per-job-kind
    /// keys; `apps/parfast/crates/parfast-ffi/API.md`'s per-kind table is what
    /// says where each control actually lands, and it is the thing to read.
    ///
    /// `pause_in_fold` is known to OVER-CLAIM for the create kind, measured
    /// rather than reasoned: the first run of the mac app against this engine
    /// took a create to Paused and it ran to completion anyway, writing the
    /// whole set, because the shipped `stripe_first` fold holds no park point
    /// at all. The finding and its CPU accounting are in
    /// the maintainer notes. The fix
    /// belongs in the engine's park sites or in the capability's honesty -
    /// NEVER in a host hard-coding the job kind again, which is the thing
    /// `ProgressSheet.canPause` had just stopped doing.
    ///
    /// Decoding defaults, as above: a core that does not send these is an OLD
    /// core, and a host must then not promise that Cancel is instant.
    public var pause_in_fold: Bool = false
    public var cancel_in_fold: Bool = false
    public var progress_in_fold: Bool = false

    public init(version: String, engine: String, cpu: String, kernel: String,
                std_naming: Bool, unicode_policy: Bool, data_skipping: Bool,
                fast_solver: Bool, pause: Bool, low_priority: Bool,
                comment: Bool = false, volume_limit_explicit: Bool = false,
                pause_in_fold: Bool = false, cancel_in_fold: Bool = false,
                progress_in_fold: Bool = false) {
        self.version = version
        self.engine = engine
        self.cpu = cpu
        self.kernel = kernel
        self.std_naming = std_naming
        self.unicode_policy = unicode_policy
        self.data_skipping = data_skipping
        self.fast_solver = fast_solver
        self.pause = pause
        self.low_priority = low_priority
        self.comment = comment
        self.volume_limit_explicit = volume_limit_explicit
        self.pause_in_fold = pause_in_fold
        self.cancel_in_fold = cancel_in_fold
        self.progress_in_fold = progress_in_fold
    }
}

/// Section 5.6 and `parfast_session::settings`. GROUPED, not flat: the plan
/// sketched one object and the core landed five groups plus three scalars, so
/// this follows the core. Defaults are the CORE's (`pf_settings_get` on a
/// fresh session), and the values here are only what a missing key decodes to
/// - every group is `#[serde(default)]` on the way in and unknown keys are
/// ignored, so a host built against an older core is never refused.
public struct CoreSettings: Codable, Hashable {

    public enum OpenAction: String, LenientRawEnum, CaseIterable {
        case verify
        case verifyThenRepair = "verify_then_repair"
        public static var unknownFallback: OpenAction { .verify }
    }

    public enum BlockAllocation: String, LenientRawEnum, CaseIterable {
        case size, count
        public static var unknownFallback: BlockAllocation { .count }
    }

    public enum RecoveryAllocation: String, LenientRawEnum, CaseIterable {
        case percent, count, size
        public static var unknownFallback: RecoveryAllocation { .percent }
    }

    public struct General: Codable, Hashable {
        public var open_par2: OpenAction = .verify
        public var purge_after_repair = false
        /// ON by the core's default, and deliberately: the `.1` copy is the
        /// only thing between a wrong repair and a lost file.
        public var keep_damaged_copies = true
        public var notifications = true
        public var auto_close_progress = false
        public var language = "en"
        public init() {}
    }

    public struct CreateDefaults: Codable, Hashable {
        public var block_allocation: BlockAllocation = .count
        public var block_count: Int = 2000
        public var block_size: Int64 = 1_048_576
        public var recovery_allocation: RecoveryAllocation = .percent
        public var recovery_percent: Double = 10
        public var recovery_count: Int = 200
        public var recovery_size: Int64 = 104_857_600
        public var scheme = "pow2"
        public var std_naming = false
        public var unicode = "auto"
        public var overwrite = false
        public init() {}
    }

    public struct Performance: Codable, Hashable {
        public var threads: Int?
        public var memory_mb: Int?
        public var fast_solver = true
        public var low_priority = false
        public init() {}
    }

    public struct Integration: Codable, Hashable {
        public var handle_par2 = true
        public var handle_sfv = false
        public var handle_md5 = false
        public var handle_sha256 = false
        public var shell_menu = true
        public init() {}
    }

    public struct Advanced: Codable, Hashable {
        public var show_command = true
        /// `verbose - quiet`, exactly as the two counters are seen on the
        /// command line: 0 is the reference's default, -2 is silence.
        public var log_level: Int = 0
        public var log_folder: String?
        public init() {}
    }

    public var general = General()
    public var create = CreateDefaults()
    public var performance = Performance()
    public var integration = Integration()
    public var advanced = Advanced()
    public var concurrency: Int = 1
    public var post_queue_action: PostAction = .none
    public var log_tail_lines: Int = 500

    public init() {}
}
