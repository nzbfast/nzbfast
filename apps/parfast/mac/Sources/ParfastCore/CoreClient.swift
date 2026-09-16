import Foundation

/// The session, one method per C function in `parfast_ffi.h` (plan 4.5).
///
/// One method per function on purpose: when `FfiCore` lands beside `MockCore`
/// the diff is a new file and nothing else, and a signature that drifts in the
/// header is a compile error in ONE place rather than a behaviour change
/// spread over the views.
///
/// Threading: the core is thread-safe and may be called from any thread. The
/// wake callback fires whenever a snapshot would differ, at most ~20 times a
/// second, from an arbitrary thread; `CoreObserver` marshals it to the main
/// actor and polls. Implementations must therefore be safe to call
/// re-entrantly from the wake handler's thread.
public protocol CoreClient: AnyObject {
    /// `pf_session_set_wake`. The callback carries no data: it means "poll".
    func setWake(_ handler: (@Sendable () -> Void)?)

    /// `pf_job_submit`. Returns the job id.
    func submit(_ spec: JobSpec) throws -> Int64

    /// `pf_job_snapshot`.
    func snapshot(job id: Int64) throws -> JobSnapshot

    /// `pf_queue_snapshot`.
    func queueSnapshot() throws -> QueueSnapshot

    /// `pf_job_cancel` / `pause` / `resume` / `remove`.
    func cancel(job id: Int64) throws
    func pause(job id: Int64) throws
    func resume(job id: Int64) throws
    func remove(job id: Int64) throws

    /// `pf_job_run_next`: take this job next, whatever its place in the
    /// queue. A flag on the entry rather than a reordered table, so iteration
    /// stays submission order and the display and the scheduler read one rule.
    ///
    /// This is NOT "resume it": resuming only lets the scheduler reach it in
    /// its own turn, and raising the concurrency would start everything queued
    /// ahead of it too. Neither is what the control promises.
    func runNext(job id: Int64) throws

    /// `pf_job_set_low_priority`.
    func setLowPriority(job id: Int64, _ on: Bool) throws

    /// `pf_queue_clear_post_action`. The core REPORTS that the queue drained
    /// and the host PERFORMS the action, because sleeping a machine is a
    /// platform call. The host must clear it whether or not it managed the
    /// action: left uncleared it falls due again on every snapshot, which at
    /// 20 Hz means a shutdown attempt twenty times a second.
    func clearQueuePostAction() throws

    /// `pf_queue_set_paused` / `set_concurrency` / `set_post_action`.
    func setQueuePaused(_ paused: Bool) throws
    func setQueueConcurrency(_ n: UInt32) throws
    func setQueuePostAction(_ action: PostAction) throws

    /// `pf_plan_preview`. No I/O beyond stat, so the Create screen can call it
    /// on every keystroke.
    func planPreview(_ spec: CreateSpec) throws -> PlanPreview

    /// `pf_capabilities`.
    func capabilities() throws -> Capabilities

    /// `pf_settings_get` / `pf_settings_set`.
    func settingsGet() throws -> CoreSettings
    func settingsSet(_ settings: CoreSettings) throws

    /// `pf_digest_cache_clear`: "Clear remembered checksums". Answers how many
    /// records went. Safe while a job runs, and leaves the setting alone.
    @discardableResult
    func clearDigestCache() throws -> Int

    /// `pf_last_error`, for the log drawer when a call returned a bare code.
    func lastError() -> CoreError?
}

/// Errors this app raises before or around a core call. A failure that came
/// FROM the core is a `CoreError` and keeps the core's own code and wording.
public enum ClientError: Error, LocalizedError {
    case noSuchJob(Int64)
    case notRunning(Int64)
    case badSpec(String)

    public var errorDescription: String? {
        switch self {
        case .noSuchJob(let id): return "No job with id \(id)"
        case .notRunning(let id): return "Job \(id) is not running"
        case .badSpec(let why): return why
        }
    }
}

/// The JSON shape both implementations speak, kept in one place so the mock
/// and the FFI cannot disagree about dates, keys or number formats.
public enum CoreJSON {
    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    public static let decoder = JSONDecoder()

    public static func encodeToString<T: Encodable>(_ value: T) throws -> String {
        String(decoding: try encoder.encode(value), as: UTF8.self)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from json: String) throws -> T {
        try decoder.decode(type, from: Data(json.utf8))
    }

    /// ISO-8601 with a Z, the `added_at` format in 4.5.
    public static func timestamp(_ date: Date = Date()) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: date)
    }
}
