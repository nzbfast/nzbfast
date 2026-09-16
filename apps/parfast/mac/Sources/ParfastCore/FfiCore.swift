import Foundation
#if PARFAST_FFI
import CParfastFFI
#endif

/// `CoreClient` over the real engine, through `parfast_ffi.h`.
///
/// Everything above `CoreClient` is unchanged from the mock-first phase: the
/// views, the view models and the tests never learn which core they are on.
/// That was the point of plan 3.3, and this file is what it bought - the diff
/// that switched this app from a demo to a PAR2 tool is this file plus one
/// line in `App.swift`.
///
/// Compiled only when the staticlib is on disk (see Package.swift): a box with
/// no Rust toolchain still builds and tests the app on `MockCore`.
#if PARFAST_FFI
public final class FfiCore: CoreClient {

    private let session: OpaquePointer
    private let lock = NSLock()
    /// Retained for the lifetime of the session: the C side holds this
    /// pointer and calls through it from arbitrary threads.
    private final class WakeBox {
        var handler: (@Sendable () -> Void)?
    }
    private let wakeBox = WakeBox()

    public init?(settings: CoreSettings? = nil) {
        let json = settings.flatMap { try? CoreJSON.encodeToString($0) }
        let created: OpaquePointer? = json.withCStringOrNil { pf_session_new($0) }
        guard let created else { return nil }
        self.session = created

        // The callback carries no data and may fire on ANY thread; it means
        // "poll". The session never holds a lock across it, so calling
        // straight back in from the handler is allowed and is exactly what a
        // polling host does.
        let box = Unmanaged.passUnretained(wakeBox).toOpaque()
        pf_session_set_wake(session, { ctx in
            guard let ctx else { return }
            Unmanaged<WakeBox>.fromOpaque(ctx).takeUnretainedValue().handler?()
        }, box)
    }

    deinit {
        // Cancels every job and does NOT wait for the workers; the session's
        // memory goes when the last of them lets go. Nothing else may touch
        // the session concurrently with this.
        pf_session_set_wake(session, nil, nil)
        pf_session_free(session)
    }

    // MARK: - Plumbing

    /// Take ownership of a `char *` the core allocated and free it with the
    /// core's own allocator. Nothing else may free one.
    private func takeString(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer else { return nil }
        defer { pf_string_free(pointer) }
        return String(cString: pointer)
    }

    private func decode<T: Decodable>(_ type: T.Type,
                                      _ pointer: UnsafeMutablePointer<CChar>?) throws -> T {
        guard let json = takeString(pointer) else { throw lastErrorOrUnknown() }
        return try CoreJSON.decode(type, from: json)
    }

    /// PF_OK is 0 and everything else is a negative code with the detail in
    /// `pf_last_error`.
    private func check(_ code: Int32) throws {
        guard code != PF_OK else { return }
        throw lastErrorOrUnknown(code)
    }

    private func lastErrorOrUnknown(_ code: Int32 = 0) -> CoreError {
        if let json = takeString(pf_last_error(session)),
           let error = try? CoreJSON.decode(CoreError.self, from: json) {
            return error
        }
        return CoreError(code: "ffi_\(code)", message: "The engine refused the call.")
    }

    // MARK: - CoreClient

    public func setWake(_ handler: (@Sendable () -> Void)?) {
        lock.withLock { wakeBox.handler = handler }
    }

    public func submit(_ spec: JobSpec) throws -> Int64 {
        let json = try CoreJSON.encodeToString(spec)
        let id = json.withCString { pf_job_submit(session, $0) }
        guard id >= 1 else { throw lastErrorOrUnknown(Int32(clamping: id)) }
        return id
    }

    public func snapshot(job id: Int64) throws -> JobSnapshot {
        try decode(JobSnapshot.self, pf_job_snapshot(session, id))
    }

    public func queueSnapshot() throws -> QueueSnapshot {
        try decode(QueueSnapshot.self, pf_queue_snapshot(session))
    }

    public func cancel(job id: Int64) throws { try check(pf_job_cancel(session, id)) }
    public func pause(job id: Int64) throws { try check(pf_job_pause(session, id)) }
    public func resume(job id: Int64) throws { try check(pf_job_resume(session, id)) }
    public func remove(job id: Int64) throws { try check(pf_job_remove(session, id)) }

    public func runNext(job id: Int64) throws { try check(pf_job_run_next(session, id)) }

    public func setLowPriority(job id: Int64, _ on: Bool) throws {
        try check(pf_job_set_low_priority(session, id, on))
    }

    public func setQueuePaused(_ paused: Bool) throws {
        try check(pf_queue_set_paused(session, paused))
    }

    public func setQueueConcurrency(_ n: UInt32) throws {
        try check(pf_queue_set_concurrency(session, n))
    }

    public func setQueuePostAction(_ action: PostAction) throws {
        try check(action.rawValue.withCString { pf_queue_set_post_action(session, $0) })
    }

    /// The other half of `post_action_due`: the session reports that the
    /// queue drained, the HOST sleeps the machine, and then clears it.
    public func clearQueuePostAction() throws {
        try check(pf_queue_clear_post_action(session))
    }

    /// Persist the queue to a path this app names - the core does not know
    /// where a mac keeps application support. Answers the number of jobs
    /// loaded. A job that was running when the file was written comes back
    /// `interrupted`, which is what makes plan 5.5's state reachable.
    @discardableResult
    public func openQueueStore(at path: String) throws -> Int {
        let loaded = path.withCString { pf_queue_open_store(session, $0) }
        guard loaded >= 0 else { throw lastErrorOrUnknown(loaded) }
        return Int(loaded)
    }

    @discardableResult
    public func clearDigestCache() throws -> Int {
        let removed = pf_digest_cache_clear(session)
        guard removed >= 0 else { throw lastErrorOrUnknown(removed) }
        return Int(removed)
    }

    public func planPreview(_ spec: CreateSpec) throws -> PlanPreview {
        // The core takes either the whole job spec or the bare create object;
        // the bare one is what this pane has.
        let json = try CoreJSON.encodeToString(spec)
        return try decode(PlanPreview.self, json.withCString { pf_plan_preview(session, $0) })
    }

    public func capabilities() throws -> Capabilities {
        try decode(Capabilities.self, pf_capabilities(session))
    }

    public func settingsGet() throws -> CoreSettings {
        try decode(CoreSettings.self, pf_settings_get(session))
    }

    public func settingsSet(_ settings: CoreSettings) throws {
        let json = try CoreJSON.encodeToString(settings)
        try check(json.withCString { pf_settings_set(session, $0) })
    }

    public func lastError() -> CoreError? {
        guard let json = takeString(pf_last_error(session)) else { return nil }
        return try? CoreJSON.decode(CoreError.self, from: json)
    }
}

private extension Optional where Wrapped == String {
    /// `pf_session_new(NULL)` is the defaults, so a nil settings object has to
    /// reach C as a real NULL and not as an empty string.
    func withCStringOrNil<R>(_ body: (UnsafePointer<CChar>?) -> R) -> R {
        guard let self else { return body(nil) }
        return self.withCString { body($0) }
    }
}
#endif
