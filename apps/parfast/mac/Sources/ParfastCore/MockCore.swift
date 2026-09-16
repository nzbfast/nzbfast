import Foundation

/// A `CoreClient` that plays the scripted scenarios in `MockScenarios.swift`
/// with no engine, no PAR2 files and no disk.
///
/// This is what lets the UI lane start the same minute as the engine lane
/// (plan 3.3 and D4), and it stays in the tree afterwards as the UI test
/// harness: every screen, state, animation and error path in section 5 is
/// reachable from here, deterministically, at an adjustable speed.
///
/// It is deliberately a full little scheduler rather than a table of canned
/// snapshots. A canned snapshot cannot show a queue draining, a pause taking
/// effect mid-phase, a rate settling, or a block map filling left to right -
/// which are exactly the behaviours the design spec is about.
///
/// Threading matches the real contract: every entry point takes the lock, the
/// tick runs on its own queue, and the wake handler fires from that queue.
public final class MockCore: CoreClient {

    // MARK: - Knobs

    /// 1.0 plays a scenario at its nominal duration. The demo menu raises it
    /// to take screenshots without waiting, and the tests raise it far higher
    /// to run a whole job inside a few ticks.
    public var speed: Double {
        get { lock.withLock { _speed } }
        set { lock.withLock { _speed = max(0.01, newValue) } }
    }

    /// Ticks per simulated second. 20 Hz is the rate the real core's wake
    /// callback is capped at, so the UI sees the same update cadence.
    public static let tickHz: Double = 20

    // MARK: - State

    private final class MockJob {
        let id: Int64
        let spec: JobSpec
        let addedAt: String
        var state: JobState = .queued
        var lowPriority: Bool
        var elapsed: Double = 0
        var duration: Double
        var log: [String] = []
        var loggedMarks: Set<String> = []
        var title: String
        var scenario: MockScenario?
        var preview: PlanPreview?
        var checksumEntries: [ChecksumEntry] = []
        var totalBytes: Int64
        var result: JobResult?
        var error: CoreError?
        /// Files the user excluded from repair, so the repair leaves them alone.
        var excluded: Set<String> = []
        /// Taken ahead of its turn by `pf_job_run_next`.
        var runNext = false

        init(id: Int64, spec: JobSpec, title: String, duration: Double,
             totalBytes: Int64, lowPriority: Bool) {
            self.id = id
            self.spec = spec
            self.title = title
            self.duration = duration
            self.totalBytes = totalBytes
            self.lowPriority = lowPriority
            self.addedAt = CoreJSON.timestamp()
        }
    }

    private let lock = NSLock()
    private var _speed: Double = 1
    private var jobs: [MockJob] = []
    private var nextId: Int64 = 1
    private var queuePaused = false
    private var concurrency = 1
    private var postAction: PostAction = .none
    private var postActionDue = false
    private var settings = CoreSettings()
    private var _lastError: CoreError?
    private var wake: (@Sendable () -> Void)?
    private var timer: DispatchSourceTimer?
    private let tickQueue = DispatchQueue(label: "com.nzbfast.parfast.mock")

    /// Sizes for paths that are not on this disk, so the Create screen has
    /// arithmetic to do in a demo. A real path is stat'd.
    public var syntheticSizes: (String) -> Int64? = MockScenario.mockSize(forPath:)

    public init(speed: Double = 1) {
        _speed = speed
        start()
    }

    deinit { timer?.cancel() }

    private func start() {
        let t = DispatchSource.makeTimerSource(queue: tickQueue)
        t.schedule(deadline: .now(), repeating: 1.0 / Self.tickHz)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    // MARK: - CoreClient

    public func setWake(_ handler: (@Sendable () -> Void)?) {
        lock.withLock { wake = handler }
    }

    public func submit(_ spec: JobSpec) throws -> Int64 {
        let job = try makeJob(spec)
        lock.withLock {
            jobs.append(job)
            scheduleLocked()
        }
        notify()
        return job.id
    }

    public func snapshot(job id: Int64) throws -> JobSnapshot {
        try lock.withLock {
            guard let job = jobs.first(where: { $0.id == id }) else { throw ClientError.noSuchJob(id) }
            return snapshotLocked(job)
        }
    }

    public func queueSnapshot() throws -> QueueSnapshot {
        lock.withLock {
            QueueSnapshot(paused: queuePaused, concurrency: concurrency,
                          post_action: postAction, post_action_due: postActionDue,
                          jobs: jobs.map(snapshotLocked))
        }
    }

    public func cancel(job id: Int64) throws {
        try mutate(id) { job in
            guard !job.state.isFinished else { return }
            job.state = .cancelled
            job.error = CoreError(code: "cancelled", message: "Stopped before it finished.")
            job.log.append("Cancelled.")
        }
    }

    public func pause(job id: Int64) throws {
        try mutate(id) { job in
            guard job.state == .running else { throw ClientError.notRunning(id) }
            job.state = .paused
            job.log.append("Paused.")
        }
    }

    public func resume(job id: Int64) throws {
        try mutate(id) { job in
            guard job.state == .paused else { return }
            job.state = .running
            job.log.append("Resumed.")
        }
    }

    public func remove(job id: Int64) throws {
        try lock.withLock {
            guard let job = jobs.first(where: { $0.id == id }) else { throw ClientError.noSuchJob(id) }
            guard job.state.isFinished else {
                let e = CoreError(code: "job_running", message: "A running job cannot be removed.")
                _lastError = e
                throw e
            }
            jobs.removeAll { $0.id == id }
        }
        notify()
    }

    /// The mock's queue is a list, so "next" is a flag read by the scheduler
    /// rather than a move - the same shape as the core's, so the two cannot
    /// disagree about what iteration order means.
    public func runNext(job id: Int64) throws {
        try mutate(id) { job in
            guard !job.state.isFinished else { return }
            job.runNext = true
        }
    }

    public func setLowPriority(job id: Int64, _ on: Bool) throws {
        try mutate(id) { job in
            job.lowPriority = on
            // A low-priority job really does run slower, so the checkbox has
            // a visible effect in a demo as well as in production.
            job.duration *= on ? 1.6 : 1 / 1.6
            job.log.append(on ? "Dropped to a low priority." : "Back to a normal priority.")
        }
    }

    public func setQueuePaused(_ paused: Bool) throws {
        lock.withLock {
            queuePaused = paused
            if paused {
                for job in jobs where job.state == .running { job.state = .paused }
            }
            scheduleLocked()
        }
        notify()
    }

    public func setQueueConcurrency(_ n: UInt32) throws {
        lock.withLock {
            concurrency = max(1, Int(n))
            scheduleLocked()
        }
        notify()
    }

    public func setQueuePostAction(_ action: PostAction) throws {
        lock.withLock {
            postAction = action
            postActionDue = false
        }
        notify()
    }

    public func clearQueuePostAction() throws {
        lock.withLock { postActionDue = false }
        notify()
    }

    public func planPreview(_ spec: CreateSpec) throws -> PlanPreview {
        MockPlanner.plan(spec: spec, sources: resolveSources(spec.sources))
    }

    /// The MOCK reports exactly what the real engine reports.
    ///
    /// Not "everything true", which is what this said first. A mock that
    /// claims every capability demos controls nobody can ship, and the
    /// screenshot set then shows an app that does not exist - chip C's point,
    /// and it is right.
    ///
    /// THE CONVERSE BITES JUST AS HARD AND IS WHAT HAPPENED HERE. A mock that
    /// claims LESS than the engine HIDES shipped controls, so the screenshots
    /// advertise an app missing features it ships (`e07dc80113`, which fixed
    /// exactly that on the Windows mock while this one never followed). Six of
    /// these were stale on 12 Sep 2026: `std_naming`, `comment` and
    /// `volume_limit_explicit` from that morning's landings, and the three
    /// in-fold keys from `par2gen-create-control` the same afternoon.
    ///
    /// THE SOURCE OF TRUTH IS `pf_capabilities` AND THE CAPABILITY TABLE IN
    /// `apps/parfast/crates/parfast-ffi/API.md`. Only two are false today, and
    /// each says why in that table: `unicode_policy`, which was looked at
    /// properly and should STAY false, and `low_priority`, which the snapshot
    /// carries for a host to act on and no engine code reads. When the engine
    /// moves, this line, that table and `MockCoreTests` move together - never
    /// one of them alone.
    public func capabilities() throws -> Capabilities {
        Capabilities(
            version: "1.5.0-mock",
            engine: "MockCore (no engine linked)",
            cpu: hostCPU(),
            kernel: "mock",
            std_naming: true,
            unicode_policy: false,
            data_skipping: true,
            fast_solver: true,
            pause: true,
            low_priority: false,
            comment: true,
            volume_limit_explicit: true,
            pause_in_fold: true,
            cancel_in_fold: true,
            progress_in_fold: true)
    }

    public func settingsGet() throws -> CoreSettings { lock.withLock { settings } }

    public func settingsSet(_ newValue: CoreSettings) throws {
        lock.withLock { settings = newValue }
        notify()
    }

    /// The demo build has no store, so there is nothing to clear.
    @discardableResult
    public func clearDigestCache() throws -> Int { 0 }

    public func lastError() -> CoreError? { lock.withLock { _lastError } }

    // MARK: - Demo helpers

    /// Submit a verify of a named scenario. The demo menu and the tests use
    /// this; a Finder drop goes through `submit` with a path and lands in the
    /// same place, because routing happens inside `makeJob`.
    @discardableResult
    public func submitVerify(scenario: MockScenario, extraDirs: [String] = []) throws -> Int64 {
        try submit(.verify(VerifySpec(par2: scenario.par2Path, extra_dirs: extraDirs)))
    }

    // MARK: - Job construction

    private func makeJob(_ spec: JobSpec) throws -> MockJob {
        let id = lock.withLock { () -> Int64 in
            let next = nextId
            nextId += 1
            return next
        }
        let lowPriority = lock.withLock { settings.performance.low_priority }

        switch spec {
        case .verify(let v):
            let scenario = MockScenario.routing(path: v.par2)
            let job = MockJob(id: id, spec: spec, title: scenario.setName,
                              duration: scenario.verifySeconds,
                              totalBytes: scenario.files.reduce(0) { $0 + $1.size },
                              lowPriority: lowPriority)
            job.scenario = scenario
            return job

        case .repairSet(let r):
            let scenario = MockScenario.routing(path: r.par2)
            let job = MockJob(id: id, spec: spec, title: scenario.setName,
                              duration: scenario.repairSeconds,
                              totalBytes: scenario.files.reduce(0) { $0 + $1.size },
                              lowPriority: lowPriority)
            job.scenario = scenario
            job.excluded = Set(r.exclude)
            return job

        case .create(let c):
            let preview = MockPlanner.plan(spec: c, sources: resolveSources(c.sources))
            let bytes = resolveSources(c.sources).reduce(Int64(0)) { $0 + $1.size }
            // A believable 30 seconds for a few gigabytes, floored so a tiny
            // set still gives the progress sheet something to animate.
            let seconds = max(6.0, min(45.0, Double(bytes) / 180_000_000.0))
            let job = MockJob(id: id, spec: spec,
                              title: (c.output as NSString).lastPathComponent,
                              duration: seconds, totalBytes: bytes, lowPriority: lowPriority)
            job.preview = preview
            return job

        case .checksumCreate(let cc):
            let sources = resolveSources(cc.sources)
            let bytes = sources.reduce(Int64(0)) { $0 + $1.size }
            let job = MockJob(id: id, spec: spec,
                              title: (cc.output as NSString).lastPathComponent,
                              duration: max(3, min(20, Double(bytes) / 400_000_000.0)),
                              totalBytes: bytes, lowPriority: lowPriority)
            job.checksumEntries = sources.map {
                ChecksumEntry(name: $0.name, expected: fakeDigest($0.name, format: cc.format),
                              actual: "", status: .pending)
            }
            return job

        case .checksumVerify(let cv):
            let entries = mockChecksumList(for: cv.file)
            let job = MockJob(id: id, spec: spec,
                              title: (cv.file as NSString).lastPathComponent,
                              duration: 4, totalBytes: 512_000_000, lowPriority: lowPriority)
            job.checksumEntries = entries
            return job
        }
    }

    private func resolveSources(_ items: [SourceItem]) -> [MockPlanner.Source] {
        var out: [MockPlanner.Source] = []
        let fm = FileManager.default
        for item in items {
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: item.path, isDirectory: &isDir), isDir.boolValue {
                let deep = item.recursive ?? true
                let children = (try? fm.contentsOfDirectory(atPath: item.path)) ?? []
                for child in children.sorted() {
                    let full = item.path + "/" + child
                    var childIsDir: ObjCBool = false
                    fm.fileExists(atPath: full, isDirectory: &childIsDir)
                    if childIsDir.boolValue {
                        if deep { out += resolveSources([SourceItem(path: full, recursive: true)]) }
                        continue
                    }
                    out.append(source(at: full))
                }
            } else {
                out.append(source(at: item.path))
            }
        }
        return out
    }

    private func source(at path: String) -> MockPlanner.Source {
        let name = (path as NSString).lastPathComponent
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let size = attrs[.size] as? NSNumber {
            return MockPlanner.Source(name: name, size: size.int64Value, path: path)
        }
        return MockPlanner.Source(name: name, size: syntheticSizes(path) ?? 10_485_760, path: path)
    }

    // MARK: - The clock

    private func tick() {
        var changed = false
        lock.withLock {
            let dt = 1.0 / Self.tickHz * _speed
            for job in jobs where job.state == .running {
                job.elapsed += dt
                changed = true
                appendPhaseLogLocked(job)
                if job.elapsed >= job.duration {
                    job.elapsed = job.duration
                    finishLocked(job)
                }
            }
            if scheduleLocked() { changed = true }
            // The queue has drained and the action has not been carried out:
            // the same contract the real core reports.
            if postAction != .none, !jobs.isEmpty,
               jobs.allSatisfy({ $0.state.isFinished }), !postActionDue {
                postActionDue = true
                changed = true
            }
        }
        if changed { notify() }
    }

    /// Start as many queued jobs as the concurrency allows. Returns whether
    /// anything moved, so an idle app is not woken twenty times a second.
    @discardableResult
    private func scheduleLocked() -> Bool {
        guard !queuePaused else { return false }
        var running = jobs.filter { $0.state == .running }.count
        var moved = false
        // Flagged jobs first, then submission order.
        let order = jobs.filter { $0.runNext } + jobs.filter { !$0.runNext }
        for job in order where job.state == .queued {
            guard running < concurrency else { break }
            job.state = .running
            job.log.append(startLine(job))
            running += 1
            moved = true
        }
        return moved
    }

    private func finishLocked(_ job: MockJob) {
        switch job.spec {
        case .verify:
            guard let s = job.scenario else { job.state = .done; return }
            job.state = .done
            job.log += verdictLines(s)
            if s.finalVerdict == .unrepairable {
                job.error = CoreError(
                    code: "unrepairable",
                    message: "needs \(s.blocksNeeded - s.recoveryAvailable) more blocks")
            }

        case .repairSet:
            guard let s = job.scenario else { job.state = .done; return }
            if s.finalVerdict == .unrepairable {
                job.state = .failed
                job.error = CoreError(
                    code: "unrepairable",
                    message: "needs \(s.blocksNeeded - s.recoveryAvailable) more blocks")
                job.log.append("Repair is not possible.")
            } else {
                job.state = .done
                let repaired = s.files.filter {
                    switch $0.outcome {
                    case .damaged, .missing: return !job.excluded.contains($0.name)
                    case .complete, .extra, .misnamed: return false
                    }
                }.count
                let purge: Bool
                if case .repairSet(let r) = job.spec { purge = r.purge } else { purge = false }
                job.result = JobResult(repaired_files: repaired, purged: purge)
                job.log.append("Repair complete.")
                if purge { job.log.append("Purge backup files.") }
            }

        case .create:
            job.state = .done
            job.result = JobResult(written: (job.preview?.files ?? []).map {
                WrittenFile(name: $0.name, size: $0.size)
            })
            job.log.append("Done")

        case .checksumCreate:
            job.state = .done
            // A checksum CREATE has nothing to compare, so no rows - which
            // is the core's own behaviour, not a shortcut.
            job.result = JobResult(checksum: ChecksumResult(
                ok: job.checksumEntries.count, mismatch: 0, missing: 0))
            job.log.append("Wrote \(job.checksumEntries.count) lines.")

        case .checksumVerify:
            let entries = job.checksumEntries
            let bad = entries.filter { $0.status == .mismatch || $0.status == .missing }
            // A checksum verify that finds problems FAILS, with the full
            // result still attached - the real core's contract, mirrored
            // rather than approximated. The mock said `done` here, which is
            // the same class of divergence as a mock that claims a capability
            // the engine does not have.
            if bad.isEmpty {
                job.state = .done
            } else {
                job.state = .failed
                let mismatched = bad.filter { $0.status == .mismatch }.count
                let absent = bad.filter { $0.status == .missing }.count
                job.error = CoreError(
                    code: "checksum_mismatch",
                    message: "\(mismatched) mismatched, \(absent) missing of \(entries.count)")
            }
            job.result = JobResult(checksum: ChecksumResult(
                ok: entries.filter { $0.status == .ok }.count,
                mismatch: entries.filter { $0.status == .mismatch }.count,
                missing: entries.filter { $0.status == .missing }.count,
                entries: entries))
            job.log.append("Checked \(entries.count) files.")
        }
    }

    private func mutate(_ id: Int64, _ body: (MockJob) throws -> Void) throws {
        try lock.withLock {
            guard let job = jobs.first(where: { $0.id == id }) else { throw ClientError.noSuchJob(id) }
            try body(job)
            scheduleLocked()
        }
        notify()
    }

    private func notify() {
        let handler = lock.withLock { wake }
        handler?()
    }

    // MARK: - Snapshots

    private func snapshotLocked(_ job: MockJob) -> JobSnapshot {
        let fraction = job.duration <= 0 ? 1 : min(1, job.elapsed / job.duration)
        let phase = phaseFor(job, fraction: fraction)
        let elapsedMs = Int64(job.elapsed * 1000)
        let remaining = fraction >= 1 || fraction <= 0
            ? nil : Int64((job.duration - job.elapsed) * 1000)
        let rate: Int64? = job.elapsed > 0.2 && job.state == .running
            ? Int64(Double(job.totalBytes) * fraction / job.elapsed)
            : nil

        var survey: Survey?
        var result = job.result
        if let s = job.scenario {
            survey = surveyFor(job, scenario: s, fraction: fraction)
        }
        if case .checksumVerify = job.spec, job.state == .running {
            let done = Int(Double(job.checksumEntries.count) * fraction)
            let partial = job.checksumEntries.prefix(done)
            // Rows arrive as they resolve; the ones behind the cursor are not
            // sent at all rather than sent as a made-up `pending`.
            result = JobResult(checksum: ChecksumResult(
                ok: partial.filter { $0.status == .ok }.count,
                mismatch: partial.filter { $0.status == .mismatch }.count,
                missing: partial.filter { $0.status == .missing }.count,
                entries: Array(partial)))
        }

        return JobSnapshot(
            id: job.id,
            kind: job.spec.kind,
            state: job.state,
            phase: phase,
            phase_text: phaseText(job, fraction: fraction, phase: phase),
            progress: job.state == .done ? 1 : fraction,
            elapsed_ms: elapsedMs,
            eta_ms: job.state == .running ? remaining : nil,
            rate_bytes_per_s: rate,
            low_priority: job.lowPriority,
            added_at: job.addedAt,
            log_tail: job.log,
            survey: survey,
            result: result,
            error: job.error,
            title: job.title)
    }

    private func phaseFor(_ job: MockJob, fraction: Double) -> JobPhase {
        switch job.spec {
        case .verify:
            if fraction < 0.04 { return .scanning }
            return fraction < 0.99 ? .hashing : .finishing
        case .repairSet:
            if fraction < 0.55 { return .solving }
            return fraction < 0.99 ? .writing : .finishing
        case .create:
            if fraction < 0.05 { return .scanning }
            if fraction < 0.60 { return .hashing }
            if fraction < 0.85 { return .solving }
            return fraction < 0.99 ? .writing : .finishing
        case .checksumCreate, .checksumVerify:
            return fraction < 0.99 ? .hashing : .finishing
        }
    }

    private func phaseText(_ job: MockJob, fraction: Double, phase: JobPhase) -> String {
        switch job.spec {
        case .verify, .repairSet:
            guard let s = job.scenario else { return "" }
            switch phase {
            case .scanning: return "Scanning \(s.folder)"
            case .hashing:
                let index = min(s.files.count, max(1, Int(Double(s.files.count) * fraction) + 1))
                return "Hashing \(index) of \(s.files.count) files"
            case .solving:
                let blocks = s.blocksNeeded
                let done = Int(Double(blocks) * min(1, fraction / 0.55))
                return "Solving \(formatted(done)) of \(formatted(blocks)) blocks"
            case .writing:
                let repairing = s.files.filter {
                    if case .complete = $0.outcome { return false }
                    if case .extra = $0.outcome { return false }
                    return true
                }.count
                return "Writing \(repairing) repaired files"
            case .finishing: return "Finishing"
            }
        case .create:
            let p = job.preview
            switch phase {
            case .scanning: return "Scanning source files"
            case .hashing:
                let blocks = p?.block_count ?? 0
                let done = Int(Double(blocks) * min(1, (fraction - 0.05) / 0.55))
                return "Hashing \(formatted(done)) of \(formatted(blocks)) blocks"
            case .solving:
                let blocks = p?.recovery_blocks ?? 0
                let done = Int(Double(blocks) * min(1, (fraction - 0.60) / 0.25))
                return "Computing recovery blocks \(formatted(done)) of \(formatted(blocks))"
            case .writing: return "Writing volumes"
            case .finishing: return "Finishing"
            }
        case .checksumCreate:
            let done = Int(Double(job.checksumEntries.count) * fraction)
            return "Hashing \(formatted(done)) of \(formatted(job.checksumEntries.count)) files"
        case .checksumVerify:
            let done = Int(Double(job.checksumEntries.count) * fraction)
            return "Checking \(formatted(done)) of \(formatted(job.checksumEntries.count)) files"
        }
    }

    // MARK: - The survey simulation

    /// Walk the scenario's files in order, hashing each over a slice of the
    /// job's time proportional to its block count, and build the block-state
    /// array the map draws. A repair walks the same array backwards: damaged
    /// and missing blocks turn present as the writing phase proceeds.
    private func surveyFor(_ job: MockJob, scenario s: MockScenario, fraction: Double) -> Survey {
        let isRepair = job.spec.kind == .repairSet
        let total = max(1, s.sourceBlocks)
        let processed = isRepair ? total : Int((Double(total) * fraction).rounded(.down))

        var states = [BlockState](repeating: .pending, count: total)
        var files: [SurveyFile] = []
        var cursor = 0
        var repaired = 0
        if isRepair {
            // Writing runs over the second 45% of a repair; before that the
            // solver is working and nothing has changed on disk yet. A
            // FINISHED repair is the whole budget by definition, not
            // 0.4499.../0.45 of it - the floating-point form of that fraction
            // is a hair under 1 and left one block unrepaired.
            if job.state == .done {
                repaired = s.blocksNeeded
            } else {
                let writeFraction = max(0, (fraction - 0.55) / 0.45)
                repaired = Int((Double(s.blocksNeeded) * min(1, writeFraction)).rounded(.down))
            }
        }
        let writeStarted = isRepair && (job.state == .done || fraction > 0.55)
        var repairBudget = repaired

        for file in s.files {
            let count = s.blocks(of: file)
            if case .extra = file.outcome {
                files.append(SurveyFile(name: file.name, size: file.size, status: .extra,
                                        blocks_ok: 0, blocks_total: 0))
                continue
            }
            let start = cursor
            cursor += count
            let excluded = job.excluded.contains(file.name)

            if start >= processed {
                for i in start..<(start + count) { states[i] = .pending }
                files.append(SurveyFile(name: file.name, size: file.size, status: .pending,
                                        blocks_ok: 0, blocks_total: count))
                continue
            }

            if processed < start + count {
                // Mid-file: the blocks behind the cursor have resolved, the
                // rest are being hashed right now.
                let done = processed - start
                _ = fill(&states, file: file, scenario: s, at: start, count: done,
                         repairBudget: &repairBudget, excluded: excluded)
                for i in (start + done)..<(start + count) { states[i] = .hashing }
                files.append(SurveyFile(
                    name: file.name, size: file.size, status: .hashing,
                    blocks_ok: okCount(file: file, scenario: s, resolved: done),
                    blocks_total: count, found_as: nil,
                    progress: Double(done) / Double(max(1, count))))
                continue
            }

            let mended = fill(&states, file: file, scenario: s, at: start, count: count,
                              repairBudget: &repairBudget, excluded: excluded)
            // "Repaired" means this file's OWN bad blocks were all rebuilt.
            // A misnamed file needs none rebuilt: it is put right by the
            // rename, so it turns complete as soon as writing has started.
            let repairedThisFile = !excluded && (mended >= neededBlocks(file, scenario: s))
                && (mended > 0 || writeStarted)
            files.append(resolvedFile(file, scenario: s, blocks: count,
                                      repaired: repairedThisFile))
        }

        let needed = s.blocksNeeded
        let verdict: SurveyVerdict
        if isRepair {
            if job.state == .failed { verdict = .failed }
            else if job.state == .done { verdict = .repaired }
            else { verdict = .repairable }
        } else if fraction < 1 {
            verdict = .verifying
        } else {
            verdict = s.finalVerdict
        }

        return Survey(
            set_name: s.setName,
            folder: s.folder,
            block_size: s.blockSize,
            source_blocks: total,
            recovery_available: s.recoveryAvailable,
            recovery_needed: isRepair && job.state == .done ? 0 : needed,
            verdict: verdict,
            files: files,
            block_runs: runLengthEncode(states))
    }

    /// The resolved states of `count` blocks of one file, starting at `at`.
    /// A damaged file's bad blocks are spread deterministically, so the map
    /// looks like damage rather than a solid band and a screenshot of it is
    /// reproducible.
    /// Returns how many of this file's bad blocks the repair budget rebuilt.
    @discardableResult
    private func fill(_ states: inout [BlockState], file: MockScenario.File,
                      scenario s: MockScenario, at: Int, count: Int,
                      repairBudget: inout Int, excluded: Bool) -> Int {
        guard count > 0 else { return 0 }
        let fileBlocks = s.blocks(of: file)
        var mended = 0
        switch file.outcome {
        case .complete:
            for i in at..<(at + count) { states[i] = .present }
        case .misnamed:
            for i in at..<(at + count) { states[i] = .misnamed }
        case .extra:
            break
        case .missing:
            for i in at..<(at + count) {
                if !excluded && repairBudget > 0 {
                    states[i] = .present
                    repairBudget -= 1
                    mended += 1
                } else {
                    states[i] = .missing
                }
            }
        case .damaged(let bad):
            let badCount = min(bad, fileBlocks)
            let stride = max(1, fileBlocks / max(1, badCount))
            for offset in 0..<count {
                let isBad = (offset % stride == 0) && (offset / stride) < badCount
                if isBad {
                    if !excluded && repairBudget > 0 {
                        states[at + offset] = .present
                        repairBudget -= 1
                        mended += 1
                    } else {
                        states[at + offset] = .damaged
                    }
                } else {
                    states[at + offset] = .present
                }
            }
        }
        return mended
    }

    /// Blocks of this file a repair would have to rebuild.
    private func neededBlocks(_ file: MockScenario.File, scenario s: MockScenario) -> Int {
        switch file.outcome {
        case .complete, .extra, .misnamed: return 0
        case .missing: return s.blocks(of: file)
        case .damaged(let bad): return min(bad, s.blocks(of: file))
        }
    }

    private func okCount(file: MockScenario.File, scenario s: MockScenario, resolved: Int) -> Int {
        switch file.outcome {
        case .complete, .misnamed: return resolved
        case .extra: return 0
        case .missing: return 0
        case .damaged(let bad):
            let fileBlocks = s.blocks(of: file)
            let stride = max(1, fileBlocks / max(1, min(bad, fileBlocks)))
            let badSoFar = min(min(bad, fileBlocks), (resolved + stride - 1) / stride)
            return max(0, resolved - badSoFar)
        }
    }

    private func resolvedFile(_ file: MockScenario.File, scenario s: MockScenario,
                              blocks: Int, repaired: Bool) -> SurveyFile {
        switch file.outcome {
        case .complete:
            return SurveyFile(name: file.name, size: file.size, status: .complete,
                              blocks_ok: blocks, blocks_total: blocks)
        case .misnamed(let foundAs):
            return SurveyFile(name: file.name, size: file.size,
                              status: repaired ? .complete : .misnamed,
                              blocks_ok: blocks, blocks_total: blocks,
                              found_as: repaired ? nil : foundAs)
        case .missing:
            return SurveyFile(name: file.name, size: file.size,
                              status: repaired ? .complete : .missing,
                              blocks_ok: repaired ? blocks : 0, blocks_total: blocks)
        case .damaged(let bad):
            let badCount = min(bad, blocks)
            return SurveyFile(name: file.name, size: file.size,
                              status: repaired ? .complete : .damaged,
                              blocks_ok: repaired ? blocks : blocks - badCount,
                              blocks_total: blocks)
        case .extra:
            return SurveyFile(name: file.name, size: file.size, status: .extra,
                              blocks_ok: 0, blocks_total: 0)
        }
    }

    /// `[[state, length], ...]`, the wire shape the block map draws from.
    public static func runLengthEncode(_ states: [BlockState]) -> [[Int]] {
        var out: [[Int]] = []
        for state in states {
            if var last = out.last, last[0] == Int(state.rawValue) {
                last[1] += 1
                out[out.count - 1] = last
            } else {
                out.append([Int(state.rawValue), 1])
            }
        }
        return out
    }

    private func runLengthEncode(_ states: [BlockState]) -> [[Int]] {
        Self.runLengthEncode(states)
    }

    // MARK: - Log lines, in the CLI's own words

    private func startLine(_ job: MockJob) -> String {
        switch job.spec {
        case .verify(let v): return "Loading \"\((v.par2 as NSString).lastPathComponent)\"."
        case .repairSet(let r): return "Loading \"\((r.par2 as NSString).lastPathComponent)\"."
        case .create(let c): return "Opening: \((c.output as NSString).lastPathComponent)"
        case .checksumCreate(let c): return "Writing \(c.format.display) list."
        case .checksumVerify(let c): return "Loading \"\((c.file as NSString).lastPathComponent)\"."
        }
    }

    private func appendPhaseLogLocked(_ job: MockJob) {
        let fraction = job.duration <= 0 ? 1 : min(1, job.elapsed / job.duration)
        func once(_ mark: String, _ lines: [String]) {
            guard !job.loggedMarks.contains(mark) else { return }
            job.loggedMarks.insert(mark)
            job.log += lines
        }
        switch job.spec {
        case .verify, .repairSet:
            guard let s = job.scenario else { return }
            if fraction > 0.03 {
                once("head", [
                    "",
                    "There are \(s.files.filter { if case .extra = $0.outcome { return false } else { return true } }.count) recoverable files and \(s.files.filter { if case .extra = $0.outcome { return true } else { return false } }.count) other files.",
                    "The block size used was \(s.blockSize) bytes.",
                    "There are a total of \(formatted(s.sourceBlocks)) data blocks.",
                    "The total size of the data files is \(formatted(Int(s.files.reduce(Int64(0)) { $0 + $1.size }))) bytes.",
                    "",
                    "Verifying source files:",
                    "",
                ])
            }
            let files = s.files
            for (i, f) in files.enumerated() {
                let mark = "file-\(i)"
                let at = Double(i) / Double(max(1, files.count))
                if fraction > at + 0.02 {
                    once(mark, ["Opening: \"\(f.name)\""])
                }
            }
        case .create:
            if fraction > 0.02, let p = job.preview {
                once("head", [
                    "Block size: \(p.block_size)",
                    "Source file count: \(formatted(p.files.count))",
                    "Source block count: \(formatted(p.block_count))",
                    "Recovery block count: \(formatted(p.recovery_blocks))",
                    "Recovery file count: \(formatted(max(0, p.files.count - 1)))",
                    "",
                ])
            }
            if fraction > 0.85 {
                once("write", ["Writing recovery packets", "Writing verification packets"])
            }
        case .checksumCreate, .checksumVerify:
            break
        }
    }

    private func verdictLines(_ s: MockScenario) -> [String] {
        var out = [""]
        if s.blocksNeeded == 0 {
            out.append("All files are correct, repair is not required.")
            return out
        }
        out.append("Repair is required.")
        let missing = s.files.filter { if case .missing = $0.outcome { return true } else { return false } }.count
        let damaged = s.files.filter { if case .damaged = $0.outcome { return true } else { return false } }.count
        if missing > 0 { out.append("\(missing) file(s) are missing.") }
        if damaged > 0 { out.append("\(damaged) file(s) exist but are damaged.") }
        out.append("You have \(formatted(s.recoveryAvailable)) out of \(formatted(s.blocksNeeded)) recovery blocks available.")
        if s.finalVerdict == .repairable {
            out.append("Repair is possible.")
        } else {
            out.append("Repair is not possible.")
            out.append("You need \(formatted(s.blocksNeeded - s.recoveryAvailable)) more recovery blocks to be able to repair.")
        }
        return out
    }

    // MARK: - Small helpers

    private func mockChecksumList(for path: String) -> [ChecksumEntry] {
        let stem = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        let format = ChecksumFormat(rawValue: (path as NSString).pathExtension.lowercased()) ?? .sfv
        let clean = stem.lowercased().contains("clean")
        return (1...12).map { i in
            let name = String(format: "%@.part%02d.rar", stem, i)
            let status: ChecksumEntry.Status
            if clean { status = .ok }
            else if i == 5 { status = .mismatch }
            else if i == 9 { status = .missing }
            else { status = .ok }
            let expected = fakeDigest(name, format: format)
            return ChecksumEntry(
                name: name, expected: expected,
                actual: status == .ok ? expected : (status == .missing ? "" : fakeDigest(name + "!", format: format)),
                status: status)
        }
    }

    /// A stable, obviously-fake digest. Deterministic so a screenshot taken
    /// twice shows the same table.
    private func fakeDigest(_ name: String, format: ChecksumFormat) -> String {
        var h: UInt64 = 0xcbf29ce484222325
        for byte in name.utf8 {
            h = (h ^ UInt64(byte)) &* 0x100000001b3
        }
        let width: Int
        switch format {
        case .sfv: width = 8
        case .md5: width = 32
        case .sha1: width = 40
        case .sha256: width = 64
        }
        var out = ""
        var seed = h
        while out.count < width {
            out += String(format: "%016lx", seed)
            seed = seed &* 0x100000001b3 &+ 0x9e3779b97f4a7c15
        }
        return String(out.prefix(width))
    }

    private func hostCPU() -> String {
        var size = 0
        sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
        guard size > 0 else { return "Apple silicon" }
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname("machdep.cpu.brand_string", &buf, &size, nil, 0)
        return String(cString: buf)
    }

    private func formatted(_ n: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}

extension NSLock {
    @discardableResult
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
