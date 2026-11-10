import SwiftUI
import XCTest
@testable import ParfastApp
@testable import ParfastCore

/// Regression tests for the mac findings of the 9 Nov 2026 parfast bug sweep
/// (A30-A37 and its section B "mac" items). Each names its finding; the
/// negative control each one was run against is recorded in the commit that
/// added it.
@MainActor
final class SweepFixTests: XCTestCase {

    private func waitFor(_ what: String, timeout: TimeInterval = 8,
                         _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTFail("timed out waiting for \(what)")
    }

    // MARK: - A30: settings written back as one stale struct

    /// Changing a setting must not put the queue's concurrency back, or bring
    /// back / drop the post-queue action. The mock now keeps both INSIDE its
    /// settings, as the real core does, which is what lets this test fail.
    func testASettingsEditKeepsTheQueuesConcurrencyAndPostAction() throws {
        let core = MockCore(speed: 60)
        let app = AppModel(core: core)
        app.setConcurrency(3)
        app.setPostAction(.notify)
        app.updateSettings { $0.general.purge_after_repair = true }
        let queue = try core.queueSnapshot()
        XCTAssertEqual(queue.concurrency, 3, "a settings edit reset the concurrency")
        XCTAssertEqual(queue.post_action, .notify, "a settings edit reset the post-queue action")
        XCTAssertTrue(try core.settingsGet().general.purge_after_repair, "and the edit itself landed")
    }

    /// The Settings window's draft is a long-lived copy: an edit made through
    /// it after the queue moved must still carry only the field it changed.
    func testAStaleDraftEditCarriesOnlyItsOwnField() throws {
        let core = MockCore(speed: 60)
        let app = AppModel(core: core)
        let draftBefore = app.settings          // taken while concurrency was 1
        app.setConcurrency(4)                   // the queue moves behind it
        var draftAfter = draftBefore
        draftAfter.general.notifications = false
        app.apply(changesFrom: draftBefore, to: draftAfter)
        XCTAssertEqual(try core.queueSnapshot().concurrency, 4)
        XCTAssertFalse(try core.settingsGet().general.notifications)
    }

    /// Opening Settings (placeholder draft -> fresh read) and the progress
    /// sheet's onAppear (a "change" to the value already set) write nothing.
    func testOpeningSettingsAndTheProgressSheetWriteNothing() {
        let spy = SpyCore()
        let app = AppModel(core: spy)
        // The core's settings must differ from the struct's placeholder, or
        // the placeholder-to-fresh move below is no move at all and the test
        // proves nothing: the queue's stepper changes them behind the model.
        try? spy.setQueueConcurrency(3)
        XCTAssertNotEqual(try? spy.settingsGet(), CoreSettings())
        // SettingsView.onAppear: reload, then the draft moves from its
        // placeholder to the fresh copy and onChange sees that move.
        app.reloadSettings()
        app.apply(changesFrom: CoreSettings(), to: app.settings)
        // ProgressSheet: notify toggled to the value the setting already has.
        app.updateSettings { $0.general.notifications = app.settings.general.notifications }
        XCTAssertEqual(spy.settingsWrites, 0)
        app.updateSettings { $0.general.auto_close_progress.toggle() }
        XCTAssertEqual(spy.settingsWrites, 1, "a real edit is still written")
    }

    /// A settings read that fails must not fall back to the cached copy and
    /// write it: that copy can be stale, which is A30 again.
    func testAFailedSettingsReadWritesNothing() {
        let spy = SpyCore()
        let app = AppModel(core: spy)
        spy.failSettingsGet = true
        app.updateSettings { $0.general.auto_close_progress.toggle() }
        XCTAssertEqual(spy.settingsWrites, 0)
        XCTAssertNotNil(app.alert, "and the failure is reported")
    }

    /// The merge is per FIELD: two editors of one group do not undo each other.
    func testTheMergeIsPerFieldNotPerGroup() {
        var current = CoreSettings()
        current.general.notifications = false        // set by the progress sheet
        current.concurrency = 5
        let staleOld = CoreSettings()                // the Settings window's draft
        var staleNew = staleOld
        staleNew.general.purge_after_repair = true
        staleNew.performance.threads = 8             // an optional, nil -> 8
        let merged = current.applyingChanges(from: staleOld, to: staleNew)
        XCTAssertTrue(merged.general.purge_after_repair)
        XCTAssertFalse(merged.general.notifications, "a sibling field in the same group survived")
        XCTAssertEqual(merged.concurrency, 5)
        XCTAssertEqual(merged.performance.threads, 8)
        // ...and back to nil removes it.
        let cleared = merged.applyingChanges(from: staleNew, to: staleOld)
        XCTAssertNil(cleared.performance.threads)
        XCTAssertFalse(cleared.general.purge_after_repair)
    }

    /// Section B: the Verify pane follows a CHANGED purge / keep-damaged
    /// default, and an unrelated edit leaves the pane's own toggle alone.
    func testTheVerifyPaneFollowsAChangedDefaultOnly() {
        let app = AppModel(core: MockCore(speed: 60))
        app.updateSettings { $0.general.purge_after_repair = true }
        XCTAssertTrue(app.verify.purge)
        app.updateSettings { $0.general.keep_damaged_copies = false }
        XCTAssertFalse(app.verify.keepDamaged)
        app.verify.purge = false                   // the pane's own choice
        app.updateSettings { $0.general.notifications.toggle() }
        XCTAssertFalse(app.verify.purge, "an unrelated setting reset the pane's toggle")
    }

    // MARK: - A33: SizeField

    func testSizeFieldHonoursTheDecimalSeparator() {
        let en = Locale(identifier: "en_US")
        let de = Locale(identifier: "de_DE")
        XCTAssertEqual(SizeField.parse("1.5", unit: 1_048_576, locale: en), 1_572_864)
        XCTAssertEqual(SizeField.parse("1,5", unit: 1_048_576, locale: de), 1_572_864)
        // The field shows Fmt.count's grouping, so it must read it back.
        XCTAssertEqual(SizeField.parse("1,024", unit: 1024, locale: en), 1_048_576)
        XCTAssertEqual(SizeField.parse("1.024", unit: 1024, locale: de), 1_048_576)
        XCTAssertEqual(SizeField.parse("", unit: 1024, locale: en), 0)
        XCTAssertNil(SizeField.parse("abc", unit: 1024, locale: en))
        XCTAssertNil(SizeField.parse("1.2.3", unit: 1024, locale: en))
        XCTAssertEqual(SizeField.parse("1.1", unit: 1024, multipleOfFour: true, locale: en), 1128)
    }

    /// Eleven digits with GiB selected trapped the whole app. Now it is nil.
    func testSizeFieldRefusesAnOverflowRatherThanTrapping() {
        let en = Locale(identifier: "en_US")
        XCTAssertNil(SizeField.parse("99999999999", unit: 1_073_741_824, locale: en))
        XCTAssertNil(SizeField.parse("9223372036854775807", unit: 2, locale: en))
        // The round-up to four must not be the step that overflows.
        XCTAssertNil(SizeField.parse("9223372036854775807", unit: 1, multipleOfFour: true, locale: en))
        XCTAssertEqual(SizeField.parse("9223372036854775807", unit: 1, locale: en), Int64.max)
    }

    // MARK: - A34: parfast:// URLs

    func testOnlyTheOpenHostIsAnOpen() {
        XCTAssertEqual(AppModel.pathsFromOpenURL(URL(string: "parfast://open?path=/a/b.par2")!),
                       ["/a/b.par2"])
        XCTAssertEqual(AppModel.pathsFromOpenURL(URL(string: "parfast://anything?path=/a/b.par2")!), [])
        XCTAssertEqual(AppModel.pathsFromOpenURL(URL(string: "parfast://?path=/a/b.par2")!), [])
        XCTAssertEqual(AppModel.pathsFromOpenURL(URL(string: "parfast://open?path=relative.par2")!), [])
        XCTAssertEqual(AppModel.pathsFromOpenURL(URL(string: "other://open?path=/a/b.par2")!), [])
    }

    /// Under "verify, then repair", a URL verifies the set and offers Repair,
    /// and never starts the repair itself.
    func testAURLOpenNeverRepairsOnItsOwn() {
        let app = AppModel(core: MockCore(speed: 60))
        app.settings.general.open_par2 = .verifyThenRepair
        app.open(paths: [MockScenario.damagedRepairable.par2Path], fromURL: true)
        XCTAssertNotNil(app.verify.jobId, "the URL still opens and verifies")
        waitFor("verify") {
            app.refresh()
            return app.verify.snapshot?.state.isFinished ?? false
        }
        for _ in 0..<20 { app.refresh(); RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
        XCTAssertTrue(app.queue.jobs.allSatisfy { $0.kind == .verify }, "a URL started a repair")
        XCTAssertTrue(app.verify.canRepair, "the user is offered it instead")
    }

    // MARK: - A35: drop collection

    /// Many completions appending at once. Without the lock this loses paths
    /// or corrupts the array; whether a given run shows it is up to the
    /// scheduler, so a green run of the unlocked version is possible.
    func testDroppedPathsSurviveConcurrentAppends() {
        let collected = DroppedPaths()
        DispatchQueue.concurrentPerform(iterations: 20_000) { i in
            collected.append("/p/\(i)")
        }
        XCTAssertEqual(collected.sorted().count, 20_000)
    }

    // MARK: - A36: result.warnings

    func testTheResultsWarningsAreDecoded() throws {
        let json = """
        {"id":3,"kind":"create","state":"done","phase":"done","phase_text":"",
         "progress":1,"elapsed_ms":10,"low_priority":false,"added_at":"",
         "log_tail":[],"result":{"written":[],"exit_code":0,
         "warnings":["/a/locked could not be read, so it was left out"]}}
        """
        let job = try CoreJSON.decode(JobSnapshot.self, from: json)
        XCTAssertEqual(job.result?.leftOut, ["/a/locked could not be read, so it was left out"])
        let plain = try CoreJSON.decode(JobResult.self, from: #"{"written":[]}"#)
        XCTAssertEqual(plain.leftOut, [], "absent when empty, as API.md says")
    }

    // MARK: - A37: titles against a core that sends none

    func testJobsAreTitledWhenTheCoreSendsNoTitle() throws {
        let spy = SpyCore()
        spy.stripTitles = true
        let app = AppModel(core: spy)
        app.submit(.checksumVerify(ChecksumVerifySpec(file: "/abs/some/list.sfv")), showSheet: false)
        XCTAssertNil(try spy.queueSnapshot().jobs.first?.title, "the spy really strips them")
        XCTAssertEqual(app.queue.jobs.first?.title, "list.sfv")
    }

    func testDisplayNameIsTheWindowsRule() {
        XCTAssertEqual(JobSpec.verify(VerifySpec(par2: "/x/set.par2")).displayName, "set.par2")
        XCTAssertEqual(JobSpec.checksumCreate(ChecksumCreateSpec(output: "/x/a.sfv")).displayName, "a.sfv")
        XCTAssertEqual(JobSpec.checksumVerify(ChecksumVerifySpec(file: "")).displayName, "")
    }

    // MARK: - Section B: notifications replayed at launch

    func testFinishedJobsInTheFirstSnapshotAreNotAnnounced() {
        // A store's jobs, finished in an earlier run, in the very first
        // snapshot the model reads (its init refreshes once).
        // The model's init polls once; that poll FAILS here, so the call
        // below is the first snapshot the model ever reads - as it is for a
        // core whose first poll did not answer.
        let spy = SpyCore()
        spy.failSnapshots = true
        let app = AppModel(core: spy)
        spy.failSnapshots = false
        var later = QueueSnapshot(jobs: [
            JobSnapshot(id: 101, kind: .verify, state: .done),
            JobSnapshot(id: 102, kind: .create, state: .interrupted),
        ])
        XCTAssertEqual(app.newlyFinished(in: later).map(\.id), [], "a store's finished jobs are not news")
        later.jobs.append(JobSnapshot(id: 103, kind: .verify, state: .done))
        XCTAssertEqual(app.newlyFinished(in: later).map(\.id), [103])
        XCTAssertEqual(app.newlyFinished(in: later).map(\.id), [], "and only once")
    }

    // MARK: - Section B: a failed verify

    func testAFailedVerifyDoesNotSayWaiting() {
        let model = VerifyModel()
        model.snapshot = JobSnapshot(id: 1, kind: .verify, state: .failed,
                                     error: CoreError(code: "read", message: "set.par2 could not be read."))
        XCTAssertNotEqual(model.pillText, S.verifyPillQueued)
        XCTAssertTrue(model.pillText.contains("could not be read"), model.pillText)
        model.snapshot = JobSnapshot(id: 1, kind: .verify, state: .failed)
        XCTAssertEqual(model.pillText, S.queueStateFailed, "no dangling reason")
        model.snapshot = JobSnapshot(id: 1, kind: .verify, state: .interrupted)
        XCTAssertEqual(model.pillText, S.queueStateInterrupted)
    }

    // MARK: - Section B: the checksum verify side shows a verify only

    func testTheChecksumVerifySideNeverShowsACreatesResult() {
        let model = ChecksumsModel()
        model.jobId = 7                                   // a checksum CREATE
        model.apply(queue: QueueSnapshot(jobs: [
            JobSnapshot(id: 7, kind: .checksumCreate, state: .running,
                        result: JobResult(checksum: ChecksumResult(ok: 3, mismatch: 0, missing: 0))),
        ]))
        XCTAssertNil(model.result)
        XCTAssertFalse(model.isBusy, "the create's busy state is not the verify side's")
        XCTAssertNotNil(model.snapshot, "the log drawer still follows the last job")
    }

    // MARK: - Section B: Create's Refresh recomputes

    func testRefreshRecomputesThePreview() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pf-refresh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("a.bin")
        try Data(count: 4096).write(to: file)
        let core = MockCore(speed: 60)
        let model = CreateModel()
        model.addSources([file.path])
        model.recompute(with: core)
        let before = model.preview?.source_bytes ?? model.preview?.files.first?.size
        try Data(count: 1_000_000).write(to: file)
        model.refreshSources(recomputingWith: core)
        let after = model.preview?.source_bytes ?? model.preview?.files.first?.size
        XCTAssertNotNil(before)
        XCTAssertNotEqual(before, after, "Refresh left the old preview standing")
    }

    // MARK: - Core lane, 9 Nov 2026: contract changes the app must follow

    /// The core refuses a Cancel on a finished job (`not_found`). That is the
    /// click racing the job, not a fault: no alert, and the job keeps its state.
    func testCancellingAFinishedJobIsNotAnError() throws {
        let app = AppModel(core: MockCore(speed: 60))
        app.openPar2(MockScenario.clean.par2Path)
        waitFor("verify") {
            app.refresh()
            return app.verify.snapshot?.state.isFinished ?? false
        }
        let id = try XCTUnwrap(app.verify.jobId)
        let before = app.verify.snapshot?.state
        app.cancel(id)
        XCTAssertNil(app.alert, "a Cancel that lost the race put up an alert")
        XCTAssertEqual(app.queue.jobs.first { $0.id == id }?.state, before)
    }

    func testAStoreThatCouldNotBeOpenedIsShown() {
        let app = AppModel(core: MockCore(speed: 60))
        app.reportStoreOpenFailure(CoreError(
            code: "refused", message: "queue.json was moved aside to queue.json.unreadable-1-2"))
        XCTAssertEqual(app.alert?.message, "queue.json was moved aside to queue.json.unreadable-1-2")
    }

    /// New error codes decode, and the message survives to be shown. (No
    /// negative control: `code` is a String, and there is no lenient enum
    /// here to break - the test pins that it stays one.)
    func testAnUnknownErrorCodeStillDecodesWithItsMessage() throws {
        for code in ["internal", "not_utf8", "output_is_a_source", "duplicate_name", "from_the_future"] {
            let json = """
            {"id":1,"kind":"checksum_verify","state":"failed","phase":"done","phase_text":"",
             "progress":1,"elapsed_ms":1,"low_priority":false,"added_at":"","log_tail":[],
             "title":"list.sfv","error":{"code":"\(code)","message":"the core's words"}}
            """
            let job = try CoreJSON.decode(JobSnapshot.self, from: json)
            XCTAssertEqual(job.error?.code, code)
            XCTAssertEqual(job.error?.message, "the core's words")
        }
    }

    /// The core's title wins when it is not empty; an empty one (an old
    /// store's job) falls back to the spec.
    func testTheCoresTitleWinsAndAnEmptyOneFallsBack() {
        let spy = SpyCore()
        spy.coreTitle = "from-the-core.par2"
        let app = AppModel(core: spy)
        app.submit(.checksumVerify(ChecksumVerifySpec(file: "/abs/list.sfv")), showSheet: false)
        XCTAssertEqual(app.queue.jobs.first?.title, "from-the-core.par2")
        spy.coreTitle = ""
        app.refresh()
        XCTAssertEqual(app.queue.jobs.first?.title, "list.sfv")
    }

    private func survey(_ verdict: SurveyVerdict) -> Survey {
        Survey(set_name: "set.par2", folder: "/x", block_size: 4, source_blocks: 1,
               recovery_available: 0, recovery_needed: 1, verdict: verdict,
               files: [], block_runs: [])
    }

    /// `unrepairable` beside exit code 6 (a member with no description): an
    /// unrepairable set, with no Repair offered.
    func testUnrepairableBesideExitSixOffersNoRepair() {
        let model = VerifyModel()
        var result = JobResult()
        result.exit_code = 6
        model.snapshot = JobSnapshot(id: 1, kind: .verify, state: .done,
                                     survey: survey(.unrepairable), result: result)
        XCTAssertFalse(model.canRepair)
        XCTAssertFalse(model.endedWithoutVerdict)
        XCTAssertEqual(model.pillText, S.verifyPillUnrepairable(short: Fmt.count(1)))
    }

    /// A failed verify can still carry the core's PENDING survey (verdict
    /// `verifying`). The failure is read off the job's state, not the survey.
    func testAFailedVerifyWithAPendingSurveyIsStillFailed() {
        let model = VerifyModel()
        model.snapshot = JobSnapshot(id: 1, kind: .verify, state: .failed,
                                     survey: survey(.verifying),
                                     error: CoreError(code: "load_failed", message: "could not load /x/set.par2"))
        XCTAssertTrue(model.endedWithoutVerdict, "a pending survey drew a map for a failed verify")
        XCTAssertFalse(model.canRepair)
        XCTAssertTrue(model.pillText.contains("could not load"), model.pillText)
        model.snapshot?.state = .cancelled
        XCTAssertTrue(model.endedWithoutVerdict)
        XCTAssertEqual(model.pillText, S.verifyPillCancelled)
    }

    // MARK: - Section B: DemoRoute

    /// A path field marks itself edited only when the USER types: the pane's
    /// own autofill, written while the field is on screen, must not, or every
    /// later autofill is refused and the index stays where the previous
    /// sources put it (found driving the real app, 9 Nov 2026).
    func testAnAutofillIsNotAHandEdit() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pf-autofill-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var files: [String] = []
        for sub in ["one", "two", "three"] {
            let d = dir.appendingPathComponent(sub)
            try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
            let f = d.appendingPathComponent("\(sub).bin")
            try Data([1, 2, 3]).write(to: f)
            files.append(f.path)
        }
        let model = CreateModel()
        // The field's binding, as PathField builds it over `$model.output`.
        let field = PathField.userEdits(
            of: Binding(get: { model.output }, set: { model.output = $0 }),
            onEdit: { model.outputEdited = true })
        model.addSources([files[0]])
        model.addSources([files[1]])           // the index moves: an autofill
        XCTAssertFalse(model.outputEdited, "an autofill was taken for a hand edit")
        model.sources = []
        model.addSources([files[2]])
        XCTAssertEqual(model.output, dir.appendingPathComponent("three/three.par2").path,
                       "the index follows the sources until the user types one")
        XCTAssertEqual(field.wrappedValue, model.output)

        field.wrappedValue = "/somewhere/typed.par2"   // the user types
        XCTAssertTrue(model.outputEdited)
        model.addSources([files[0]])
        XCTAssertEqual(model.output, "/somewhere/typed.par2", "a typed index is kept")
    }

    func testARepeatedDemoQueryKeyDoesNotTrap() {
        let q = DemoRoute.query(URL(string: "parfast://demo?size=1x1&size=2x2")!)
        XCTAssertEqual(q["size"], "2x2")
    }
}

/// A `CoreClient` over `MockCore` that counts settings writes and, when asked,
/// strips `title` from every snapshot the way the real core leaves it out.
final class SpyCore: CoreClient {
    let inner = MockCore(speed: 60)
    private(set) var settingsWrites = 0
    var stripTitles = false
    /// A queue poll that throws, as a core that cannot answer does.
    var failSnapshots = false
    /// A settings read that throws.
    var failSettingsGet = false
    /// When set, every snapshot carries this title, as a core that sends one.
    var coreTitle: String?

    private func strip(_ job: JobSnapshot) -> JobSnapshot {
        var job = job
        if stripTitles { job.title = nil }
        if let coreTitle { job.title = coreTitle }
        return job
    }

    func setWake(_ handler: (@Sendable () -> Void)?) { inner.setWake(handler) }
    func submit(_ spec: JobSpec) throws -> Int64 { try inner.submit(spec) }
    func snapshot(job id: Int64) throws -> JobSnapshot { strip(try inner.snapshot(job: id)) }
    func queueSnapshot() throws -> QueueSnapshot {
        if failSnapshots { throw ClientError.badSpec("no answer") }
        var q = try inner.queueSnapshot()
        q.jobs = q.jobs.map(strip)
        return q
    }
    func cancel(job id: Int64) throws { try inner.cancel(job: id) }
    func pause(job id: Int64) throws { try inner.pause(job: id) }
    func resume(job id: Int64) throws { try inner.resume(job: id) }
    func remove(job id: Int64) throws { try inner.remove(job: id) }
    func runNext(job id: Int64) throws { try inner.runNext(job: id) }
    func setLowPriority(job id: Int64, _ on: Bool) throws { try inner.setLowPriority(job: id, on) }
    func clearQueuePostAction() throws { try inner.clearQueuePostAction() }
    func setQueuePaused(_ paused: Bool) throws { try inner.setQueuePaused(paused) }
    func setQueueConcurrency(_ n: UInt32) throws { try inner.setQueueConcurrency(n) }
    func setQueuePostAction(_ action: PostAction) throws { try inner.setQueuePostAction(action) }
    func planPreview(_ spec: CreateSpec) throws -> PlanPreview { try inner.planPreview(spec) }
    func capabilities() throws -> Capabilities { try inner.capabilities() }
    func settingsGet() throws -> CoreSettings {
        if failSettingsGet { throw ClientError.badSpec("no answer") }
        return try inner.settingsGet()
    }
    func settingsSet(_ settings: CoreSettings) throws {
        settingsWrites += 1
        try inner.settingsSet(settings)
    }
    func clearDigestCache() throws -> Int { try inner.clearDigestCache() }
    func lastError() -> CoreError? { inner.lastError() }
}
