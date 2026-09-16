import XCTest
@testable import ParfastApp
@testable import ParfastCore

/// The view models over `MockCore`, which is the whole point of the mock
/// (plan 7: "mac XCTest over the view models with MockCore").
@MainActor
final class ViewModelTests: XCTestCase {

    private func app(speed: Double = 60) -> AppModel {
        AppModel(core: MockCore(speed: speed))
    }

    private func waitFor(_ what: String, timeout: TimeInterval = 8,
                         _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTFail("timed out waiting for \(what)")
    }

    // MARK: - Drop routing (5.1)

    func testPar2GoesToVerifyAndStartsIt() {
        let app = app()
        app.mode = .create
        app.open(paths: [MockScenario.damagedRepairable.par2Path])
        XCTAssertEqual(app.mode, .verify)
        XCTAssertEqual(app.verify.par2Path, MockScenario.damagedRepairable.par2Path)
        XCTAssertNotNil(app.verify.jobId)
    }

    func testChecksumFileGoesToChecksumsVerify() {
        let app = app()
        for ext in AppModel.checksumExtensions {
            app.mode = .create
            app.open(paths: ["/abs/list.\(ext)"])
            XCTAssertEqual(app.mode, .checksums, ext)
            XCTAssertEqual(app.checksums.subMode, .verify, ext)
        }
    }

    func testAnythingElseGoesToCreateAsSources() {
        let app = app()
        let paths = (1...3).map { "\(MockScenario.mockRoot)/create/source.part0\($0).rar" }
        app.open(paths: paths)
        XCTAssertEqual(app.mode, .create)
        XCTAssertEqual(app.create.sources.map(\.path), paths)
    }

    func testAPar2InAMixedDropWins() {
        let app = app()
        app.open(paths: ["\(MockScenario.mockRoot)/create/source.part01.rar",
                         MockScenario.clean.par2Path])
        XCTAssertEqual(app.mode, .verify)
    }

    func testDroppingWhileAJobRunsAddsToTheQueue() {
        let app = app(speed: 1)
        app.open(paths: [MockScenario.tenThousandBlocks.par2Path])
        waitFor("the first job to start") { app.queue.running == 1 }
        app.open(paths: [MockScenario.clean.par2Path])
        app.refresh()
        XCTAssertEqual(app.queue.jobs.count, 2)
        XCTAssertEqual(app.queue.waiting, 1)
    }

    // MARK: - Verify

    func testRepairIsOnlyOfferedWhenTheVerdictSaysSo() {
        for (scenario, expected) in [(MockScenario.clean, false),
                                     (MockScenario.damagedRepairable, true),
                                     (MockScenario.unrepairable, false)] {
            let app = app()
            app.openPar2(scenario.par2Path)
            waitFor("verify of \(scenario.id)") {
                app.refresh()
                return app.verify.snapshot?.state.isFinished ?? false
            }
            XCTAssertEqual(app.verify.canRepair, expected, scenario.id)
        }
    }

    func testProblemsFilterHidesTheHealthyRows() {
        let app = app()
        app.openPar2(MockScenario.damagedRepairable.par2Path)
        waitFor("verify") {
            app.refresh()
            return app.verify.snapshot?.state.isFinished ?? false
        }
        app.verify.filter = .all
        let all = app.verify.rows().count
        app.verify.filter = .problems
        let problems = app.verify.rows()
        XCTAssertLessThan(problems.count, all)
        XCTAssertTrue(problems.allSatisfy { $0.status != .complete })
    }

    func testExcludingAFileSurvivesIntoTheRepairSpec() {
        let app = app()
        app.openPar2(MockScenario.damagedRepairable.par2Path)
        waitFor("verify") {
            app.refresh()
            return app.verify.snapshot?.state.isFinished ?? false
        }
        app.verify.toggleExcluded(["archive-set.part03.rar"])
        app.startRepair()
        waitFor("repair") {
            app.refresh()
            return app.verify.snapshot?.state.isFinished ?? false
        }
        XCTAssertEqual(app.verify.snapshot?.result?.repaired_files, 1)
    }

    func testTheSummaryCardOnlyAppearsAfterARepair() {
        let app = app()
        app.openPar2(MockScenario.damagedRepairable.par2Path)
        waitFor("verify") {
            app.refresh()
            return app.verify.snapshot?.state.isFinished ?? false
        }
        XCTAssertNil(app.verify.finishedRepair(in: app.queue))
        app.startRepair()
        waitFor("repair") {
            app.refresh()
            return app.verify.snapshot?.state.isFinished ?? false
        }
        XCTAssertNotNil(app.verify.finishedRepair(in: app.queue))
    }

    func testStatusTextNamesTheBadBlockCount() {
        let model = VerifyModel()
        let file = SurveyFile(name: "a", size: 1, status: .damaged, blocks_ok: 6, blocks_total: 10)
        XCTAssertTrue(model.statusText(file).contains("4"))
    }

    // MARK: - Create

    func testAddingSourcesFillsInTheBaseFolderAndTheOutputName() {
        let app = app()
        app.create.addSources((1...3).map { "\(MockScenario.mockRoot)/create/source.part0\($0).rar" })
        XCTAssertEqual(app.create.basePath, "\(MockScenario.mockRoot)/create")
        XCTAssertTrue(app.create.output.hasSuffix(".par2"))
        XCTAssertTrue(app.create.output.hasPrefix("\(MockScenario.mockRoot)/create/"))
    }

    func testATypedOutputNameIsNotOverwrittenByTheNextDrop() {
        let app = app()
        app.create.addSources(["\(MockScenario.mockRoot)/create/source.part01.rar"])
        app.create.output = "/tmp/mine.par2"
        app.create.outputEdited = true
        app.create.addSources(["\(MockScenario.mockRoot)/create/source.part02.rar"])
        XCTAssertEqual(app.create.output, "/tmp/mine.par2")
    }

    func testThePreviewFollowsTheControls() {
        let app = app()
        app.create.addSources((1...4).map { "\(MockScenario.mockRoot)/create/source.part0\($0).rar" })
        app.create.blockMode = .count
        app.create.blockCount = 1000
        app.create.recoveryMode = .percent
        app.create.recoveryPercent = 10
        app.create.recompute(with: app.core)
        let ten = try? XCTUnwrap(app.create.preview)
        app.create.recoveryPercent = 20
        app.create.recompute(with: app.core)
        let twenty = try? XCTUnwrap(app.create.preview)
        XCTAssertNotNil(ten)
        XCTAssertNotNil(twenty)
        XCTAssertEqual((twenty?.recovery_blocks ?? 0), (ten?.recovery_blocks ?? 0) * 2, accuracy: 2)
    }

    func testTheSchemeFamilyDrivesTheVolumeUnion() {
        let model = CreateModel()
        model.schemeFamily = .uniform
        model.uniformBy = .blocks
        model.uniformBlocks = 25
        XCTAssertEqual(model.volumes, .uniformBlocksPerFile(25))
        model.schemeFamily = .pow2Limit
        model.limitBy = .largest
        XCTAssertEqual(model.volumes, .pow2LimitLargestSource)
    }

    func testCreateWithNoSourcesAsksForSomeRatherThanSubmitting() {
        let app = app()
        app.startCreate()
        XCTAssertNotNil(app.alert)
        XCTAssertTrue(app.queue.jobs.isEmpty)
    }

    func testCreateRunsAndTheWrittenFilesMatchThePreview() {
        let app = app(speed: 60)
        app.create.addSources((1...4).map { "\(MockScenario.mockRoot)/create/source.part0\($0).rar" })
        app.create.recompute(with: app.core)
        let promised = app.create.preview?.files.map(\.name) ?? []
        app.startCreate()
        waitFor("create", timeout: 12) {
            app.refresh()
            return app.create.snapshot?.state.isFinished ?? false
        }
        XCTAssertEqual(app.create.snapshot?.result?.written?.map(\.name), promised)
        XCTAssertFalse(promised.isEmpty)
    }

    // MARK: - Checksums and the queue

    /// A checksum verify with problems finishes FAILED and still carries its
    /// rows. The screen must read the result off the snapshot rather than
    /// gating on `.done`, or it shows an empty table on exactly the file the
    /// user opened it for.
    func testAFailedChecksumVerifyStillFillsTheScreen() {
        let app = app()
        app.openChecksumFile("/abs/set.sfv")
        waitFor("checksum verify") {
            app.refresh()
            return app.checksums.snapshot?.state.isFinished ?? false
        }
        XCTAssertFalse(app.checksums.isBusy)
        XCTAssertNotNil(app.checksums.result, "the totals survive a failed job")
        XCTAssertFalse(app.checksums.entries.isEmpty, "and so do the rows")
    }

    func testChecksumVerifyReportsItsTotals() {
        let app = app()
        app.openChecksumFile("/abs/set.sfv")
        waitFor("checksum verify") {
            app.refresh()
            return app.checksums.snapshot?.state.isFinished ?? false
        }
        let result = app.checksums.result
        XCTAssertEqual(result?.mismatch, 1)
        XCTAssertEqual(result?.missing, 1)
        XCTAssertEqual((result?.ok ?? 0) + (result?.mismatch ?? 0) + (result?.missing ?? 0), 12)
        // `result.checksum.entries` landed 12 Sep, so the table has rows.
        XCTAssertEqual(app.checksums.entries.count, 12)
    }

    func testThreeQueuedJobsRunInOrder() {
        let app = app(speed: 40)
        for scenario in [MockScenario.clean, .damagedRepairable, .unicodeNames] {
            _ = app.submit(.verify(VerifySpec(par2: scenario.par2Path)), showSheet: false)
        }
        waitFor("the queue to drain", timeout: 14) {
            app.refresh()
            return !app.queue.jobs.isEmpty && app.queue.jobs.allSatisfy { $0.state.isFinished }
        }
        XCTAssertEqual(app.queue.jobs.map { $0.title },
                       ["holiday-video.par2", "archive-set.par2", "Sommerferien Öresund.par2"])
    }

    func testPostActionAsksBeforeSleepingTheMac() {
        let app = app()
        app.setPostAction(.sleep)
        XCTAssertNotNil(app.alert, "sleep must confirm once, when it is set")
        XCTAssertEqual(app.queue.post_action, .none, "and not take effect until it is confirmed")
        app.alert?.action?()
        app.refresh()
        XCTAssertEqual(app.queue.post_action, .sleep)
    }

    func testNotifyPostActionNeedsNoConfirmation() {
        let app = app()
        app.setPostAction(.notify)
        XCTAssertNil(app.alert)
        XCTAssertEqual(app.queue.post_action, .notify)
    }
}

/// The copy rules (CLAUDE.md invariant 6, plan 5.7) hold over the GENERATED
/// table, so a string added to en.json without re-reading the rules fails
/// here as well as in `Tools/generate.py --check`.
final class CopyRuleTests: XCTestCase {

    /// Every string constant the generator emitted, by reflection over the
    /// catalogue it also writes - which is the one list that cannot go stale
    /// against `S` because the same run produced both.
    ///
    /// Read from the SOURCE tree by `#filePath`, not out of the built resource
    /// bundle. SwiftPM 6.3 copies the catalogue into the bundle verbatim, but
    /// SwiftPM 6.4 compiles it to `en.lproj/Localizable.strings` and ships no
    /// `.xcstrings` at all, so a `Bundle.module` lookup found nothing and all
    /// three tests failed on that toolchain while passing on CI's. The source
    /// file is exactly what `Tools/generate.py` writes, on every toolchain. A
    /// missing file still throws: failing to find is failing.
    private func catalogueValues() throws -> [String: String] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ParfastAppTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // mac
            .appendingPathComponent("Sources/ParfastApp/Resources/Localizable.xcstrings")
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let strings = try XCTUnwrap(root["strings"] as? [String: Any])
        var out: [String: String] = [:]
        for (key, entry) in strings {
            let locals = (entry as? [String: Any])?["localizations"] as? [String: Any]
            let unit = (locals?["en"] as? [String: Any])?["stringUnit"] as? [String: Any]
            out[key] = unit?["value"] as? String
        }
        return out
    }

    func testNoDashesAsPunctuation() throws {
        for (key, value) in try catalogueValues() {
            XCTAssertFalse(value.contains("\u{2014}"), "\(key) carries an em-dash")
            XCTAssertFalse(value.contains("\u{2013}"), "\(key) carries an en-dash")
        }
    }

    func testTheBannedWordIsAbsent() throws {
        for (key, value) in try catalogueValues() {
            XCTAssertFalse(value.lowercased().contains("streaming"), "\(key)")
        }
    }

    func testTheCatalogueAndTheSwiftConstantsAgree() throws {
        let catalogue = try catalogueValues()
        XCTAssertGreaterThan(catalogue.count, 200)
        // Spot-check across the screens rather than reflecting over an enum,
        // which Swift cannot enumerate: a drift shows up as a build error in
        // the views long before it shows up here.
        XCTAssertEqual(catalogue["mode.verify"], S.modeVerify)
        XCTAssertEqual(catalogue["create.output.title"], S.createOutputTitle)
        XCTAssertEqual(catalogue["queue.state.interrupted"], S.queueStateInterrupted)
    }
}
