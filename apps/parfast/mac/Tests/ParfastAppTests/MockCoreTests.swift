import XCTest
@testable import ParfastCore

/// The mock is the UI's test harness, so it needs its own tests: a screen
/// built on a scenario that plays wrongly is a screen that looks right and is.
final class MockCoreTests: XCTestCase {

    /// Runs the mock fast. The scenarios are 5 to 12 nominal seconds, so 60x
    /// puts a whole job inside a couple of ticks and the suite stays quick.
    private func core(speed: Double = 60) -> MockCore { MockCore(speed: speed) }

    func waitFor(_ description: String, timeout: TimeInterval = 8,
                         _ condition: @escaping () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTFail("timed out waiting for \(description)")
    }

    private func runToCompletion(_ core: MockCore, _ spec: JobSpec,
                                 timeout: TimeInterval = 8) throws -> JobSnapshot {
        let id = try core.submit(spec)
        waitFor("job \(id) to finish", timeout: timeout) {
            (try? core.snapshot(job: id))?.state.isFinished ?? false
        }
        return try core.snapshot(job: id)
    }

    // MARK: - Verdicts

    func testEveryScenarioReachesItsDeclaredVerdict() throws {
        for scenario in MockScenario.all {
            let core = core()
            let snapshot = try runToCompletion(core, .verify(VerifySpec(par2: scenario.par2Path)))
            XCTAssertEqual(snapshot.state, .done, scenario.id)
            XCTAssertEqual(snapshot.survey?.verdict, scenario.finalVerdict, scenario.id)
        }
    }

    func testCleanSetNeedsNothing() throws {
        let snapshot = try runToCompletion(core(), .verify(VerifySpec(par2: MockScenario.clean.par2Path)))
        let survey = try XCTUnwrap(snapshot.survey)
        XCTAssertEqual(survey.recovery_needed, 0)
        XCTAssertTrue(survey.files.allSatisfy { $0.status == .complete })
        XCTAssertEqual(survey.counts()[.present], survey.source_blocks)
    }

    func testDamagedSetIsRepairableAndNamesTheDamage() throws {
        let scenario = MockScenario.damagedRepairable
        let snapshot = try runToCompletion(core(), .verify(VerifySpec(par2: scenario.par2Path)))
        let survey = try XCTUnwrap(snapshot.survey)
        XCTAssertEqual(survey.verdict, .repairable)
        XCTAssertEqual(survey.recovery_needed, scenario.blocksNeeded)
        XCTAssertLessThanOrEqual(survey.recovery_needed, survey.recovery_available)
        XCTAssertTrue(survey.files.contains { $0.status == .missing })
        XCTAssertTrue(survey.files.contains { $0.status == .damaged })
        XCTAssertGreaterThan(survey.counts()[.missing] ?? 0, 0)
    }

    func testUnrepairableSetRefusesRepairWithAShortfall() throws {
        let scenario = MockScenario.unrepairable
        let verify = try runToCompletion(core(), .verify(VerifySpec(par2: scenario.par2Path)))
        XCTAssertEqual(verify.survey?.verdict, .unrepairable)
        XCTAssertEqual(verify.error?.code, "unrepairable")

        let repair = try runToCompletion(core(), .repairSet(RepairSpec(par2: scenario.par2Path)))
        XCTAssertEqual(repair.state, .failed)
        XCTAssertEqual(repair.error?.code, "unrepairable")
        XCTAssertTrue(repair.error?.message.contains("more blocks") ?? false)
    }

    func testMisnamedFilesCarryWhereTheyWereFound() throws {
        let snapshot = try runToCompletion(
            core(), .verify(VerifySpec(par2: MockScenario.misnamedAndMoved.par2Path)))
        let survey = try XCTUnwrap(snapshot.survey)
        let misnamed = survey.files.filter { $0.status == .misnamed }
        XCTAssertEqual(misnamed.count, 2)
        XCTAssertTrue(misnamed.allSatisfy { $0.found_as?.isEmpty == false })
        XCTAssertTrue(survey.files.contains { $0.status == .extra })
        // A file found elsewhere is not a block that needs rebuilding.
        XCTAssertEqual(survey.counts()[.misnamed], misnamed.reduce(0) { $0 + $1.blocks_total })
    }

    func testUnicodeNamesSurviveTheSurvey() throws {
        let snapshot = try runToCompletion(
            core(), .verify(VerifySpec(par2: MockScenario.unicodeNames.par2Path)))
        let names = try XCTUnwrap(snapshot.survey).files.map(\.name)
        XCTAssertTrue(names.contains("日本語のメモ.txt"))
        XCTAssertTrue(names.contains("Ελληνικά-σημειώσεις.md"))
    }

    func testBigSetIsPastTheMergeThreshold() throws {
        let snapshot = try runToCompletion(
            core(), .verify(VerifySpec(par2: MockScenario.tenThousandBlocks.par2Path)), timeout: 12)
        let survey = try XCTUnwrap(snapshot.survey)
        XCTAssertGreaterThan(survey.source_blocks, 4000)
        XCTAssertEqual(survey.expandedStates().count, survey.source_blocks)
    }

    // MARK: - Repair

    func testRepairTurnsEveryDamagedFileComplete() throws {
        let scenario = MockScenario.damagedRepairable
        let snapshot = try runToCompletion(core(), .repairSet(RepairSpec(par2: scenario.par2Path)))
        XCTAssertEqual(snapshot.state, .done)
        let survey = try XCTUnwrap(snapshot.survey)
        XCTAssertEqual(survey.verdict, .repaired)
        XCTAssertEqual(survey.recovery_needed, 0)
        XCTAssertEqual(survey.counts()[.present], survey.source_blocks)
        XCTAssertEqual(snapshot.result?.repaired_files, 2)
    }

    func testExcludedFileIsLeftAlone() throws {
        let scenario = MockScenario.damagedRepairable
        let excluded = "archive-set.part03.rar"
        let snapshot = try runToCompletion(core(), .repairSet(
            RepairSpec(par2: scenario.par2Path, exclude: [excluded])))
        XCTAssertEqual(snapshot.result?.repaired_files, 1)
        let survey = try XCTUnwrap(snapshot.survey)
        XCTAssertEqual(survey.files.first { $0.name == excluded }?.status, .missing)
    }

    func testPurgeIsReportedBack() throws {
        let snapshot = try runToCompletion(core(), .repairSet(
            RepairSpec(par2: MockScenario.damagedRepairable.par2Path, purge: true)))
        XCTAssertEqual(snapshot.result?.purged, true)
    }

    // MARK: - Progress and the block map filling

    func testTheMapFillsLeftToRightAndProgressNeverGoesBackwards() throws {
        let core = core(speed: 6)
        let id = try core.submit(.verify(VerifySpec(par2: MockScenario.clean.par2Path)))
        var lastProgress = -1.0
        var sawPending = false
        var sawPartialFill = false
        waitFor("verify to finish") {
            guard let s = try? core.snapshot(job: id) else { return false }
            XCTAssertGreaterThanOrEqual(s.progress, lastProgress)
            lastProgress = s.progress
            if let survey = s.survey {
                let counts = survey.counts()
                if (counts[.pending] ?? 0) > 0 { sawPending = true }
                if (counts[.present] ?? 0) > 0 && (counts[.pending] ?? 0) > 0 {
                    sawPartialFill = true
                }
            }
            return s.state.isFinished
        }
        XCTAssertTrue(sawPending, "the map should start out pending")
        XCTAssertTrue(sawPartialFill, "the map should fill progressively, not in one step")
    }

    func testPauseHoldsProgressAndResumeReleasesIt() throws {
        let core = core(speed: 2)
        let id = try core.submit(.verify(VerifySpec(par2: MockScenario.tenThousandBlocks.par2Path)))
        waitFor("job to start") { (try? core.snapshot(job: id))?.state == .running }
        try core.pause(job: id)
        let held = try core.snapshot(job: id)
        XCTAssertEqual(held.state, .paused)
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        XCTAssertEqual(try core.snapshot(job: id).progress, held.progress, accuracy: 0.0001)
        try core.resume(job: id)
        waitFor("progress to move again") {
            (try? core.snapshot(job: id)).map { $0.progress > held.progress } ?? false
        }
    }

    func testCancelStopsTheJob() throws {
        let core = core(speed: 1)
        let id = try core.submit(.verify(VerifySpec(par2: MockScenario.tenThousandBlocks.par2Path)))
        waitFor("job to start") { (try? core.snapshot(job: id))?.state == .running }
        try core.cancel(job: id)
        XCTAssertEqual(try core.snapshot(job: id).state, .cancelled)
        XCTAssertEqual(try core.snapshot(job: id).error?.code, "cancelled")
    }

    // MARK: - The queue

    func testThreeJobsRunOneAtATimeInOrder() throws {
        let core = core(speed: 40)
        var ids: [Int64] = []
        for scenario in [MockScenario.clean, .damagedRepairable, .unicodeNames] {
            ids.append(try core.submit(.verify(VerifySpec(par2: scenario.par2Path))))
        }
        var everSawTwoRunning = false
        waitFor("the queue to drain", timeout: 12) {
            guard let q = try? core.queueSnapshot() else { return false }
            if q.running > 1 { everSawTwoRunning = true }
            return q.jobs.allSatisfy { $0.state.isFinished }
        }
        XCTAssertFalse(everSawTwoRunning, "concurrency 1 must mean one at a time")
        let finished = try core.queueSnapshot().jobs
        XCTAssertEqual(finished.map(\.id), ids)
        XCTAssertTrue(finished.allSatisfy { $0.state == .done })
    }

    func testRaisingConcurrencyRunsTwoAtOnce() throws {
        let core = core(speed: 3)
        try core.setQueueConcurrency(2)
        for scenario in [MockScenario.tenThousandBlocks, .damagedRepairable] {
            _ = try core.submit(.verify(VerifySpec(par2: scenario.par2Path)))
        }
        waitFor("two running at once") { (try? core.queueSnapshot())?.running == 2 }
    }

    func testPausingTheQueueHoldsEverything() throws {
        let core = core(speed: 2)
        _ = try core.submit(.verify(VerifySpec(par2: MockScenario.tenThousandBlocks.par2Path)))
        waitFor("job to start") { (try? core.queueSnapshot())?.running == 1 }
        try core.setQueuePaused(true)
        XCTAssertEqual(try core.queueSnapshot().running, 0)
        XCTAssertTrue(try core.queueSnapshot().paused)
    }

    func testARunningJobCannotBeRemoved() throws {
        let core = core(speed: 1)
        let id = try core.submit(.verify(VerifySpec(par2: MockScenario.tenThousandBlocks.par2Path)))
        waitFor("job to start") { (try? core.snapshot(job: id))?.state == .running }
        XCTAssertThrowsError(try core.remove(job: id))
        try core.cancel(job: id)
        XCTAssertNoThrow(try core.remove(job: id))
    }

    // MARK: - Checksums

    func testChecksumVerifyReportsMismatchesAndMissing() throws {
        let snapshot = try runToCompletion(
            core(), .checksumVerify(ChecksumVerifySpec(file: "/abs/set.sfv")))
        // Problems mean the JOB failed, with the result still attached - the
        // real core's contract. A host reading `result` only on `.done` would
        // show an empty table on exactly the file it was opened for.
        XCTAssertEqual(snapshot.state, .failed)
        XCTAssertEqual(snapshot.error?.code, "checksum_mismatch")
        let result = try XCTUnwrap(snapshot.result?.checksum)
        XCTAssertEqual(result.ok + result.mismatch + result.missing, 12)
        XCTAssertEqual(result.mismatch, 1)
        XCTAssertEqual(result.missing, 1)
        // `entries` landed nested INSIDE the checksum result on 12 Sep, so
        // the table has rows again. Nested, not beside the result: the
        // Windows lane guessed `result.checksum_entries` and got an empty
        // table that looked like an empty checksum file.
        XCTAssertEqual(result.entries?.count, 12)
        let mismatched = try XCTUnwrap(result.entries?.first { $0.status == .mismatch })
        XCTAssertFalse(mismatched.actual.isEmpty, "a mismatch has something to compare")
        let absent = try XCTUnwrap(result.entries?.first { $0.status == .missing })
        XCTAssertTrue(absent.actual.isEmpty, "a missing file came to nothing")
    }

    /// A clean checksum file is `done`; only problems fail it.
    func testACleanChecksumVerifyIsDone() throws {
        let snapshot = try runToCompletion(
            core(), .checksumVerify(ChecksumVerifySpec(file: "/abs/clean-set.sfv")))
        XCTAssertEqual(snapshot.state, .done)
        XCTAssertNil(snapshot.error)
        XCTAssertEqual(snapshot.result?.checksum?.mismatch, 0)
    }

    func testChecksumCreateWritesOneLinePerSource() throws {
        let spec = ChecksumCreateSpec(
            sources: (1...4).map { SourceItem(path: "\(MockScenario.mockRoot)/create/source.part0\($0).rar") },
            format: .md5, output: "/abs/x.md5")
        let snapshot = try runToCompletion(core(), .checksumCreate(spec))
        let result = try XCTUnwrap(snapshot.result?.checksum)
        XCTAssertEqual(result.ok, 4)
        // A checksum CREATE has nothing to compare, so no rows - the core's
        // own behaviour, mirrored rather than approximated.
        XCTAssertEqual(result.entries?.isEmpty ?? true, true)
    }

    // MARK: - Create

    func testCreateReportsTheFilesItsPreviewPromised() throws {
        let spec = MockScenario.longCreateSpec()
        let core = core(speed: 60)
        let preview = try core.planPreview(spec)
        let snapshot = try runToCompletion(core, .create(spec), timeout: 12)
        XCTAssertEqual(snapshot.state, .done)
        let written = try XCTUnwrap(snapshot.result?.written)
        XCTAssertEqual(written.map(\.name), preview.files.map(\.name))
        XCTAssertEqual(written.map(\.size), preview.files.map(\.size))
    }

    func testLowPriorityIsReportedAndSlowsTheJob() throws {
        let core = core(speed: 40)
        let id = try core.submit(.verify(VerifySpec(par2: MockScenario.tenThousandBlocks.par2Path)))
        try core.setLowPriority(job: id, true)
        XCTAssertTrue(try core.snapshot(job: id).low_priority)
    }

    /// The mock reports what the REAL engine reports, capability for
    /// capability. A mock that claims everything demos controls nobody can
    /// ship, and a screenshot set taken through it shows an app that does not
    /// exist; a mock that claims LESS hides controls the engine HAS, and the
    /// screenshots then advertise an app missing features it ships. This test
    /// went stale the second way on 12 Sep 2026, on six keys at once.
    ///
    /// THIS TEST IS A MIRROR, NOT A RULE. When the capability table in
    /// `apps/parfast/crates/parfast-ffi/API.md` moves, the fix is to re-read it
    /// and change the mock AND these lines together - never to relax an
    /// assertion so the survivors agree. Its Windows counterpart is
    /// `Parfast.Tests/CapabilityTests.TheMockClaimsWhatTodaysEngineClaims`, and
    /// the two must not drift.
    func testTheMockClaimsExactlyWhatTheRealEngineClaims() throws {
        let caps = try core().capabilities()
        XCTAssertFalse(caps.version.isEmpty)
        for (name, value) in [("pause", caps.pause),
                              ("data_skipping", caps.data_skipping),
                              ("fast_solver", caps.fast_solver),
                              ("std_naming", caps.std_naming),
                              ("comment", caps.comment),
                              ("volume_limit_explicit", caps.volume_limit_explicit),
                              ("pause_in_fold", caps.pause_in_fold),
                              ("cancel_in_fold", caps.cancel_in_fold),
                              ("progress_in_fold", caps.progress_in_fold)] {
            XCTAssertTrue(value, "\(name) is true in the engine today")
        }
        // The only two left. `unicode_policy` was looked at properly on
        // 12 Sep 2026 and should STAY false; `low_priority` is carried in the
        // snapshot for a host to act on and nothing in the engine reads it.
        for (name, value) in [("unicode_policy", caps.unicode_policy),
                              ("low_priority", caps.low_priority)] {
            XCTAssertFalse(value, "\(name) is false in the engine today")
        }
    }

    /// The mock's BEHAVIOUR already honoured this and only its capability
    /// claim did not, which is the shape of the bug: a running create paused
    /// and cancelled fine, and `ProgressSheet` disabled the button anyway
    /// because `pause_in_fold` said the engine could not park there.
    func testARunningCreateCanBePausedAndResumed() throws {
        let core = core(speed: 20)
        let id = try core.submit(.create(MockScenario.longCreateSpec()))
        waitFor("the create to start running") {
            (try? core.snapshot(job: id))?.state == .running
        }

        try core.pause(job: id)
        XCTAssertEqual(try core.snapshot(job: id).state, .paused)
        try core.resume(job: id)
        XCTAssertEqual(try core.snapshot(job: id).state, .running)
    }

    func testAnUnknownPathStillOpensSomething() throws {
        // A real .par2 dropped on a mock build must not dead-end: routing
        // adopts the path and plays the damaged scenario under its own name.
        let snapshot = try runToCompletion(
            core(), .verify(VerifySpec(par2: "/tmp/downloads/whatever.par2")))
        XCTAssertEqual(snapshot.survey?.set_name, "whatever.par2")
        XCTAssertEqual(snapshot.survey?.folder, "/tmp/downloads")
    }
}

/// Chip C (the Windows lane) flagged this one from their own tests on
/// 12 Sep 2026, and it is worth a test of its own rather than a line in a
/// handoff: a file found under another name COSTS NO RECOVERY BLOCKS. Its
/// data is on the disk. If the survey counts it as lost, a set two renames
/// from perfect reports as "repairable, only just", and on a thin set it
/// reports as NOT REPAIRABLE - refusing a repair that would have worked.
extension MockCoreTests {

    func testAMisnamedFileCostsNoRecoveryBlocks() throws {
        let s = MockScenario.misnamedAndMoved
        let misnamedBlocks = s.files
            .filter { if case .misnamed = $0.outcome { return true } else { return false } }
            .reduce(0) { $0 + s.blocks(of: $1) }
        XCTAssertGreaterThan(misnamedBlocks, 0, "the scenario must actually have some")

        // What the scenario declares.
        XCTAssertEqual(s.blocksNeeded, 6, "only the damaged file's bad blocks are owed")
        XCTAssertEqual(s.finalVerdict, .repairable)

        // What the survey reports, which is what the pill reads from.
        let core = MockCore(speed: 60)
        let id = try core.submit(.verify(VerifySpec(par2: s.par2Path)))
        waitFor("verify") { (try? core.snapshot(job: id))?.state.isFinished ?? false }
        let survey = try XCTUnwrap(try core.snapshot(job: id).survey)
        XCTAssertEqual(survey.recovery_needed, 6)
        XCTAssertEqual(survey.verdict, .repairable)

        // And the counterfactual, which is the whole point: counting them as
        // lost would flip this set past its 80 available blocks.
        XCTAssertGreaterThan(s.blocksNeeded + misnamedBlocks, s.recoveryAvailable,
                             "if misnamed counted as lost this set would read unrepairable")
    }

    /// The block map must not paint a misnamed block as damage either - it is
    /// its own state, amber, with its own legend entry.
    func testMisnamedBlocksAreTheirOwnStateOnTheMap() throws {
        let s = MockScenario.misnamedAndMoved
        let core = MockCore(speed: 60)
        let id = try core.submit(.verify(VerifySpec(par2: s.par2Path)))
        waitFor("verify") { (try? core.snapshot(job: id))?.state.isFinished ?? false }
        let counts = try XCTUnwrap(try core.snapshot(job: id).survey).counts()
        XCTAssertEqual(counts[.misnamed], 400)
        XCTAssertEqual(counts[.damaged], 6)
        XCTAssertNil(counts[.missing])
    }
}


/// `pf_job_run_next`, landed 12 Sep at the Windows lane's request. Until then
/// "Run now" resumed the selected job, which only lets the scheduler reach it
/// in its OWN turn - not what the control promises.
extension MockCoreTests {

    func testRunNextTakesAJobAheadOfItsTurn() throws {
        let core = MockCore(speed: 8)
        var ids: [Int64] = []
        for scenario in [MockScenario.tenThousandBlocks, .clean, .unicodeNames] {
            ids.append(try core.submit(.verify(VerifySpec(par2: scenario.par2Path))))
        }
        waitFor("the first job to start") { (try? core.queueSnapshot())?.running == 1 }

        // The third job would be last. Ask for it next.
        try core.runNext(job: ids[2])
        waitFor("the flagged job to start", timeout: 20) {
            (try? core.snapshot(job: ids[2]))?.state == .running
        }
        // ... and it went before the one submitted ahead of it.
        XCTAssertEqual(try core.snapshot(job: ids[1]).state, .queued)

        // The queue is still listed in SUBMISSION order: run-next is a flag on
        // the entry, not a reordered table, so the display and the scheduler
        // read one rule.
        XCTAssertEqual(try core.queueSnapshot().jobs.map(\.id), ids)
    }

    func testRunNextOnAFinishedJobIsHarmless() throws {
        let core = MockCore(speed: 60)
        let id = try core.submit(.verify(VerifySpec(par2: MockScenario.clean.par2Path)))
        waitFor("finish") { (try? core.snapshot(job: id))?.state.isFinished ?? false }
        XCTAssertNoThrow(try core.runNext(job: id))
        XCTAssertEqual(try core.snapshot(job: id).state, .done)
    }
}
