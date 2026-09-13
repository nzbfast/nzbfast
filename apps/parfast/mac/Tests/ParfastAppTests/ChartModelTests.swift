import XCTest
@testable import ParfastApp
@testable import ParfastCore

/// The three charts of the 12 September 2026 prettiness review, section 4, in the
/// only place they can be tested without a window: their pure models.
///
/// TESTS ARE NECESSARY AND NOT SUFFICIENT HERE, and the review itself is the
/// evidence - it came out of looking at pictures of an app whose whole suite was
/// green. So these pin the things a picture cannot show: the arithmetic, the
/// refusal arms, and the cases where a chart must decline to draw rather than draw
/// something plausible. The picture is checked by building the bundle and shooting
/// it, which is the other half and is not optional.
///
/// Ported case for case from the Windows `ChartModelTests.cs`, deliberately: a
/// chart that draws a different series on the two platforms is the failure the
/// shared models exist to prevent, and a test suite that only overlaps by accident
/// cannot see it.
@MainActor
final class ChartModelTests: XCTestCase {

    // MARK: - (a) the create cost bar

    private func plan(sourceBytes: Int64, totalBytes: Int64, recoveryBytes: Int64,
                      paddingBytes: Int64 = 4_096) -> PlanPreview {
        PlanPreview(
            block_size: 1 << 20, block_count: 2_000,
            padding_bytes: paddingBytes,
            padding_pct: sourceBytes == 0 ? 0 : Double(paddingBytes) / Double(sourceBytes) * 100,
            efficiency_pct: 99, recovery_blocks: 200, recovery_percent: 10,
            recovery_bytes: recoveryBytes, total_bytes: totalBytes,
            files: [], command: "", warnings: [],
            source_bytes: sourceBytes, source_files: 3)
    }

    func testCostBarIsEmptyWithNoPlan() {
        let model = CostBarModel(nil)
        XCTAssertFalse(model.hasPlan)
        XCTAssertTrue(model.segments.isEmpty)
        XCTAssertEqual(model.footprintText, "")
        XCTAssertEqual(model.paddingText, "")
    }

    /// The whole is source PLUS the PAR2 set, so a ten per cent set is nine point
    /// one per cent of the bar. This is the number a reader could check against
    /// the recovery percentage beside it, and the two are allowed to differ only
    /// because the bar's caption names what it is a proportion OF.
    func testCostBarWholeIsTheFootprintAndNotTheSource() {
        let model = CostBarModel(plan(sourceBytes: 1_000_000_000,
                                      totalBytes: 100_000_000,
                                      recoveryBytes: 99_000_000))
        XCTAssertTrue(model.hasPlan)
        XCTAssertEqual(model.footprintBytes, 1_100_000_000)
        XCTAssertEqual(model.segments.count, 2)
        XCTAssertEqual(model.segments[0].kind, .source)
        XCTAssertEqual(model.segments[1].kind, .par2)
        XCTAssertEqual(model.segments[0].share + model.segments[1].share, 1.0, accuracy: 1e-9)
        XCTAssertEqual(model.par2Share, 100_000_000.0 / 1_100_000_000, accuracy: 1e-9)
    }

    /// THE DEFECT THAT MOTIVATED THE MOCK FIX, pinned so it cannot come back. With
    /// `source_bytes` unset the whole is the PAR2 set alone and the bar draws ONE
    /// HUNDRED PER CENT RECOVERY over a 2 GiB source, confidently - which is what
    /// every mock-driven demo and screenshot would have shown.
    func testAnUnsetSourceSizeDoesNotDrawAFullBarOfRecovery() {
        var preview = plan(sourceBytes: 0, totalBytes: 100_000_000, recoveryBytes: 99_000_000)
        preview.source_bytes = nil
        let model = CostBarModel(preview)
        XCTAssertEqual(model.par2Share, 1.0, "an absent source size still draws a full PAR2 bar")

        // And the planner the demo actually runs on fills it in, which is the half
        // that stops the case above being reachable.
        let live = MockPlanner.plan(
            spec: CreateSpec(block: .count(2_000), recovery: .percent(10),
                             output: "/abs/set.par2"),
            sources: [MockPlanner.Source(name: "a.bin", size: 2 << 30, path: "/abs/a.bin")])
        XCTAssertEqual(live.source_bytes, 2 << 30)
        XCTAssertEqual(live.source_files, 1)
        let bar = CostBarModel(live)
        XCTAssertLessThan(bar.par2Share, 0.2, "a ten per cent set is about 9% of the footprint")
        XCTAssertGreaterThan(bar.par2Share, 0.05)
    }

    /// Padding is never a segment at any size, because it is never written. The
    /// figure is reported instead, WITH the reason - a bare number beside a
    /// part-to-whole picture reads as a part somebody forgot to draw.
    func testPaddingIsNeverASegmentAndCarriesItsReason() {
        let model = CostBarModel(plan(sourceBytes: 1_000_000_000, totalBytes: 100_000_000,
                                      recoveryBytes: 99_000_000, paddingBytes: 900_000_000))
        XCTAssertFalse(model.segments.contains { $0.bytes == 900_000_000 })
        XCTAssertEqual(model.segments.count, 2)
        XCTAssertTrue(model.paddingText.contains("not part of the bar"))
    }

    /// A share whose point width is under the floor is NOT drawn and NOT widened:
    /// in a proportion bar the width is the value. The block map floors a bad tick
    /// instead, because there the tick carries presence and the ground beside it
    /// carries the proportion - the two rules are opposite on purpose.
    func testIsDrawableIsAPixelTestAndNotAShareTest() {
        let cases: [(Double, Double, Bool)] = [
            (0.0, 600, false),
            (0.000_018, 600, false),  // a 40 KiB index against 2.2 GiB
            (0.004, 600, false),      // 2.4 points, under the floor
            (0.005, 600, true),       // 3.0 points, exactly at it
            (0.5, 600, true),
            (0.5, 4, false),          // a bar too narrow to draw anything honestly
        ]
        for (share, width, drawable) in cases {
            XCTAssertEqual(CostBarModel.isDrawable(share: share, width: width), drawable,
                           "share \(share) in \(width)")
        }
    }

    func testPar2SegmentAccountsForTheIndexInWordsRatherThanInInk() {
        let model = CostBarModel(plan(sourceBytes: 1_000_000_000, totalBytes: 100_040_960,
                                      recoveryBytes: 100_000_000))
        let inside = model.describeInside(model.segments[1])
        XCTAssertTrue(inside.contains("parity"))
        XCTAssertTrue(inside.contains("index"))
        XCTAssertEqual(model.describeInside(model.segments[0]), "")
    }

    func testCostBarSummaryIsASentenceAndNotALabel() {
        XCTAssertEqual(CostBarModel(nil).accessibleSummary(), "No plan yet.")
        let summary = CostBarModel(plan(sourceBytes: 1_000_000_000, totalBytes: 100_000_000,
                                        recoveryBytes: 99_000_000)).accessibleSummary()
        XCTAssertTrue(summary.contains("PAR2 set"))
        XCTAssertTrue(summary.contains("on disk"))
        XCTAssertFalse(summary.contains("{"))
    }

    /// A segment's own legend line quotes a share out of a hundred, so the two
    /// have to add up to one hundred per cent and neither may be clamped.
    func testSegmentFiguresAreSharesOfTheFootprint() {
        let model = CostBarModel(plan(sourceBytes: 3_000_000_000, totalBytes: 1_000_000_000,
                                      recoveryBytes: 990_000_000))
        XCTAssertTrue(model.describe(model.segments[0]).contains("75.0%"),
                      model.describe(model.segments[0]))
        XCTAssertTrue(model.describe(model.segments[1]).contains("25.0%"),
                      model.describe(model.segments[1]))
    }

    /// The bar has to MOVE as the recovery slider moves, which is the whole reason
    /// it is drawn from the live preview rather than from a finished plan.
    func testCostBarGrowsWithRecovery() {
        var model = CostBarModel(plan(sourceBytes: 1_000_000_000, totalBytes: 50_000_000,
                                      recoveryBytes: 49_500_000))
        let small = model.par2Share
        model.update(plan(sourceBytes: 1_000_000_000, totalBytes: 200_000_000,
                          recoveryBytes: 198_000_000))
        XCTAssertGreaterThan(model.par2Share, small,
                             "the PAR2 share went \(small) -> \(model.par2Share)")
    }

    // MARK: - (b) the rate history

    func testRateHistoryHasNoShapeUntilThereIsOne() {
        let rates = RateHistory()
        XCTAssertFalse(rates.hasShape)
        rates.push(elapsedMs: 0, rateBytesPerS: 1_000_000)
        XCTAssertFalse(rates.hasShape, "one sample is a point, not a shape")
        rates.push(elapsedMs: 1_000, rateBytesPerS: 2_000_000)
        XCTAssertTrue(rates.hasShape)
    }

    /// A series of zeroes is not a shape. A job in a phase that moves no bytes
    /// would otherwise draw a flat line along the floor, which reads as a stall
    /// rather than as an absence of measurement.
    func testAllZeroesIsNotAShape() {
        let rates = RateHistory()
        for s in 0..<30 { rates.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: 0) }
        XCTAssertEqual(rates.count, 30)
        XCTAssertFalse(rates.hasShape)
        XCTAssertGreaterThanOrEqual(rates.displayMax, 1, "the scale never divides by zero")
    }

    /// THE X AXIS IS ELAPSED SECONDS, NOT POLLS. Twenty snapshots inside one
    /// second are one sample, and the LATEST reading wins - averaging would smooth
    /// the series before the chart's own smoothing got to it.
    func testManySnapshotsInOneSecondAreOneSample() {
        let rates = RateHistory()
        for i in 0..<20 {
            rates.push(elapsedMs: Int64(500 + i * 10), rateBytesPerS: Int64(1_000_000 + i))
        }
        XCTAssertEqual(rates.count, 1)
        XCTAssertEqual(rates.current, 1_000_019)
    }

    /// A short gap is carried forward so the axis stays a real time axis; a long
    /// one clears the history rather than manufacturing a flat plateau nobody
    /// observed.
    func testAShortGapIsCarriedAndALongOneClears() {
        let rates = RateHistory()
        rates.push(elapsedMs: 0, rateBytesPerS: 5_000_000)
        rates.push(elapsedMs: 1_000, rateBytesPerS: 6_000_000)

        // Three unobserved seconds, inside the carry budget.
        rates.push(elapsedMs: 5_000, rateBytesPerS: 7_000_000)
        XCTAssertEqual(rates.count, 6)
        XCTAssertEqual(rates[2], 6_000_000)
        XCTAssertEqual(rates[4], 6_000_000)
        XCTAssertEqual(rates[5], 7_000_000)

        // Now a stall past the budget.
        rates.push(elapsedMs: 60_000, rateBytesPerS: 8_000_000)
        XCTAssertEqual(rates.count, 1)
        XCTAssertEqual(rates.current, 8_000_000)
    }

    /// A clock that went backwards means a different run of the job, and drawing
    /// across it would join two unrelated series into one line.
    func testABackwardClockStartsAgain() {
        let rates = RateHistory()
        rates.push(elapsedMs: 30_000, rateBytesPerS: 5_000_000)
        rates.push(elapsedMs: 31_000, rateBytesPerS: 5_000_000)
        rates.push(elapsedMs: 400, rateBytesPerS: 9_000_000)
        XCTAssertEqual(rates.count, 1)
        XCTAssertEqual(rates.current, 9_000_000)
    }

    func testTheRingHoldsTwoMinutesAndDropsTheOldest() {
        let rates = RateHistory()
        for s in 0..<(RateHistory.capacity + 40) {
            rates.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: Int64(1_000 + s))
        }
        XCTAssertEqual(rates.count, RateHistory.capacity)
        XCTAssertEqual(rates.current, Int64(1_000 + RateHistory.capacity + 39))
        XCTAssertEqual(rates[0], 1_040)
    }

    /// The VU-meter rule: up instantly so a spike is never clipped, down gently so
    /// a spiky series does not re-scale the whole chart on every sample.
    func testTheScaleRisesInstantlyAndFallsGently() {
        let rates = RateHistory()
        rates.push(elapsedMs: 0, rateBytesPerS: 1_000_000)
        rates.push(elapsedMs: 1_000, rateBytesPerS: 1_000_000)
        XCTAssertEqual(rates.displayMax, 1_000_000, accuracy: 1)

        rates.push(elapsedMs: 2_000, rateBytesPerS: 10_000_000)
        XCTAssertEqual(rates.displayMax, 10_000_000, accuracy: 1)

        // The spike scrolls nowhere yet, so the peak holds the scale up.
        rates.push(elapsedMs: 3_000, rateBytesPerS: 1_000_000)
        XCTAssertEqual(rates.displayMax, 10_000_000, accuracy: 1)
    }

    func testTheScaleEasesDownOnceThePeakLeavesTheWindowAndSnapsUnderReducedMotion() {
        func filled(smooth: Bool) -> RateHistory {
            let h = RateHistory()
            h.smoothScale = smooth
            h.push(elapsedMs: 0, rateBytesPerS: 10_000_000)
            for s in 1...(RateHistory.capacity + 5) {
                h.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: 1_000_000)
            }
            return h
        }
        let smoothed = filled(smooth: true)
        let snapped = filled(smooth: false)
        XCTAssertEqual(snapped.displayMax, 1_000_000, accuracy: 1)
        XCTAssertGreaterThan(smoothed.displayMax, snapped.displayMax,
                             "eased scale should still be above the snapped one")
        XCTAssertLessThan(smoothed.displayMax, 10_000_000, "and should be on its way down")
    }

    /// The trend says nothing for the first fifteen seconds. A comparison over
    /// three samples flaps while the engine's own rate estimate settles, and a
    /// figure that flickers reads as the app being confused rather than the job
    /// being uneven.
    func testTheTrendWaitsForEnoughHistory() {
        let rates = RateHistory()
        for s in 0..<14 { rates.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: 5_000_000) }
        XCTAssertNil(rates.trend)
        XCTAssertEqual(rates.trendText, "")
        rates.push(elapsedMs: 14_000, rateBytesPerS: 5_000_000)
        XCTAssertNotNil(rates.trend)
    }

    /// The median and not the mean, because one stalled second at zero drags a
    /// mean down and would report a slowdown that did not happen.
    func testOneStalledSecondDoesNotFakeASlowdown() {
        let rates = RateHistory()
        for s in 0..<30 {
            rates.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: s == 7 ? 0 : 5_000_000)
        }
        XCTAssertEqual(try XCTUnwrap(rates.trend), 0, accuracy: 1e-6)
        XCTAssertEqual(rates.trendText, S.progressRateSteady)
    }

    func testTheTrendNamesTheDirection() {
        let slowing = RateHistory()
        for s in 0..<25 { slowing.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: 8_000_000) }
        slowing.push(elapsedMs: 25_000, rateBytesPerS: 4_000_000)
        XCTAssertTrue(slowing.trendText.contains("slower"), slowing.trendText)

        let speeding = RateHistory()
        for s in 0..<25 { speeding.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: 4_000_000) }
        speeding.push(elapsedMs: 25_000, rateBytesPerS: 8_000_000)
        XCTAssertTrue(speeding.trendText.contains("faster"), speeding.trendText)
    }

    /// A big speed-up must not be clamped to "100% faster". The mac's `Fmt.percent`
    /// takes a figure already out of a hundred and does not clamp, which is what
    /// this needs; the Windows app has a second formatter that DOES clamp to 0..1
    /// and would have understated a five times jump by a factor of four.
    func testALargeSpeedUpIsNotClampedToOneHundredPerCent() {
        let rates = RateHistory()
        for s in 0..<25 { rates.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: 1_000_000) }
        rates.push(elapsedMs: 25_000, rateBytesPerS: 6_000_000)
        XCTAssertEqual(rates.trendText, "500% faster than the last minute")
    }

    func testTheVisibleWindowIsTheMostRecentSamples() {
        let rates = RateHistory()
        for s in 0..<50 { rates.push(elapsedMs: Int64(s) * 1_000, rateBytesPerS: Int64(s)) }
        let window = rates.visible(10)
        XCTAssertEqual(window.count, 10)
        XCTAssertEqual(window.first, 40)
        XCTAssertEqual(window.last, 49)
        XCTAssertEqual(rates.visible(500).count, 50)
    }

    func testResetThrowsTheHistoryAway() {
        let rates = RateHistory()
        rates.push(elapsedMs: 0, rateBytesPerS: 1_000_000)
        rates.push(elapsedMs: 1_000, rateBytesPerS: 1_000_000)
        rates.reset()
        XCTAssertEqual(rates.count, 0)
        XCTAssertFalse(rates.hasShape)
        XCTAssertEqual(rates.current, 0)
    }

    /// `apply(_:)` is the whole of the sheet's wiring, so both of its rules are
    /// tested here rather than left to a view nothing can drive headlessly.
    func testApplyIgnoresAFinishedJobAndClearsForANewOne() {
        let rates = RateHistory()
        func snapshot(id: Int64, state: JobState, elapsed: Int64) -> JobSnapshot {
            JobSnapshot(id: id, kind: .verify, state: state, elapsed_ms: elapsed,
                        rate_bytes_per_s: 400_000_000)
        }
        for s in 0..<20 {
            rates.apply(snapshot(id: 1, state: .running, elapsed: Int64(s) * 1_000))
        }
        XCTAssertEqual(rates.count, 20)
        XCTAssertNotNil(rates.trend)

        // A FINISHED job must not extend the chart. Its last snapshot arrives on
        // every poll, so applying unconditionally would grow a flat tail claiming
        // the job is still running at the rate it stopped at.
        for _ in 0..<5 {
            rates.apply(snapshot(id: 1, state: .done, elapsed: 30_000))
        }
        XCTAssertEqual(rates.count, 20)

        // And a second job in the same sheet starts with a clean chart rather than
        // inheriting the shape of the first.
        rates.apply(snapshot(id: 2, state: .running, elapsed: 1_000))
        XCTAssertEqual(rates.count, 1)
    }

    /// A job that reports no rate at all leaves the chart absent rather than flat:
    /// `rate_bytes_per_s` is optional on the wire and a nil is not a zero.
    func testAJobWithNoRateFieldIsNotPlottedAsZero() {
        let rates = RateHistory()
        for s in 0..<10 {
            rates.apply(JobSnapshot(id: 1, kind: .create, state: .running,
                                    elapsed_ms: Int64(s) * 1_000, rate_bytes_per_s: nil))
        }
        XCTAssertEqual(rates.count, 0)
        XCTAssertFalse(rates.hasShape)
    }

    // MARK: - (c) the per-file block strip

    private func file(_ name: String, total: Int, ok: Int = 0,
                      status: FileStatus = .complete) -> SurveyFile {
        SurveyFile(name: name, size: Int64(total) * 1024, status: status,
                   blocks_ok: ok, blocks_total: total)
    }

    /// Two files, the second one damaged in its last two blocks. The strips must
    /// put the damage in the SECOND row and leave the first clean, which is the
    /// connection this chart exists to make.
    func testAStripIsTheFilesOwnSliceOfTheSetStrip() {
        var states = [BlockState](repeating: .present, count: 10)
        states[8] = .damaged
        states[9] = .damaged

        let strips = FileStripModel.build(setStates: states, files: [
            file("a.bin", total: 6, ok: 6),
            file("b.bin", total: 4, ok: 2, status: .damaged),
        ])

        let a = try! XCTUnwrap(strips["a.bin"])
        let b = try! XCTUnwrap(strips["b.bin"])
        XCTAssertEqual(a.bad, 0)
        XCTAssertEqual(b.bad, 2)
        XCTAssertEqual(a.blocks, 6)
        XCTAssertEqual(b.blocks, 4)
        XCTAssertTrue(a.cells.allSatisfy { $0.badMark == nil })
        XCTAssertTrue(b.cells.contains { $0.badMark == .damaged })
    }

    /// The offsets are a running sum of blocks_total, so they mean nothing if that
    /// sum is not the strip. Refusing is the only safe answer: a plausible strip
    /// beside the wrong name reads as information.
    func testMismatchedTotalsRefuseRatherThanSlideTheOffsets() {
        let strips = FileStripModel.build(
            setStates: [BlockState](repeating: .present, count: 10),
            files: [file("a.bin", total: 6), file("b.bin", total: 9)])  // 15, not 10
        XCTAssertTrue(strips.isEmpty)
    }

    /// An extra file owns no source blocks and gets no strip, not an empty one -
    /// and it must not move the offsets of the members after it.
    func testAnExtraFileGetsNoStripAndDoesNotMoveTheOffsets() {
        var states = [BlockState](repeating: .present, count: 8)
        states[7] = .missing

        let strips = FileStripModel.build(setStates: states, files: [
            file("a.bin", total: 4, ok: 4),
            file("spare.txt", total: 0, status: .extra),
            file("b.bin", total: 4, ok: 3),
        ])
        XCTAssertNil(strips["spare.txt"])
        XCTAssertEqual(try XCTUnwrap(strips["a.bin"]).bad, 0)
        XCTAssertEqual(try XCTUnwrap(strips["b.bin"]).bad, 1)
    }

    /// An unchanged survey cuts an EQUAL strip, which is what stops SwiftUI
    /// redrawing a settled table ten times a second. This is the mac's mechanism
    /// where the Windows version hands the same INSTANCE back - a value that
    /// compares equal is what a value-typed view diffs on.
    func testAnUnchangedStripComparesEqualAndAMovedOneDoesNot() {
        let states = [BlockState](repeating: .present, count: 8)
        let files = [file("a.bin", total: 4, ok: 4), file("b.bin", total: 4, ok: 4)]

        let first = FileStripModel.build(setStates: states, files: files)
        let again = FileStripModel.build(setStates: states, files: files)
        XCTAssertEqual(first["a.bin"], again["a.bin"])
        XCTAssertEqual(first["b.bin"], again["b.bin"])

        var moved = states
        moved[5] = .damaged
        let third = FileStripModel.build(setStates: moved, files: [
            files[0], file("b.bin", total: 4, ok: 3, status: .damaged),
        ])
        XCTAssertEqual(again["a.bin"], third["a.bin"])
        XCTAssertNotEqual(again["b.bin"], third["b.bin"])
    }

    /// A member with more blocks than the cell budget is merged, and a member with
    /// fewer is NOT inflated: the budget is a ceiling, not a target.
    func testTheCellBudgetIsACeilingAndNotATarget() {
        let small = FileStripModel.build(
            setStates: [BlockState](repeating: .present, count: 8),
            files: [file("a", total: 8, ok: 8)])
        XCTAssertEqual(try XCTUnwrap(small["a"]).cells.count, 8)

        let big = FileStripModel.build(
            setStates: [BlockState](repeating: .present, count: 5_000),
            files: [file("a", total: 5_000, ok: 5_000)])
        XCTAssertEqual(try XCTUnwrap(big["a"]).cells.count, FileStripModel.targetCells)
    }

    /// A lone damaged block in a merged member must still leave a tick. This is
    /// the same failure the big map's rule exists to prevent, at a sixtieth of the
    /// width, where it is much easier to lose.
    func testOneDamagedBlockInFiveThousandStillTicks() {
        var states = [BlockState](repeating: .present, count: 5_000)
        states[2_500] = .damaged
        let strip = try! XCTUnwrap(FileStripModel.build(
            setStates: states, files: [file("a", total: 5_000, ok: 4_999)])["a"])
        XCTAssertEqual(strip.bad, 1)
        XCTAssertEqual(strip.cells.filter { $0.badMark == .damaged }.count, 1)
    }

    /// MISNAMED IS NOT BAD. The data is on the disk under another name, it costs
    /// no recovery blocks, and counting it as damage would make a set two renames
    /// from perfect look nearly lost. `BlockMapRule.isBad` is the one place that
    /// rule lives, and this is the strip inheriting it rather than restating it.
    func testAMisnamedMemberIsGroundedNotTicked() {
        let strip = try! XCTUnwrap(FileStripModel.build(
            setStates: [BlockState](repeating: .misnamed, count: 12),
            files: [file("a", total: 12, ok: 12, status: .misnamed)])["a"])
        XCTAssertEqual(strip.bad, 0)
        XCTAssertTrue(strip.cells.allSatisfy { $0.badMark == nil })
        XCTAssertTrue(strip.cells.allSatisfy { $0.ground == .misnamed })
    }

    func testTheStripSummaryIsTheRowsCensusInWords() {
        let strip = try! XCTUnwrap(FileStripModel.build(
            setStates: [BlockState](repeating: .present, count: 32),
            files: [file("a", total: 32, ok: 29)])["a"])
        XCTAssertEqual(strip.accessibleSummary(), "29 of 32 blocks present")
    }

    func testNoStatesMeansNoStrips() {
        XCTAssertTrue(FileStripModel.build(setStates: [], files: [file("a", total: 4)]).isEmpty)
    }

    // MARK: - The charts against the mock's own scenarios

    /// Runs a scenario to a settled verify and hands back the survey the screens
    /// would draw, which is what the screenshots and the demo are driven from.
    private func settledSurvey(_ scenario: MockScenario) throws -> Survey {
        let core = MockCore(speed: 200)
        let id = try core.submitVerify(scenario: scenario)
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline {
            if let job = try core.queueSnapshot().jobs.first(where: { $0.id == id }),
               job.state.isFinished, let survey = job.survey {
                return survey
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        throw XCTSkip("the mock verify did not settle")
    }

    /// The real fixture, over every scenario in the catalogue: a strip per member,
    /// the damage in the right row, and the census agreeing with the row's own
    /// figure.
    ///
    /// The unit cases above build states by hand; this one runs the mock's own
    /// survey builder. A disagreement between the two is the interesting kind of
    /// failure - it means the derivation and the fixture read the block order
    /// differently, which is precisely the defect the refusal arm cannot catch
    /// because both sides reconcile with themselves.
    func testEveryScenarioCutsAStripPerMember() throws {
        for scenario in MockScenario.all {
            let survey = try settledSurvey(scenario)
            let strips = FileStripModel.build(setStates: survey.expandedStates(),
                                              files: survey.files)
            // FAILING TO FIND IS FAILING. Every arm below is inside a loop over
            // the survey's files, so a scenario whose strips all came back nil -
            // the refusal arm firing on a fixture it should reconcile with - would
            // otherwise pass this test by asserting nothing at all.
            XCTAssertEqual(strips.count, survey.files.filter { $0.blocks_total > 0 }.count,
                           "\(scenario.id): reached no strips to check")
            for file in survey.files {
                guard file.blocks_total > 0 else {
                    XCTAssertNil(strips[file.name], "\(scenario.id): \(file.name)")
                    continue
                }
                let strip = try XCTUnwrap(strips[file.name], "\(scenario.id): \(file.name)")
                XCTAssertEqual(strip.blocks, file.blocks_total, "\(scenario.id): \(file.name)")
                XCTAssertEqual(strip.ok, file.blocks_ok, "\(scenario.id): \(file.name)")

                // A row the survey calls complete cannot carry a bad mark, and a
                // row it calls damaged or missing must. Either way round is a
                // strip drawn over the wrong file's blocks.
                if file.status == .complete {
                    XCTAssertEqual(strip.bad, 0, "\(scenario.id): \(file.name) is complete")
                }
                if file.status == .damaged || file.status == .missing {
                    XCTAssertGreaterThan(strip.bad, 0,
                                         "\(scenario.id): \(file.name) is \(file.status) "
                                         + "and its strip has no bad block")
                }
            }
        }
    }

    /// Mid-verify, with the cursor part way through, the strips still line up:
    /// this is the state the map is drawn in most of the time and the one where
    /// the pending tail makes an off-by-one easy to miss.
    func testStripsLineUpMidVerify() throws {
        let core = MockCore(speed: 1)
        let id = try core.submitVerify(scenario: .damagedRepairable)
        let deadline = Date().addingTimeInterval(8)
        var seen = false
        while Date() < deadline && !seen {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
            guard let job = try core.queueSnapshot().jobs.first(where: { $0.id == id }),
                  let survey = job.survey, job.progress > 0.2, job.progress < 0.9,
                  survey.files.contains(where: { $0.status == .hashing }) else { continue }
            seen = true
            let strips = FileStripModel.build(setStates: survey.expandedStates(),
                                              files: survey.files)
            let members = survey.files.filter { $0.blocks_total > 0 }
            XCTAssertEqual(strips.count, members.count, "a strip per member, mid-verify")
            for file in members {
                XCTAssertEqual(try XCTUnwrap(strips[file.name]).blocks, file.blocks_total)
            }
        }
        XCTAssertTrue(seen, "never caught the verify mid-flight")
    }

    /// THE FILTER MUST NOT REACH THE OFFSETS. Cutting over the rows the table
    /// draws would slide every surviving strip onto another file's blocks, and the
    /// picture would be confident and wrong. This is the test for the one mistake
    /// the derivation cannot detect on its own.
    func testTheProblemsFilterDoesNotMoveAnyStrip() throws {
        let app = AppModel(core: MockCore(speed: 200))
        app.openPar2(MockScenario.damagedRepairable.par2Path)
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline, !(app.verify.snapshot?.state.isFinished ?? false) {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        let survey = try XCTUnwrap(app.verify.survey)

        app.verify.filter = .all
        let unfiltered = app.verify.strips
        app.verify.filter = .problems
        XCTAssertLessThan(app.verify.rows().count, survey.files.count,
                          "the filter has to actually remove rows for this to prove anything")
        XCTAssertEqual(app.verify.strips, unfiltered,
                       "the strips moved when the table was filtered")

        // And every row the filtered table draws still gets ITS OWN strip.
        for row in app.verify.rows() where row.blocks_total > 0 {
            XCTAssertEqual(try XCTUnwrap(app.verify.strips[row.name]).blocks, row.blocks_total)
        }
    }

    /// Opening a second set must not leave the first set's damage under the new
    /// set's names. The reconciliation guard cannot catch this - both surveys
    /// reconcile with themselves - so the clearing is the whole defence.
    func testOpeningAnotherSetDropsTheStripsImmediately() throws {
        let app = AppModel(core: MockCore(speed: 200))
        app.openPar2(MockScenario.damagedRepairable.par2Path)
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline, app.verify.strips.isEmpty {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTAssertFalse(app.verify.strips.isEmpty, "no strips to drop")

        app.verify.setTarget(MockScenario.clean.par2Path)
        XCTAssertTrue(app.verify.strips.isEmpty)
    }

    /// The whole of (a) through the screen's own model rather than through the
    /// chart model directly, because the wiring is where it has to be right: a
    /// preview recompute must move the bar.
    func testTheCreateScreensCostBarFollowsTheRecoveryChips() {
        let app = AppModel(core: MockCore(speed: 200))
        app.create.addSources((1...3).map {
            "\(MockScenario.mockRoot)/create/source.part0\($0).rar"
        })

        app.create.recoveryPercent = 5
        app.create.recompute(with: app.core)
        XCTAssertTrue(app.create.cost.hasPlan)
        let small = app.create.cost.par2Share

        app.create.recoveryPercent = 20
        app.create.recompute(with: app.core)
        XCTAssertGreaterThan(app.create.cost.par2Share, small,
                             "the cost bar did not move: \(small) -> \(app.create.cost.par2Share)")

        // And an emptied source list takes the bar with it rather than leaving the
        // last plan's picture over no files.
        app.create.sources = []
        app.create.recompute(with: app.core)
        XCTAssertFalse(app.create.cost.hasPlan)
    }
}
