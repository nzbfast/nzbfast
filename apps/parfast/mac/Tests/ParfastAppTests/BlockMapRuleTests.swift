import XCTest
@testable import ParfastCore

/// The block map's merge rule, pinned with the numbers that chose it.
///
/// The two failure modes are opposite and both silent, so both are tested:
/// over-stating damage (a set that is 2% damaged looking a fifth destroyed)
/// and hiding it (one bad block in forty vanishing). The table in
/// `BlockMapRule`'s doc comment is exactly `testTheMeasurementThatChoseIt`.
final class BlockMapRuleTests: XCTestCase {

    /// The mock's ten-thousand-block set: 188 damaged blocks scattered
    /// through four of twenty files, which is what dropped articles look like.
    private func bigSetStates() -> [BlockState] {
        var states: [BlockState] = []
        for i in 1...20 {
            let blocks = 500
            let bad = [3, 7, 12, 18].contains(i) ? 37 + i : 0
            if bad == 0 {
                states += [BlockState](repeating: .present, count: blocks)
            } else {
                let stride = max(1, blocks / bad)
                for off in 0..<blocks {
                    let isBad = (off % stride == 0) && (off / stride) < bad
                    states.append(isBad ? .damaged : .present)
                }
            }
        }
        return states
    }

    private func score(_ states: [BlockState], columns: Int)
        -> (worstWins: Int, majorityGround: Int, ticked: Int) {
        var worst = 0, major = 0, ticked = 0
        for c in 0..<columns {
            let r = BlockMapRule.range(column: c, of: columns, blocks: states.count)
            if BlockMapRule.badMark(states, in: r) != nil { worst += 1; ticked += 1 }
            if BlockMapRule.isBad(BlockMapRule.ground(states, in: r)) { major += 1 }
        }
        return (worst, major, ticked)
    }

    func testTheMeasurementThatChoseIt() {
        let states = bigSetStates()
        XCTAssertEqual(states.count, 10_000)
        XCTAssertEqual(states.filter { $0 == .damaged }.count, 188)

        let s = score(states, columns: 400)
        // Worst-wins would paint a fifth of the strip red for 1.88% damage.
        XCTAssertEqual(s.worstWins, 78)
        XCTAssertGreaterThan(Double(s.worstWins) / 400, 0.19)
        // The majority ground paints none of it red, which is honest about area
        XCTAssertEqual(s.majorityGround, 0)
        // ... and the tick still marks every cell that holds damage.
        XCTAssertEqual(s.ticked, s.worstWins)
    }

    func testALoneBadBlockIsNeverHidden() {
        var states = [BlockState](repeating: .present, count: 10_000)
        states[4_321] = .damaged
        let s = score(states, columns: 400)
        // This is the case worst-wins exists to protect, and the reason the
        // ground alone is not enough.
        XCTAssertEqual(s.majorityGround, 0, "one block in twenty-five cannot win a majority")
        XCTAssertEqual(s.ticked, 1, "and the tick is what makes it visible anyway")
    }

    func testMisnamedIsNotBad() {
        // A file found under another name costs no recovery blocks, so it must
        // not be marked as damage. Chip C flagged the survey half of this on
        // 12 Sep 2026; this is the renderer half.
        XCTAssertFalse(BlockMapRule.isBad(.misnamed))
        XCTAssertTrue(BlockMapRule.isBad(.damaged))
        XCTAssertTrue(BlockMapRule.isBad(.missing))
        var states = [BlockState](repeating: .present, count: 100)
        for i in 0..<40 { states[i] = .misnamed }
        let r = BlockMapRule.range(column: 0, of: 4, blocks: 100)
        XCTAssertNil(BlockMapRule.badMark(states, in: r))
        XCTAssertEqual(BlockMapRule.ground(states, in: r), .misnamed)
    }

    func testGroundBreaksATieTowardsWhatMatters() {
        var states = [BlockState](repeating: .present, count: 10)
        for i in 0..<5 { states[i] = .damaged }
        XCTAssertEqual(BlockMapRule.ground(states, in: 0...9), .damaged)
    }

    func testASingleBlockCellIsItsOwnState() {
        var states = [BlockState](repeating: .present, count: 8)
        states[3] = .missing
        for i in 0..<8 {
            let r = BlockMapRule.range(column: i, of: 8, blocks: 8)
            XCTAssertEqual(r, i...i)
            XCTAssertEqual(BlockMapRule.ground(states, in: r), states[i])
        }
    }

    func testRangesTileTheWholeStripWithNoGapOrOverlap() {
        for (blocks, columns) in [(10_000, 400), (1_089, 530), (7, 7), (5, 3), (1, 1)] {
            var covered: [Int] = []
            for c in 0..<columns {
                covered += Array(BlockMapRule.range(column: c, of: columns, blocks: blocks))
            }
            XCTAssertEqual(covered, Array(0..<blocks), "\(blocks) blocks over \(columns) columns")
        }
    }

    func testTheMarkFloorIsAtLeastTwoDevicePixelsAtOneX() {
        XCTAssertGreaterThanOrEqual(BlockMapRule.minimumMarkWidth, 2)
    }
}

// MARK: - blocksPerCell

extension BlockMapRuleTests {
    /// The regression this function exists for: a column count of zero must
    /// not yield the total. It rendered as "each one covers 10,000 blocks"
    /// on the acceptance corpus's ten thousand block scenario, beside a map
    /// of about fourteen hundred cells.
    func testBlocksPerCellRefusesAnUnknownColumnCount() {
        XCTAssertNil(BlockMapRule.blocksPerCell(blocks: 10_000, columns: 0))
        XCTAssertNil(BlockMapRule.blocksPerCell(blocks: 10_000, columns: -1))
        XCTAssertNil(BlockMapRule.blocksPerCell(blocks: 0, columns: 1_400))
    }

    func testBlocksPerCellDividesWhenTheColumnCountIsKnown() {
        XCTAssertEqual(BlockMapRule.blocksPerCell(blocks: 10_000, columns: 1_400), 7)
        XCTAssertEqual(BlockMapRule.blocksPerCell(blocks: 10_000, columns: 1_000), 10)
    }

    /// A merged map has more blocks than cells, so one is the division
    /// rounding down and two is the smallest honest answer.
    func testBlocksPerCellFloorsAtTwo() {
        XCTAssertEqual(BlockMapRule.blocksPerCell(blocks: 4_100, columns: 4_000), 2)
    }
}
