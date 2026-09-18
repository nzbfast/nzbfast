import XCTest
@testable import ParfastCore

/// The create planner's arithmetic, against the engine's.
///
/// Every number here was measured through `pf_plan_preview` over real files on
/// 12 September 2026, and the names say which FIELD each one pins - because the two
/// defects this sweep started from survived precisely by being unnamed. `source_bytes`
/// and `source_files` were never set on this side at all, and nothing anywhere asserted
/// their names.
///
/// `PlannerParityTests` drives the real engine and compares every field; it is SKIPPED
/// without the staticlib, which is why these value tests exist beside it.
final class PlannerTests: XCTestCase {

    private func sources(_ sizes: [Int64], name: (Int) -> String = { "part\($0 + 1).bin" })
        -> [MockPlanner.Source] {
        sizes.enumerated().map {
            MockPlanner.Source(name: name($0.offset), size: $0.element,
                               path: "/abs/\(name($0.offset))")
        }
    }

    // MARK: - block_size, block_count, padding_bytes, padding_pct, efficiency_pct

    func testBlockCountFromBlockSize() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(1_048_576), recovery: .percent(10), output: "/abs/x.par2"),
            sources: sources([1_048_576, 1_048_577]))
        // Two files: one exact block, and one block plus a byte, which is two.
        XCTAssertEqual(plan.block_count, 3)
        XCTAssertEqual(plan.block_size, 1_048_576)
        XCTAssertEqual(plan.padding_bytes, 1_048_575)
    }

    /// block_size and block_count: a block COUNT is the reference's own SEARCH over the
    /// multiples of four, and this file divided the payload until 12 September 2026.
    ///
    /// A slice never spans a file boundary, so the count is the sum of per-file ceilings
    /// and the remainders do not pool. The engine's own fixture is two members of 40,000
    /// and 17,000 bytes at `-b64`: the division gives 892, which slices into 45 + 20 = 65,
    /// one MORE than was asked for, where the reference answers 896 and gets 45 + 19 = 64.
    /// Measured through `pf_plan_preview`, padding included.
    func testTheGridIsTheReferencesSearchAndNotADivision() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .count(64), recovery: .percent(5), output: "/abs/x.par2"),
            sources: sources([40_000, 17_000]))
        XCTAssertEqual(plan.block_size, 896, "the reference's answer, not 57000/64")
        XCTAssertEqual(plan.block_count, 64)
        XCTAssertEqual(plan.padding_bytes, 344)
        XCTAssertEqual(plan.source_bytes, 57_000)
    }

    /// block_size: the spec's input-slice ceiling is ENFORCED, and the raise is to a
    /// MULTIPLE of the size that was asked for.
    ///
    /// This file warned and kept the illegal size, so the pane drew a block size and a
    /// count the create would never use. Measured: one gibibyte at a 4,096 byte block is
    /// 32,768 bytes and 32,768 slices.
    func testABlockSizeOverTheSliceCeilingIsRaisedToAMultipleOfItself() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(4096), recovery: .count(2), output: "/abs/x.par2"),
            sources: sources([1024 * 1_048_576]))
        XCTAssertEqual(plan.block_size, 32_768)
        XCTAssertEqual(plan.block_count, 32_768)
        XCTAssertEqual(plan.block_size % 4096, 0)
        XCTAssertTrue(plan.warnings.contains { $0.contains("32,768") }, "\(plan.warnings)")
    }

    /// block_size: a block count no block size can reach lands on the payload itself -
    /// one slice per member - and not on the largest member.
    func testABlockCountNoSizeCanReachLandsOnThePayload() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .count(2), recovery: .count(1), output: "/abs/x.par2"),
            sources: sources([1_048_576, 1_048_576, 1_048_576]))
        XCTAssertEqual(plan.block_size, 3_145_728)
        XCTAssertEqual(plan.block_count, 3)
    }

    func testOddBlockSizeIsRoundedAndWarned() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(1001), recovery: .percent(10), output: "/abs/x.par2"),
            sources: sources([100_000]))
        XCTAssertEqual(plan.block_size, 1004)
        XCTAssertTrue(plan.warnings.contains { $0.contains("multiple of 4") })
    }

    /// padding_pct and efficiency_pct are percentages of the SAME denominator - the
    /// padded grid - so they are complements and sum to a hundred.
    ///
    /// The engine's fixture is two 5,000 byte members at a 4,096 block: the padded grid is
    /// 16,384 and the padding 6,384, so padding is 38.96% and efficiency 61.04%.
    func testPaddingAndEfficiencyArePercentagesOfTheSameThing() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(4096), recovery: .percent(0), output: "/abs/x.par2"),
            sources: sources([5_000, 5_000]))
        XCTAssertEqual(plan.block_count, 4)
        XCTAssertEqual(plan.padding_bytes, 2 * (8_192 - 5_000))
        XCTAssertEqual(plan.padding_pct, 6_384.0 / 16_384 * 100, accuracy: 1e-9)
        XCTAssertEqual(plan.efficiency_pct, 61.03515625, accuracy: 1e-9)
        XCTAssertEqual(plan.padding_pct + plan.efficiency_pct, 100, accuracy: 1e-9)
    }

    func testEfficiencyAndPaddingAgree() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(1024), recovery: .percent(0), output: "/abs/x.par2"),
            sources: sources([2048]))
        XCTAssertEqual(plan.padding_bytes, 0)
        XCTAssertEqual(plan.efficiency_pct, 100, accuracy: 0.0001)
    }

    // MARK: - source_bytes and source_files

    /// source_bytes and source_files: the two fields API.md marks ADDED, which this file
    /// never passed to `PlanPreview` at all.
    ///
    /// They are OPTIONALS on the contract with nil defaults, so leaving them out compiled
    /// and ran and drew a create cost bar whose whole was the PAR2 set alone: a two
    /// gigabyte source protected at ten per cent read as one hundred per cent recovery.
    /// The Windows lane had the same defect and it was found there first, by drawing it.
    func testTheAddedSourceFieldsAreSet() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(1_048_576), recovery: .percent(10), output: "/abs/x.par2"),
            sources: sources([4 * 1_048_576, 6 * 1_048_576]))
        XCTAssertEqual(plan.source_bytes, 10 * 1_048_576)
        XCTAssertEqual(plan.source_files, 2)
    }

    // MARK: - recovery_blocks, recovery_percent, recovery_bytes

    func testRecoveryPercentBecomesBlocks() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .count(1000), recovery: .percent(10), output: "/abs/x.par2"),
            sources: sources([100_000_000]))
        XCTAssertEqual(plan.recovery_blocks, MockPlanner.percentBlocks(plan.block_count, 10))
        XCTAssertEqual(plan.recovery_bytes, Int64(plan.recovery_blocks) * plan.block_size)
        XCTAssertEqual(plan.recovery_percent,
                       Double(plan.recovery_blocks) / Double(plan.block_count) * 100,
                       accuracy: 1e-9)
    }

    /// recovery_blocks: a percentage is round-to-nearest with a FLOOR OF ONE BLOCK.
    ///
    /// Measured against par2cmdline-turbo 1.5.0 over 32 input blocks: -r49, -r50 and -r51
    /// all give 16 and -r52 gives 17. This file had the rounding and not the floor, so
    /// `-r1` over 32 blocks drew a set with NO recovery in it - and then warned that the
    /// set could not repair, which made a wrong number look deliberate.
    func testARecoveryPercentageNeverRoundsDownToNothing() {
        for (ask, want) in [(49, 16), (50, 16), (51, 16), (52, 17), (1, 1)] {
            let plan = MockPlanner.plan(
                spec: CreateSpec(block: .size(1024), recovery: .percent(Double(ask)),
                                 output: "/abs/x.par2"),
                sources: sources([32_768]))
            XCTAssertEqual(plan.block_count, 32)
            XCTAssertEqual(plan.recovery_blocks, want, "-r\(ask)")
        }
    }

    /// recovery_blocks: a recovery SIZE is a CEILING over the block size.
    ///
    /// `bytes.div_ceil(block)`, so a target the block size does not divide buys the slice
    /// that covers it: 100 MiB plus one byte at a 1 MiB block is 101 slices.
    func testARecoverySizeRoundsUpToTheSliceThatCoversIt() {
        let mib: Int64 = 1_048_576
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .size(100 * mib + 1), output: "/abs/x.par2"),
            sources: sources([1000 * mib]))
        XCTAssertEqual(plan.recovery_blocks, 101)
        XCTAssertEqual(plan.recovery_bytes, 101 * mib)
    }

    /// warnings: `-r` is an integer percent in the reference's dialect, so a fractional
    /// ask is rounded and said out loud.
    func testAFractionalRecoveryPercentageIsRoundedAndSaidOutLoud() {
        let mib: Int64 = 1_048_576
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .percent(7.5), output: "/abs/x.par2"),
            sources: sources([100 * mib]))
        XCTAssertEqual(plan.recovery_blocks, 8)
        XCTAssertTrue(plan.warnings.contains { $0.contains("whole percents") }, "\(plan.warnings)")
        XCTAssertTrue(plan.command.contains("-r8"), plan.command)
    }

    // MARK: - files, and their names, sizes and blocks

    /// files: the "none" scheme is an index AND ONE VOLUME, not one merged file.
    ///
    /// A `-n1` create writes the critical packets to `set.par2` and every recovery slice
    /// to one volume beside it. Measured: 2,384 bytes and 10,495,736 bytes, two files.
    /// This file merged them and listed one.
    func testSchemeNoneIsAnIndexAndOneVolume() {
        let mib: Int64 = 1_048_576
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(10), output: "/abs/set.par2",
                             volumes: .none),
            sources: sources([100 * mib], name: { _ in "part01.bin" }))
        XCTAssertEqual(plan.files.count, 2)
        XCTAssertEqual(plan.files[0].name, "set.par2")
        XCTAssertEqual(plan.files[0].blocks, 0)
        XCTAssertEqual(plan.files[0].size, 2_384)
        XCTAssertEqual(plan.files[1].name, "set.vol00+10.par2")
        XCTAssertEqual(plan.files[1].blocks, 10)
        XCTAssertEqual(plan.files[1].size, 10_495_736)
        XCTAssertTrue(plan.command.contains("-n1"), plan.command)
    }

    /// files[].name: the two fields have DIFFERENT widths and neither is three.
    ///
    /// Measured over thirteen slices from zero: `vol00+1 vol01+2 vol03+4 vol07+6`. The
    /// first field is as wide as `first + recovery` - 13, two digits - and NOT as wide as
    /// the largest index that appears, which is 7; the second is as wide as the largest
    /// COUNT, one digit. This file padded both to three and drew `vol000+016`, and the
    /// next tool along finds a set's volumes by that pattern.
    func testVolumeNamesUseParCmdlinesTwoMeasuredFieldWidths() {
        let mib: Int64 = 1_048_576
        let thirteen = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(13), output: "/abs/set.par2",
                             volumes: .pow2),
            sources: sources([100 * mib]))
        XCTAssertEqual(thirteen.files.dropFirst().map(\.name),
                       ["set.vol00+1.par2", "set.vol01+2.par2", "set.vol03+4.par2",
                        "set.vol07+6.par2"])

        // Under --std-naming both fields are EXPONENTS, so both take the first field's
        // width, and the second is the volume's LAST exponent rather than its count.
        let std = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(13), output: "/abs/set.par2",
                             volumes: .pow2, std_naming: true),
            sources: sources([100 * mib]))
        XCTAssertEqual(std.files.dropFirst().map(\.name),
                       ["set.vol00-00.par2", "set.vol01-02.par2", "set.vol03-06.par2",
                        "set.vol07-12.par2"])
        XCTAssertTrue(std.command.contains("--std-naming"), std.command)

        // The first field is sized by the exponent one PAST the last written, so nine
        // slices from 95 run to 104 and go three wide.
        let offset = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(9), output: "/abs/set.par2",
                             volumes: .pow2, first_recovery_block: 95),
            sources: sources([100 * mib]))
        XCTAssertEqual(offset.files.dropFirst().map(\.name),
                       ["set.vol095+1.par2", "set.vol096+2.par2", "set.vol098+4.par2",
                        "set.vol102+2.par2"])
    }

    /// files[].size and total_bytes: a volume REPEATS the critical block logarithmically,
    /// so its size is its slices plus `bit length of the slice count` copies of that
    /// block - the creator packet riding once.
    ///
    /// This file used a placeholder index of `1024 + 512 * files` and added one copy of
    /// it, which is the right order of magnitude and the wrong number for every set.
    /// Every byte below is the engine's over the same fixture.
    func testEveryFilesSizeIsTheEnginesAndTheTotalIsTheirSum() {
        let mib: Int64 = 1_048_576
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(31), output: "/abs/set.par2",
                             volumes: .pow2),
            sources: sources([100 * mib], name: { _ in "part01.bin" }))
        XCTAssertEqual(plan.files[0].size, 2_384)
        XCTAssertEqual(plan.files.dropFirst().map(\.size),
                       [1_051_028, 2_101_976, 4_201_568, 8_398_448, 16_789_904])
        XCTAssertEqual(plan.total_bytes, 32_545_308)
        XCTAssertEqual(plan.files.reduce(Int64(0)) { $0 + $1.size }, plan.total_bytes)

        // files[].efficiency_pct is the recovery payload as a share of the file's OWN
        // size - how much of what a downloader fetches is parity rather than overhead.
        XCTAssertEqual(plan.files[0].efficiency_pct, 0)
        XCTAssertEqual(plan.files.last!.efficiency_pct,
                       Double(16 * mib) / 16_789_904 * 100, accuracy: 1e-9)

        // recovery_bytes is the PAYLOAD, not the bytes the volumes take up.
        XCTAssertEqual(plan.recovery_bytes, 31 * mib)
        XCTAssertLessThan(plan.recovery_bytes, plan.total_bytes - plan.files[0].size)
    }

    func testPreviewFilesSumToTheTotal() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .count(500), recovery: .percent(10), output: "/abs/x.par2",
                             volumes: .pow2),
            sources: sources([50_000_000, 50_000_000]))
        XCTAssertEqual(plan.files.reduce(Int64(0)) { $0 + $1.size }, plan.total_bytes)
        XCTAssertEqual(plan.files.dropFirst().reduce(0) { $0 + $1.blocks }, plan.recovery_blocks)
    }

    // MARK: - the volume layout

    /// files: an even split gives the REMAINDER TO THE FIRST volumes.
    ///
    /// `par2gen::VolumePlan::Even` over 100 slices in 7 volumes is 15 15 14 14 14 14 14,
    /// and the sizes are 15,810,956 and 14,762,312. Taking blocks-per-file off the front
    /// until the blocks run out gives 15 15 15 15 15 15 10 instead.
    func testUniformBySevenFilesSplitsEvenlyWithTheRemainderFirst() {
        let mib: Int64 = 1_048_576
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(100), output: "/abs/set.par2",
                             volumes: .uniformFiles(7)),
            sources: sources([1000 * mib], name: { _ in "part01.bin" }))
        XCTAssertEqual(plan.files.dropFirst().map(\.blocks), [15, 15, 14, 14, 14, 14, 14])
        XCTAssertEqual(plan.files[1].size, 15_810_956)
        XCTAssertEqual(plan.files.last!.size, 14_762_312)
        XCTAssertTrue(plan.command.contains("-n7"), plan.command)
    }

    /// files: a uniform volume SIZE divides by the slice's cost ON DISK - the block plus
    /// the writer's 68-byte packet head - so a 10 MiB volume at a 1 MiB block holds NINE
    /// slices, not ten.
    ///
    /// This file divided by the block size alone and drew ten volumes of ten, whose tenth
    /// slice would have put every file over the size the user typed. Measured: twelve
    /// volumes, the first four of nine slices and the rest of eight.
    func testAUniformVolumeSizeCountsTheSlicesPacketHeadToo() {
        let mib: Int64 = 1_048_576
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(100), output: "/abs/set.par2",
                             volumes: .uniformFileSize(10 * mib)),
            sources: sources([1000 * mib]))
        XCTAssertEqual(plan.files.dropFirst().map(\.blocks), [9, 9, 9, 9, 8, 8, 8, 8, 8, 8, 8, 8])
    }

    /// files: a volume count above the CLI's cap of 31 recovery files is clamped to it,
    /// and the constant that says so read 32,768 until 12 September 2026.
    func testAUniformCountAboveTheCliCapIsClamped() {
        let mib: Int64 = 1_048_576
        XCTAssertEqual(MockPlanner.maxRecoveryFiles, 31)
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(100), output: "/abs/set.par2",
                             volumes: .uniformFiles(99)),
            sources: sources([1000 * mib]))
        let volumes = plan.files.dropFirst()
        XCTAssertEqual(volumes.count, 31)
        XCTAssertEqual(volumes.reduce(0) { $0 + $1.blocks }, 100)
        XCTAssertEqual(volumes.first!.blocks, 4)
        XCTAssertEqual(volumes.last!.blocks, 3)
    }

    func testPow2Doubles() {
        var warnings: [String] = []
        let layout = MockPlanner.volumeLayout(scheme: .pow2, recoveryBlocks: 100, blockSize: 1_048_576,
                                             largestSource: 1_048_576_000, warnings: &warnings)
        XCTAssertEqual(layout, [1, 2, 4, 8, 16, 32, 37])
        XCTAssertEqual(layout.reduce(0, +), 100)
    }

    /// files: the pow2 ceilings FLOOR-divide, because a ceiling that rounds up is not one.
    ///
    /// The largest member here is twenty and a HALF blocks, so no volume may carry more
    /// than twenty; this file took the ceiling and allowed 21. A byte ceiling divides by
    /// block + 68 for the same reason a uniform volume size does.
    func testPow2CeilingsFloorDivide() {
        let mib: Int64 = 1_048_576
        var warnings: [String] = []
        let largest = MockPlanner.volumeLayout(
            scheme: .pow2LimitLargestSource, recoveryBlocks: 100, blockSize: mib,
            largestSource: 20 * mib + mib / 2, warnings: &warnings)
        XCTAssertEqual(largest, [1, 2, 4, 8, 16, 20, 20, 20, 9])

        let bySize = MockPlanner.volumeLayout(
            scheme: .pow2LimitSize(10 * mib), recoveryBlocks: 100, blockSize: mib,
            largestSource: 1000 * mib, warnings: &warnings)
        XCTAssertEqual(bySize, [1, 2, 4, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 4])
        XCTAssertTrue(warnings.contains { $0.contains("9 recovery block(s)") }, "\(warnings)")
    }

    func testUniformSchemeSplitsEvenly() {
        XCTAssertEqual(MockPlanner.evenSplit(10, volumes: 4), [3, 3, 2, 2])
        XCTAssertEqual(MockPlanner.evenSplit(10, volumes: 4).reduce(0, +), 10)
    }

    // MARK: - command

    /// command: the switches are the engine's, and `-B` carries its value ATTACHED.
    ///
    /// The reference's short options take an attached value, so the `-B /abs` this file
    /// used to emit is an empty base path followed by a bare `/abs` - which the parser
    /// takes as the OUTPUT path, shifting the whole line by one. A block ceiling is
    /// `--volume-blocks=N` rather than a warning saying the CLI cannot say it, and the
    /// member list is never truncated, because "... 4 more" is not a command.
    func testCommandUsesTheCLIsOwnFlags() {
        let spec = CreateSpec(
            sources: [SourceItem(path: "/abs/a.bin")],
            path_mode: .relative, base_path: "/abs",
            block: .size(1_048_576), recovery: .percent(10),
            output: "/abs/x.par2", volumes: .uniformFiles(7),
            perf: PerfSpec(threads: 3, memory_mb: 512))
        let plan = MockPlanner.plan(spec: spec, sources: sources([100_000_000]))
        XCTAssertTrue(plan.command.hasPrefix("parfast c "))
        XCTAssertTrue(plan.command.contains("-s1048576"), plan.command)
        XCTAssertTrue(plan.command.contains("-r10"), plan.command)
        XCTAssertTrue(plan.command.contains("-n7"), plan.command)
        XCTAssertTrue(plan.command.contains("-t3"), plan.command)
        XCTAssertTrue(plan.command.contains("-m512"), plan.command)
        XCTAssertTrue(plan.command.contains("-B/abs"), plan.command)
        XCTAssertFalse(plan.command.contains("-B /abs"), plan.command)
        XCTAssertFalse(plan.command.contains("-R"), plan.command)
        XCTAssertTrue(plan.command.hasSuffix("/abs/x.par2 /abs/part1.bin"), plan.command)
    }

    /// command: the line carries the Overwrite decision, both ways round.
    ///
    /// The engine's `command_args` has spelled `--no-clobber` since 17 September 2026 and
    /// this mock did not, which `PlannerParityTests` caught on every one of its cases at
    /// once. That parity test is the stronger claim and it is COMPILED OUT on a box with
    /// no staticlib, so the value assertion lives here too: the mock is exactly what
    /// draws the pane on such a box, and a pane that protects the set while handing the
    /// user a line that overwrites it is the pane lying about the one tick that decides
    /// whether a file survives. The ticked arm is beside it so the switch is conditional
    /// rather than unconditional - the way the engine's own test is written.
    func testCommandCarriesTheOverwriteDecision() {
        let mib: Int64 = 1_048_576
        func line(overwrite: Bool) -> String {
            MockPlanner.plan(
                spec: CreateSpec(block: .size(mib), recovery: .count(2),
                                 output: "/abs/x.par2", overwrite: overwrite),
                sources: sources([10 * mib])).command
        }
        XCTAssertTrue(line(overwrite: false).contains("--no-clobber"), line(overwrite: false))
        XCTAssertFalse(line(overwrite: true).contains("--no-clobber"), line(overwrite: true))
    }

    /// command: a block ceiling is parfast's own long option, and a recovery size is
    /// spelled as a scaled `-r` only when a unit divides it exactly.
    func testCommandSpellsTheCeilingsAndSizesTheEngineSpells() {
        let mib: Int64 = 1_048_576
        let blocks = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(100), output: "/abs/x.par2",
                             volumes: .pow2LimitBlocks(8)),
            sources: sources([1000 * mib]))
        XCTAssertTrue(blocks.command.contains("--volume-blocks=8"), blocks.command)
        XCTAssertFalse(blocks.command.contains(" -l"), blocks.command)

        let largest = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .count(100), output: "/abs/x.par2",
                             volumes: .pow2LimitLargestSource),
            sources: sources([1000 * mib]))
        XCTAssertTrue(largest.command.contains(" -l"), largest.command)

        let exact = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .size(100 * mib), output: "/abs/x.par2"),
            sources: sources([1000 * mib]))
        XCTAssertTrue(exact.command.contains("-rm100"), exact.command)

        let inexact = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .size(100 * mib + 1), output: "/abs/x.par2"),
            sources: sources([1000 * mib]))
        XCTAssertTrue(inexact.command.contains("-c101"), inexact.command)
    }

    // MARK: - warnings

    func testPastTheBlockCeilingWarns() {
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(1024), recovery: .percent(10), output: "/abs/x.par2"),
            sources: sources([1024 * 40_000]))
        XCTAssertTrue(plan.warnings.contains { $0.contains("32,768") }, "\(plan.warnings)")
    }

    /// warnings: zero recovery is the index and nothing else, and says what that costs.
    func testZeroRecoveryIsTheIndexAlone() {
        let mib: Int64 = 1_048_576
        let plan = MockPlanner.plan(
            spec: CreateSpec(block: .size(mib), recovery: .percent(0), output: "/abs/x.par2"),
            sources: sources([10 * mib]))
        XCTAssertEqual(plan.recovery_blocks, 0)
        XCTAssertEqual(plan.recovery_bytes, 0)
        XCTAssertEqual(plan.files.count, 1)
        XCTAssertEqual(plan.total_bytes, plan.files[0].size)
        XCTAssertTrue(plan.warnings.contains { $0.contains("detect damage") }, "\(plan.warnings)")
    }
}
