import XCTest
@testable import ParfastCore

/// The mock planner against the REAL one, field by field, over real files.
///
/// `PlannerTests` pins the mock's arithmetic to numbers measured off the engine and
/// written down; this pins it to the engine ITSELF, so a rule that changes there shows
/// up as a diff rather than as a stale constant nobody re-measured.
///
/// # Why both, and why this one needs no corpus
///
/// This is COMPILED OUT without `mac/vendor/lib/libparfast_ffi.a`, which is most boxes
/// and every CI job that does not build Rust - a suite with only this test would be a
/// suite that silently proves nothing, which is exactly how `source_bytes` and
/// `source_files` stayed unset here for a fortnight. So the value tests say what the
/// answers ARE and this one says they are still the engine's.
///
/// Unlike the other real-engine tests in `FfiCoreTests`, it needs no `PARFAST_CORPUS`:
/// `pf_plan_preview` reads no source byte beyond `stat`, so sparse temp files are a
/// sufficient fixture and the test runs off the staticlib alone.
///
/// # It does not run in CI yet, and that is a two-line absence rather than a choice
///
/// `parfast-gui`'s `mac` job builds both slices, `lipo`s them into
/// `apps/parfast/target/universal/libparfast_ffi.a` and asserts the result is
/// universal - and then nothing copies it to `mac/vendor/lib/libparfast_ffi.a`, the
/// only path `Package.swift` checks. So `PARFAST_FFI` is undefined there, this file
/// compiles to nothing, and the job is green over 138 tests where a full run is 152.
/// Measured on run 34723537097; `testTheRealEngineTestsAreCompiledIn` is what says so
/// in the log. The Windows twin DOES run in CI, because its csproj copies the cdylib
/// through a conditional item. Both halves are written up in
/// the maintainer notes, including why the copy
/// has to respect the job's `ffi` and `app` gates.
final class PlannerParityTests: XCTestCase {

    #if PARFAST_FFI

    /// Every field of PlanPreview and PreviewFile, over specs that between them reach all
    /// four volume schemes, both block spellings, all three recovery spellings, both
    /// volume namings, the slice ceiling and the CLI's recovery-file cap.
    func testEveryPlanPreviewFieldAgreesWithTheEngine() throws {
        guard let core = FfiCore() else {
            throw XCTSkip("the core would not open")
        }
        let mib: Int64 = 1_048_576
        let cases: [(String, [Int64], (CreateSpec) -> CreateSpec)] = [
            ("two small members at an explicit block size", [5_000, 5_000],
             { $0.with { $0.block = .size(4_096) } }),
            ("the grid search, which is not a division", [40_000, 17_000],
             { $0.with { $0.block = .count(64) } }),
            ("a percentage that floors at one slice", [32_768],
             { $0.with { $0.block = .size(1_024); $0.recovery = .percent(1) } }),
            ("a fractional percentage", [100 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .percent(7.5) } }),
            ("an explicit zero recovery", [10 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .percent(0) } }),
            ("a recovery size no unit divides", [1000 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .size(100 * mib + 1) } }),
            ("scheme none, an index and one volume", [100 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(10); $0.volumes = .none } }),
            ("uniform by files, evenly split", [1000 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(100)
                         $0.volumes = .uniformFiles(7) } }),
            ("uniform above the CLI's cap", [1000 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(100)
                         $0.volumes = .uniformFiles(99) } }),
            ("uniform by volume size, which pays the packet head", [1000 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(100)
                         $0.volumes = .uniformFileSize(10 * mib) } }),
            ("uniform by blocks per file", [1000 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(100)
                         $0.volumes = .uniformBlocksPerFile(10) } }),
            ("a pow2 ceiling at the largest source, which floors",
             [20 * mib + mib / 2, 8 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(100)
                         $0.volumes = .pow2LimitLargestSource } }),
            ("a pow2 ceiling in blocks", [1000 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(100)
                         $0.volumes = .pow2LimitBlocks(8) } }),
            ("a pow2 ceiling in bytes", [1000 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(100)
                         $0.volumes = .pow2LimitSize(10 * mib) } }),
            ("the spec's own volume naming, offset", [100 * mib],
             { $0.with { $0.block = .size(mib); $0.recovery = .count(13)
                         $0.std_naming = true; $0.first_recovery_block = 95 } }),
            ("a block size over the slice ceiling", [1024 * mib],
             { $0.with { $0.block = .size(4_096); $0.recovery = .count(2) } }),
            ("a block count no block size can reach", [mib, mib, mib],
             { $0.with { $0.block = .count(2); $0.recovery = .count(1) } }),
        ]

        // One line per field per case, compared as two LISTS, so a failure names the case
        // and the field rather than stopping at the first number that moved.
        var fromEngine: [String] = []
        var fromMock: [String] = []
        for (tag, sizes, shape) in cases {
            let sources = try write(sizes)
            let spec = shape(CreateSpec(
                sources: sources.map { SourceItem(path: $0.path) },
                block: .size(mib), recovery: .count(1),
                output: dir.appendingPathComponent("set.par2").path,
                volumes: .pow2))
            fromEngine += describe(tag, try core.planPreview(spec))
            fromMock += describe(tag, MockPlanner.plan(spec: spec, sources: sources))
        }

        XCTAssertEqual(fromEngine, fromMock)
    }

    /// Every field of one preview, as comparable lines.
    private func describe(_ tag: String, _ p: PlanPreview) -> [String] {
        var out: [String] = [
            "\(tag): block_size = \(p.block_size)",
            "\(tag): block_count = \(p.block_count)",
            "\(tag): padding_bytes = \(p.padding_bytes)",
            "\(tag): padding_pct = \(round9(p.padding_pct))",
            "\(tag): efficiency_pct = \(round9(p.efficiency_pct))",
            "\(tag): recovery_blocks = \(p.recovery_blocks)",
            "\(tag): recovery_percent = \(round9(p.recovery_percent))",
            "\(tag): recovery_bytes = \(p.recovery_bytes)",
            "\(tag): total_bytes = \(p.total_bytes)",
            "\(tag): source_bytes = \(p.source_bytes ?? -1)",
            "\(tag): source_files = \(p.source_files ?? -1)",
            "\(tag): files.count = \(p.files.count)",
        ]
        for (i, f) in p.files.enumerated() {
            out.append("\(tag): files[\(i)].name = \((f.name as NSString).lastPathComponent)")
            out.append("\(tag): files[\(i)].blocks = \(f.blocks)")
            out.append("\(tag): files[\(i)].size = \(f.size)")
            out.append("\(tag): files[\(i)].efficiency_pct = \(round9(f.efficiency_pct))")
        }
        // The command line is compared SWITCH FOR SWITCH and not as one string: both sides
        // end with the same absolute member paths by construction, and the leading
        // switches are the part either side can get wrong.
        let switches = p.command.split(separator: " ").dropFirst(2)
            .prefix { $0.hasPrefix("-") }.joined(separator: " ")
        out.append("\(tag): command switches = \(switches)")
        return out
    }

    private func round9(_ d: Double) -> String { String(format: "%.9f", d) }

    /// Sparse files of the asked-for sizes: the engine stats every member, so a gigabyte
    /// costs nothing to offer it.
    private func write(_ sizes: [Int64]) throws -> [MockPlanner.Source] {
        let sub = dir.appendingPathComponent(UUID().uuidString.prefix(8).lowercased())
        try FileManager.default.createDirectory(at: sub, withIntermediateDirectories: true)
        var out: [MockPlanner.Source] = []
        for (i, size) in sizes.enumerated() {
            let name = String(format: "part%02d.bin", i + 1)
            let url = sub.appendingPathComponent(name)
            FileManager.default.createFile(atPath: url.path, contents: nil)
            let h = try FileHandle(forWritingTo: url)
            try h.truncate(atOffset: UInt64(size))
            try h.close()
            out.append(MockPlanner.Source(name: name, size: size, path: url.path))
        }
        return out
    }

    #endif

    private var dir: URL {
        let d = FileManager.default.temporaryDirectory
            .appendingPathComponent("parfast-parity-\(ObjectIdentifier(self).hashValue)")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
        super.tearDown()
    }
}

private extension CreateSpec {
    /// A spec with one or more fields changed, so a table of cases reads as a table.
    func with(_ change: (inout CreateSpec) -> Void) -> CreateSpec {
        var copy = self
        change(&copy)
        return copy
    }
}
