import XCTest
@testable import ParfastCore

/// The JSON the app sends the core must be EXACTLY the shapes plan 4.5
/// names. These are the tests that will catch an integration mistake against
/// the real `parfast-ffi` before a single pixel is drawn, so they assert the
/// wire form and not just a round trip.
final class CoreContractTests: XCTestCase {

    private func json(_ spec: JobSpec) throws -> [String: Any] {
        let data = try JSONEncoder().encode(spec)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testCreateSpecWireShape() throws {
        let spec = JobSpec.create(CreateSpec(
            sources: [SourceItem(path: "/abs/a.bin"), SourceItem(path: "/abs/dir", recursive: true)],
            path_mode: .relative,
            base_path: "/abs",
            block: .size(1_048_576),
            recovery: .percent(10),
            output: "/abs/name.par2",
            volumes: .uniformFiles(7),
            comment: "hello"))
        let top = try json(spec)
        XCTAssertEqual(top["kind"] as? String, "create")
        let create = try XCTUnwrap(top["create"] as? [String: Any])
        XCTAssertEqual(create["path_mode"] as? String, "relative")
        XCTAssertEqual((create["block"] as? [String: Any])?["size"] as? Int, 1_048_576)
        XCTAssertNil((create["block"] as? [String: Any])?["count"])
        XCTAssertEqual((create["recovery"] as? [String: Any])?["percent"] as? Double, 10)
        let volumes = try XCTUnwrap(create["volumes"] as? [String: Any])
        XCTAssertEqual(volumes["scheme"] as? String, "uniform")
        XCTAssertEqual(volumes["files"] as? Int, 7)
        let sources = try XCTUnwrap(create["sources"] as? [[String: Any]])
        XCTAssertEqual(sources[0]["path"] as? String, "/abs/a.bin")
        XCTAssertEqual(sources[1]["recursive"] as? Bool, true)
    }

    func testBlockCountAndRecoveryUnionsAreExclusive() throws {
        let spec = JobSpec.create(CreateSpec(block: .count(2000), recovery: .size(104_857_600)))
        let create = try XCTUnwrap(try json(spec)["create"] as? [String: Any])
        XCTAssertEqual((create["block"] as? [String: Any])?["count"] as? Int, 2000)
        XCTAssertNil((create["block"] as? [String: Any])?["size"])
        XCTAssertEqual((create["recovery"] as? [String: Any])?["size"] as? Int, 104_857_600)
        XCTAssertNil((create["recovery"] as? [String: Any])?["percent"])
    }

    func testPow2LimitShapes() throws {
        for (scheme, check) in [
            (VolumeScheme.pow2LimitLargestSource, { (v: [String: Any]) in
                XCTAssertEqual(v["limit"] as? String, "largest_source") }),
            (VolumeScheme.pow2LimitBlocks(512), { v in
                XCTAssertEqual((v["limit"] as? [String: Any])?["blocks"] as? Int, 512) }),
            (VolumeScheme.pow2LimitSize(10_485_760), { v in
                XCTAssertEqual((v["limit"] as? [String: Any])?["size"] as? Int, 10_485_760) }),
        ] {
            let spec = JobSpec.create(CreateSpec(volumes: scheme))
            let create = try XCTUnwrap(try json(spec)["create"] as? [String: Any])
            let volumes = try XCTUnwrap(create["volumes"] as? [String: Any])
            XCTAssertEqual(volumes["scheme"] as? String, "pow2_limit")
            check(volumes)
        }
    }

    func testVolumeSchemeRoundTrips() throws {
        let all: [VolumeScheme] = [
            .none, .uniformFiles(7), .uniformBlocksPerFile(100), .uniformFileSize(10_485_760),
            .pow2, .pow2LimitLargestSource, .pow2LimitBlocks(512), .pow2LimitSize(10_485_760),
        ]
        for scheme in all {
            let data = try JSONEncoder().encode(scheme)
            XCTAssertEqual(try JSONDecoder().decode(VolumeScheme.self, from: data), scheme)
        }
    }

    func testVerifyAndRepairSpecShapes() throws {
        let verify = try json(.verify(VerifySpec(par2: "/abs/x.par2", extra_dirs: ["/abs/other"])))
        XCTAssertEqual(verify["kind"] as? String, "verify")
        let v = try XCTUnwrap(verify["verify"] as? [String: Any])
        XCTAssertEqual(v["extra_dirs"] as? [String], ["/abs/other"])
        XCTAssertEqual((v["options"] as? [String: Any])?["skip_leaway"] as? Int, 64)

        let repair = try json(.repairSet(RepairSpec(par2: "/abs/x.par2", purge: true)))
        XCTAssertEqual(repair["kind"] as? String, "repair")
        XCTAssertEqual((repair["repair"] as? [String: Any])?["purge"] as? Bool, true)
    }

    func testChecksumSpecShapes() throws {
        let create = try json(.checksumCreate(ChecksumCreateSpec(
            sources: [SourceItem(path: "/abs/a")], format: .sha256, output: "/abs/x.sha256")))
        XCTAssertEqual(create["kind"] as? String, "checksum_create")
        XCTAssertEqual((create["checksum_create"] as? [String: Any])?["format"] as? String, "sha256")

        let verify = try json(.checksumVerify(ChecksumVerifySpec(file: "/abs/x.sfv")))
        XCTAssertEqual(verify["kind"] as? String, "checksum_verify")
    }

    /// Chip A may ADD an enum case; that must not make this app refuse to run.
    func testUnknownEnumCasesDecodeToAFallback() throws {
        let json = """
        {"id":1,"kind":"defragment","state":"levitating","phase":"pondering",
         "phase_text":"","progress":0,"elapsed_ms":0,"low_priority":false,
         "added_at":"","log_tail":[]}
        """
        let snapshot = try JSONDecoder().decode(JobSnapshot.self, from: Data(json.utf8))
        XCTAssertEqual(snapshot.kind, .verify)
        XCTAssertEqual(snapshot.state, .queued)
        XCTAssertEqual(snapshot.phase, .scanning)
    }

    func testSurveyDecodesAndExpands() throws {
        let json = """
        {"set_name":"x.par2","folder":"/abs","block_size":1048576,"source_blocks":1000,
         "recovery_available":100,"recovery_needed":12,"verdict":"repairable","files":[],
         "block_runs":[[1,240],[2,3],[1,757]]}
        """
        let survey = try JSONDecoder().decode(Survey.self, from: Data(json.utf8))
        let states = survey.expandedStates()
        XCTAssertEqual(states.count, 1000)
        XCTAssertEqual(states[0], .present)
        XCTAssertEqual(states[240], .damaged)
        XCTAssertEqual(states[243], .present)
        XCTAssertEqual(survey.counts()[.damaged], 3)
    }

    func testRunLengthEncodeIsLossless() {
        let states: [BlockState] = [.present, .present, .damaged, .missing, .missing, .missing]
        let runs = MockCore.runLengthEncode(states)
        XCTAssertEqual(runs, [[1, 2], [2, 1], [3, 3]])
        let survey = Survey(set_name: "", folder: "", block_size: 1, source_blocks: states.count,
                            recovery_available: 0, recovery_needed: 0, verdict: .complete,
                            files: [], block_runs: runs)
        XCTAssertEqual(survey.expandedStates(), states)
    }
}
