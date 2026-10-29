import XCTest
@testable import ParfastApp
@testable import ParfastCore

/// The posting set (plan B1, API.md `posting_set`): the wire shape the app
/// sends, the password never coming back, the core's recorded frames decoding
/// into this app's types, the mock's posting job, and the pane's model.
@MainActor
final class PostingSetTests: XCTestCase {

    private func json(_ spec: JobSpec) throws -> [String: Any] {
        let data = try JSONEncoder().encode(spec)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func waitFor(_ what: String, timeout: TimeInterval = 10, _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTFail("timed out waiting for \(what)")
    }

    // MARK: - The wire

    func testPostingSetWireShape() throws {
        let spec = JobSpec.postingSet(PostingSetSpec(
            sources: [SourceItem(path: "/abs/a.mkv"), SourceItem(path: "/abs/dir", recursive: true)],
            output_dir: "/abs/out", name: "Movie.2026",
            rar: RarOptions(volumes: .size(104_857_600), compression: 3, solid: true,
                            password: .given("secret"), encrypt_headers: true, recovery_percent: 3),
            par2: PostingPar2(block: .count(2000), recovery: .percent(5), volumes: .pow2)))
        let top = try json(spec)
        XCTAssertEqual(top["kind"] as? String, "posting_set")
        let ps = try XCTUnwrap(top["posting_set"] as? [String: Any])
        XCTAssertEqual(ps["output_dir"] as? String, "/abs/out")
        XCTAssertEqual(ps["name"] as? String, "Movie.2026")
        let rar = try XCTUnwrap(ps["rar"] as? [String: Any])
        let volumes = try XCTUnwrap(rar["volumes"] as? [String: Any])
        XCTAssertEqual(volumes["split"] as? String, "size")
        XCTAssertEqual(volumes["size"] as? Int, 104_857_600)
        XCTAssertEqual(rar["compression"] as? Int, 3)
        XCTAssertEqual(rar["solid"] as? Bool, true)
        XCTAssertEqual(rar["password"] as? String, "secret", "a string on the way IN")
        XCTAssertEqual(rar["recovery_percent"] as? Int, 3)
        let par2 = try XCTUnwrap(ps["par2"] as? [String: Any])
        XCTAssertEqual((par2["block"] as? [String: Any])?["count"] as? Int, 2000)
        XCTAssertEqual((par2["recovery"] as? [String: Any])?["percent"] as? Double, 5)
        XCTAssertEqual((par2["volumes"] as? [String: Any])?["scheme"] as? String, "pow2")
    }

    func testRarVolumeShapes() throws {
        for (choice, split, key, value) in [
            (RarVolumes.none, "none", nil as String?, nil as Int?),
            (.size(65_536), "size", "size", 65_536),
            (.count(20), "count", "count", 20),
        ] {
            let data = try JSONEncoder().encode(choice)
            let v = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(v["split"] as? String, split)
            if let key { XCTAssertEqual(v[key] as? Int, value) } else { XCTAssertEqual(v.count, 1) }
            XCTAssertEqual(try JSONDecoder().decode(RarVolumes.self, from: data), choice)
        }
    }

    func testNoPasswordSendsNoPasswordKey() throws {
        let spec = JobSpec.postingSet(PostingSetSpec(output_dir: "/abs/out", name: "x"))
        let rar = try XCTUnwrap((try json(spec)["posting_set"] as? [String: Any])?["rar"] as? [String: Any])
        XCTAssertNil(rar["password"])
    }

    /// The core sends `{"withheld":true}` on every echo. That decodes as the
    /// marker, re-encodes as the marker, and the password's description never
    /// carries the bytes, so a log line built from a spec cannot leak one.
    func testThePasswordIsWithheldOnEveryWayBack() throws {
        let echoed = Data(#"{"volumes":{"split":"none"},"compression":0,"solid":false,"password":{"withheld":true},"encrypt_headers":true,"recovery_percent":0}"#.utf8)
        let rar = try JSONDecoder().decode(RarOptions.self, from: echoed)
        XCTAssertEqual(rar.password, .withheld)
        let again = try XCTUnwrap(JSONSerialization.jsonObject(
            with: try JSONEncoder().encode(rar)) as? [String: Any])
        XCTAssertEqual((again["password"] as? [String: Any])?["withheld"] as? Bool, true)

        let given = RarPassword.given("hunter2-secret")
        XCTAssertFalse("\(given)".contains("hunter2"))
        XCTAssertFalse(String(reflecting: given).contains("hunter2"))
        XCTAssertFalse("\(RarOptions(password: given))".contains("hunter2"))
    }

    // MARK: - The core's own recorded frames

    /// `shared/contract/posting-set-snapshots.json` is real snapshots from the
    /// core. Every frame must decode into this app's types, and the last of
    /// each run must carry the route and both halves' files - so the app reads
    /// what the core actually sends, not what a mock invented. Read from the
    /// SOURCE tree by `#filePath`, as the strings test does.
    func testTheRecordedCoreFramesDecode() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("shared/contract/posting-set-snapshots.json")
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        for (run, route) in [("one_pass", PostingResult.Route.onePass),
                             ("two_pass_volumes", .twoPass)] {
            let entry = try XCTUnwrap(root[run] as? [String: Any], run)
            let spec = try JSONDecoder().decode(
                JobSpec.self, from: JSONSerialization.data(withJSONObject: entry["spec"] as Any))
            XCTAssertEqual(spec.kind, .postingSet, run)
            let frames = try XCTUnwrap(entry["snapshots"] as? [Any], run)
            let snaps = try frames.map {
                try JSONDecoder().decode(JobSnapshot.self, from: JSONSerialization.data(withJSONObject: $0))
            }
            XCTAssertTrue(snaps.allSatisfy { $0.kind == .postingSet }, run)
            XCTAssertEqual(snaps.map(\.progress), snaps.map(\.progress).sorted(), "\(run): monotone")
            let last = try XCTUnwrap(snaps.last)
            XCTAssertEqual(last.state, .done, run)
            let posting = try XCTUnwrap(last.result?.posting, run)
            XCTAssertEqual(posting.route, route, run)
            XCTAssertFalse(posting.rar.isEmpty, run)
            XCTAssertTrue(posting.par2.first?.name.hasSuffix(".par2") ?? false, run)
            XCTAssertEqual(last.result?.written?.map(\.name), (posting.rar + posting.par2).map(\.name), run)
            if route == .twoPass {
                XCTAssertFalse((posting.route_reason ?? "").isEmpty, "two_pass says why")
                XCTAssertTrue(posting.rar.first?.name.hasSuffix(".part01.rar") ?? false)
            } else {
                XCTAssertNil(posting.route_reason)
                XCTAssertEqual(posting.rar.map(\.name), ["Movie.2026.rar"])
            }
        }
    }

    // MARK: - The mock

    func testTheMockClaimsThePostingSet() throws {
        let caps = try MockCore().capabilities()
        XCTAssertTrue(caps.hasPostingSet)
        XCTAssertEqual(caps.posting_one_pass, true)
    }

    /// An older core sends no key, and that must decode as "no posting set".
    func testACoreWithoutTheKeyHidesThePane() throws {
        var caps = try MockCore().capabilities()
        caps.posting_set = nil
        caps.posting_one_pass = nil
        let data = try JSONEncoder().encode(caps)
        let back = try JSONDecoder().decode(Capabilities.self, from: data)
        XCTAssertFalse(back.hasPostingSet)
        let app = AppModel(core: MockCore(speed: 60))
        XCTAssertTrue(app.availableModes.contains(.posting))
        app.capabilities.posting_set = nil
        XCTAssertFalse(app.availableModes.contains(.posting))
    }

    private func run(_ core: MockCore, _ spec: PostingSetSpec) throws -> JobSnapshot {
        let id = try core.submit(.postingSet(spec))
        var seen: [Double] = []
        waitFor("posting set \(id)") {
            let s = try? core.snapshot(job: id)
            if let p = s?.progress { seen.append(p) }
            return s?.state.isFinished ?? false
        }
        XCTAssertEqual(seen, seen.sorted(), "progress never goes backwards")
        return try core.snapshot(job: id)
    }

    func testTheMockTakesOnePassForOneStoredArchive() throws {
        let core = MockCore(speed: 60)
        let job = try run(core, PostingSetSpec(sources: MockScenario.postingSources(),
                                               output_dir: "/abs/out", name: "Holiday"))
        XCTAssertEqual(job.state, .done)
        let posting = try XCTUnwrap(job.result?.posting)
        XCTAssertEqual(posting.route, .onePass)
        XCTAssertNil(posting.route_reason)
        XCTAssertEqual(posting.rar.map(\.name), ["Holiday.rar"])
        XCTAssertEqual(posting.par2.first?.name, "Holiday.par2")
        XCTAssertEqual(posting.source_files, 2)
    }

    func testTheMockSplitsIntoNumberedVolumesOnTwoPasses() throws {
        let core = MockCore(speed: 60)
        let job = try run(core, PostingSetSpec(
            sources: MockScenario.postingSources(), output_dir: "/abs/out", name: "Holiday",
            rar: RarOptions(volumes: .size(104_857_600))))
        let posting = try XCTUnwrap(job.result?.posting)
        XCTAssertEqual(posting.route, .twoPass)
        XCTAssertFalse((posting.route_reason ?? "").isEmpty)
        XCTAssertEqual(posting.rar.first?.name, "Holiday.part01.rar", "as wide as N needs")
        XCTAssertEqual(posting.rar.count, 41)
        XCTAssertTrue(posting.rar.dropLast().allSatisfy { $0.size == 104_857_600 })
    }

    func testTheMockRefusesANameThatIsNotOneComponent() {
        let core = MockCore(speed: 60)
        for bad in ["", "a/b", ".."] {
            XCTAssertThrowsError(try core.submit(.postingSet(PostingSetSpec(
                sources: MockScenario.postingSources(), output_dir: "/abs/out", name: bad)))) {
                XCTAssertEqual(($0 as? CoreError)?.code, "bad_spec", bad)
            }
        }
    }

    // MARK: - The pane

    func testThePaneDefaultsAreThePostingDefaults() {
        let app = AppModel(core: MockCore(speed: 60))
        let m = app.posting
        m.addSources(MockScenario.postingSources().map(\.path))
        XCTAssertEqual(m.name, "Holiday.Film.2026", "the shared stem of the two names")
        XCTAssertEqual(m.outputDir, "\(MockScenario.mockRoot)/posting")
        let spec = m.spec()
        XCTAssertEqual(spec.rar.volumes, .none)
        XCTAssertEqual(spec.rar.compression, 0, "stored")
        XCTAssertFalse(spec.rar.solid)
        XCTAssertNil(spec.rar.password)
        XCTAssertEqual(spec.rar.recovery_percent, 0)
        XCTAssertFalse(spec.overwrite)
        XCTAssertTrue(m.expectsOnePass)
        // The PAR2 half is the Settings pane's Create default.
        XCTAssertEqual(spec.par2.recovery, .percent(app.settings.create.recovery_percent))
    }

    func testTheRouteThePanePredicts() {
        let m = PostingModel()
        XCTAssertTrue(m.expectsOnePass)
        m.split = .count
        XCTAssertFalse(m.expectsOnePass)
        m.split = .none
        m.compression = 2
        XCTAssertFalse(m.expectsOnePass)
        m.compression = 0
        m.recoveryRecord = 3
        XCTAssertFalse(m.expectsOnePass)
        m.recoveryRecord = 0
        m.password = "x"
        XCTAssertTrue(m.expectsOnePass, "a password does not change the route")
    }

    func testSolidIsNeverSentForAStoredSetAndVolumesHaveAFloor() {
        let m = PostingModel()
        m.solid = true
        XCTAssertFalse(m.spec().rar.solid)
        m.compression = 3
        XCTAssertTrue(m.spec().rar.solid)
        m.split = .size
        m.volumeSize = 1000
        XCTAssertEqual(m.spec().rar.volumes, .size(PostingModel.minVolumeSize))
    }

    func testAnEditedNameIsLeftAlone() {
        let m = PostingModel()
        m.addSources(["\(MockScenario.mockRoot)/posting/One.mkv"])
        XCTAssertEqual(m.name, "One")
        m.name = "Mine"
        m.nameEdited = true
        m.addSources(["\(MockScenario.mockRoot)/posting/Two.mkv"])
        XCTAssertEqual(m.name, "Mine")
    }

    func testDropsOnThePaneAreItsSources() {
        let app = AppModel(core: MockCore(speed: 60))
        app.mode = .posting
        app.open(paths: MockScenario.postingSources().map(\.path))
        XCTAssertEqual(app.mode, .posting)
        XCTAssertEqual(app.posting.sources.count, 2)
        XCTAssertTrue(app.create.sources.isEmpty)
    }

    func testThePaneRunsAJobAndShowsItsResult() {
        let app = AppModel(core: MockCore(speed: 60))
        app.mode = .posting
        app.posting.addSources(MockScenario.postingSources().map(\.path))
        app.posting.password = "secret"
        app.startPosting()
        XCTAssertNotNil(app.posting.jobId)
        waitFor("the result card") { app.refresh(); return app.posting.finished != nil }
        XCTAssertEqual(app.posting.finished?.result?.posting?.route, .onePass)
        XCTAssertEqual(app.displayKind(.postingSet), S.jobKindPostingSet)
    }

    func testErrorCodesUseTheTablesWords() {
        let m = PostingModel()
        XCTAssertEqual(m.errorText(CoreError(code: "password_required", message: "x")),
                       S.errorPasswordRequired)
        XCTAssertEqual(m.errorText(CoreError(code: "rar_failed", message: "disk full")),
                       S.errorRarFailed(reason: "disk full"))
    }
}

#if PARFAST_FFI
/// The REAL engine through `FfiCore`: one stored archive takes one pass, a
/// volume set takes two, and both halves' files are on disk where
/// `result.posting` says. Needs only the staticlib and a temp folder, so it
/// runs on any box that built `mac/vendor/lib/libparfast_ffi.a`.
final class PostingSetEngineTests: XCTestCase {

    private func run(_ core: FfiCore, _ spec: PostingSetSpec) throws -> JobSnapshot {
        let id = try core.submit(.postingSet(spec))
        let deadline = Date().addingTimeInterval(120)
        while Date() < deadline {
            let snapshot = try core.snapshot(job: id)
            if snapshot.state.isFinished { return snapshot }
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        XCTFail("posting set \(id) did not finish")
        return try core.snapshot(job: id)
    }

    private func scratch() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("parfast-posting-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("out"),
                                                withIntermediateDirectories: true)
        var bytes = [UInt8](repeating: 0, count: 3 * 1_048_576 + 12_345)
        var x: UInt32 = 2_463_534_242
        for i in bytes.indices { x ^= x << 13; x ^= x >> 17; x ^= x << 5; bytes[i] = UInt8(x & 0xff) }
        try Data(bytes).write(to: dir.appendingPathComponent("clip.bin"))
        try Data("notes\n".utf8).write(to: dir.appendingPathComponent("clip.nfo"))
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    func testTheEngineAdvertisesThePostingSet() throws {
        let core = try XCTUnwrap(FfiCore())
        XCTAssertTrue(try core.capabilities().hasPostingSet)
    }

    func testOneStoredArchiveIsOnePassAndBothHalvesAreOnDisk() throws {
        let dir = try scratch()
        let core = try XCTUnwrap(FfiCore())
        let job = try run(core, PostingSetSpec(
            sources: [SourceItem(path: dir.appendingPathComponent("clip.bin").path),
                      SourceItem(path: dir.appendingPathComponent("clip.nfo").path)],
            output_dir: dir.appendingPathComponent("out").path, name: "Clip",
            par2: PostingPar2(recovery: .percent(5))))
        XCTAssertEqual(job.state, .done, job.error?.message ?? "")
        let posting = try XCTUnwrap(job.result?.posting)
        XCTAssertEqual(posting.route, .onePass)
        XCTAssertEqual(posting.rar.map(\.name), ["Clip.rar"])
        XCTAssertEqual(posting.par2.first?.name, "Clip.par2")
        for file in posting.rar + posting.par2 {
            let attrs = try FileManager.default.attributesOfItem(
                atPath: dir.appendingPathComponent("out").appendingPathComponent(file.name).path)
            XCTAssertEqual((attrs[.size] as? NSNumber)?.int64Value, file.size, file.name)
        }
    }

    func testAVolumeSetIsTwoPassAndSaysWhy() throws {
        let dir = try scratch()
        let core = try XCTUnwrap(FfiCore())
        let job = try run(core, PostingSetSpec(
            sources: [SourceItem(path: dir.appendingPathComponent("clip.bin").path)],
            output_dir: dir.appendingPathComponent("out").path, name: "Clip",
            rar: RarOptions(volumes: .size(1_048_576), password: .given("pw-test")),
            par2: PostingPar2(recovery: .percent(5))))
        XCTAssertEqual(job.state, .done, job.error?.message ?? "")
        let posting = try XCTUnwrap(job.result?.posting)
        XCTAssertEqual(posting.route, .twoPass)
        XCTAssertFalse((posting.route_reason ?? "").isEmpty)
        XCTAssertEqual(posting.rar.first?.name, "Clip.part1.rar")
        XCTAssertEqual(posting.rar.count, 4)
        // The password went in and nothing in the snapshot carries it back.
        let echoed = try CoreJSON.encodeToString(job)
        XCTAssertFalse(echoed.contains("pw-test"))
    }
}
#endif
