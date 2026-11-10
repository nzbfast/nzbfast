import CryptoKit
import XCTest
@testable import ParfastApp
@testable import ParfastCore

/// The release-test scenarios, driven through `AppModel` and the pane models
/// the views bind to, over the REAL engine (`FfiCore`). These need only the
/// staticlib - no corpus - so a build that links the engine runs them.
///
/// What they prove is the logic below the views: the same model calls a
/// button makes, against the real core, with the disk checked afterwards.
/// They do NOT exercise the SwiftUI views themselves.
@MainActor
final class EngineScenarioTests: XCTestCase {

    #if PARFAST_FFI

    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pf-engine-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let scratch { try? FileManager.default.removeItem(at: scratch) }
    }

    // MARK: - Helpers

    private func waitFor(_ what: String, timeout: TimeInterval = 120,
                         _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        XCTFail("timed out waiting for \(what)")
    }

    private func job(_ app: AppModel, _ id: Int64?) -> JobSnapshot? {
        guard let id else { return nil }
        app.refresh()
        return app.queue.jobs.first { $0.id == id }
    }

    private func finish(_ app: AppModel, _ id: Int64?, _ what: String,
                        timeout: TimeInterval = 120) -> JobSnapshot? {
        waitFor(what, timeout: timeout) { job(app, id)?.state.isFinished ?? false }
        return job(app, id)
    }

    @discardableResult
    private func writeFile(_ dir: URL, _ name: String, size: Int, seed: UInt8) throws -> URL {
        let url = dir.appendingPathComponent(name)
        var bytes = [UInt8](repeating: 0, count: size)
        var x: UInt32 = UInt32(seed) &* 2_654_435_761 &+ 1
        for i in 0..<size {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5
            bytes[i] = UInt8(truncatingIfNeeded: x)
        }
        try Data(bytes).write(to: url)
        return url
    }

    private func sha(_ url: URL) throws -> String {
        SHA256.hash(data: try Data(contentsOf: url)).map { String(format: "%02x", $0) }.joined()
    }

    /// par2cmdline, the reference tool. Answers (exit code, output).
    private func par2cmd(_ args: [String], cwd: URL) throws -> (Int32, String) {
        let candidates = ["/opt/homebrew/bin/par2", "/usr/local/bin/par2"]
        guard let bin = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
        else { throw XCTSkip("par2cmdline is not installed") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = args
        p.currentDirectoryURL = cwd
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        try p.run()
        let out = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: out, as: UTF8.self))
    }

    private func makeApp(store: URL? = nil) throws -> (AppModel, FfiCore) {
        let core = try XCTUnwrap(FfiCore())
        if let store { try core.openQueueStore(at: store.path) }
        return (AppModel(core: core), core)
    }

    // MARK: - a. create, then par2cmdline verifies it

    func testA_CreateIsDoneAndPar2cmdlineVerifiesTheSet() throws {
        let (app, _) = try makeApp()
        let files = try (1...3).map { try writeFile(scratch, "file\($0).bin", size: 300_000 + $0 * 1000, seed: UInt8($0)) }
        app.mode = .create
        app.create.addSources(files.map(\.path))
        XCTAssertEqual(app.create.output, scratch.appendingPathComponent(app.create.suggestedStem() + ".par2").path,
                       "the output is filled from the sources")
        app.startCreate()
        XCTAssertNil(app.alert?.message)
        let done = finish(app, app.create.jobId, "create")
        XCTAssertEqual(done?.state, .done, done?.error?.message ?? "")
        XCTAssertFalse(done?.result?.written?.isEmpty ?? true)
        let (code, out) = try par2cmd(["v", app.create.output], cwd: scratch)
        XCTAssertEqual(code, 0, out)
        XCTAssertTrue(out.contains("All files are correct"), out)
    }

    // MARK: - b. open a .par2, damage, verify repairable, repair

    func testB_OpenVerifyDamageRepair() throws {
        let (app, _) = try makeApp()
        let original = try writeFile(scratch, "movie.bin", size: 2_000_000, seed: 7)
        try writeFile(scratch, "notes.txt", size: 40_000, seed: 8)
        let originalSha = try sha(original)
        app.create.addSources([original.path, scratch.appendingPathComponent("notes.txt").path])
        app.create.recoveryPercent = 10
        app.startCreate()
        XCTAssertEqual(finish(app, app.create.jobId, "create")?.state, .done)
        let par2 = app.create.output

        // The Finder route: open(paths:) with a .par2.
        app.open(paths: [par2])
        XCTAssertEqual(app.mode, .verify)
        _ = finish(app, app.verify.jobId, "clean verify")
        XCTAssertEqual(app.verify.survey?.verdict, .complete)
        XCTAssertFalse(app.verify.canRepair)

        // Damage 4 KiB in the middle.
        let h = try FileHandle(forWritingTo: original)
        try h.seek(toOffset: 1_000_000)
        h.write(Data(repeating: 0xAB, count: 4096))
        try h.close()
        XCTAssertNotEqual(try sha(original), originalSha)

        app.open(paths: [par2])
        _ = finish(app, app.verify.jobId, "damaged verify")
        XCTAssertEqual(app.verify.survey?.verdict, .repairable)
        XCTAssertTrue(app.verify.canRepair)

        app.startRepair()
        let repair = finish(app, app.verify.lastRepairJobId, "repair")
        XCTAssertEqual(repair?.state, .done, repair?.error?.message ?? "")
        XCTAssertEqual(try sha(original), originalSha, "the repair restored the original bytes")
        let (code, out) = try par2cmd(["v", par2], cwd: scratch)
        XCTAssertEqual(code, 0, out)
    }

    // MARK: - c. URL open under "verify, then repair": verify only (A34)

    func testC_URLOpenVerifiesButNeverRepairs_FinderOpenDoes() throws {
        let (app, core) = try makeApp()
        let f = try writeFile(scratch, "data.bin", size: 1_000_000, seed: 3)
        let originalSha = try sha(f)
        app.create.addSources([f.path])
        app.startCreate()
        XCTAssertEqual(finish(app, app.create.jobId, "create")?.state, .done)
        let par2 = app.create.output
        app.updateSettings { $0.general.open_par2 = .verifyThenRepair }
        XCTAssertEqual(try core.settingsGet().general.open_par2, .verifyThenRepair)

        let h = try FileHandle(forWritingTo: f)
        try h.seek(toOffset: 500_000)
        h.write(Data(repeating: 0, count: 2048))
        try h.close()

        // The URL route, through the same parse the AppDelegate uses.
        let url = URL(string: "parfast://open?path=" + par2.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)!
        let paths = AppModel.pathsFromOpenURL(url)
        XCTAssertEqual(paths, [par2])
        let before = try core.queueSnapshot().jobs.count
        app.open(paths: paths, fromURL: true)
        _ = finish(app, app.verify.jobId, "URL verify")
        XCTAssertEqual(app.verify.survey?.verdict, .repairable)
        // Give an auto-repair every chance to start.
        RunLoop.current.run(until: Date().addingTimeInterval(1.0))
        app.refresh()
        let kinds = try core.queueSnapshot().jobs.dropFirst(before).map(\.kind)
        XCTAssertEqual(kinds, [.verify], "a URL open must not start a repair")
        XCTAssertNotEqual(try sha(f), originalSha, "nothing repaired the file")

        // Any other host is ignored.
        XCTAssertTrue(AppModel.pathsFromOpenURL(URL(string: "parfast://other?path=\(par2)")!).isEmpty)

        // Control: the Finder route DOES auto-repair under that setting.
        app.open(paths: [par2])
        waitFor("auto repair from a Finder open") {
            app.refresh()
            return app.queue.jobs.contains { $0.kind == .repairSet && $0.state.isFinished }
        }
        XCTAssertEqual(try sha(f), originalSha)
    }

    // MARK: - d. settings persist; Settings edits keep concurrency and action (A30)

    func testD_SettingsPersistAndAnEditKeepsConcurrencyAndAction() throws {
        let store = scratch.appendingPathComponent("queue.json")
        do {
            let (app, core) = try makeApp(store: store)
            app.setConcurrency(3)
            app.setPostAction(.notify)
            // The Settings window: open (placeholder -> fresh), then one edit.
            let placeholder = CoreSettings()
            app.reloadSettings()
            let opened = app.settings
            app.apply(changesFrom: placeholder, to: opened)
            var edited = opened
            edited.general.purge_after_repair = !opened.general.purge_after_repair
            app.apply(changesFrom: opened, to: edited)
            let s = try core.settingsGet()
            XCTAssertEqual(s.concurrency, 3)
            XCTAssertEqual(s.post_queue_action, .notify)
            XCTAssertEqual(s.general.purge_after_repair, edited.general.purge_after_repair)
            XCTAssertEqual(try core.queueSnapshot().post_action, .notify)
            XCTAssertEqual(try core.queueSnapshot().concurrency, 3)
            // Back to None so the "relaunch" never holds an armed action.
            app.setPostAction(.none)
            app.updateSettings { $0.create.block_count = 1234 }
        }
        // "Relaunch": a new session over the same store.
        let (app2, core2) = try makeApp(store: store)
        let s2 = try core2.settingsGet()
        XCTAssertEqual(s2.create.block_count, 1234)
        XCTAssertEqual(s2.concurrency, 3)
        XCTAssertEqual(s2.post_queue_action, PostAction.none)
        XCTAssertEqual(app2.settings.create.block_count, 1234)
        XCTAssertEqual(app2.create.blockCount, 1234, "the Create pane starts from the persisted default")
    }

    // MARK: - f. output folder differs from the source folder (A6)

    func testF_CreateIntoAnotherFolderStoresBareNamesAndVerifies() throws {
        let (app, _) = try makeApp()
        let src = scratch.appendingPathComponent("src")
        let out = scratch.appendingPathComponent("out")
        try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        let files = try (1...2).map { try writeFile(src, "part\($0).bin", size: 400_000, seed: UInt8(20 + $0)) }
        app.create.addSources(files.map(\.path))
        app.create.output = out.appendingPathComponent("set.par2").path
        app.create.outputEdited = true
        app.startCreate()
        let done = finish(app, app.create.jobId, "create")
        XCTAssertEqual(done?.state, .done, done?.error?.message ?? "")

        // par2cmdline reads the names the set stores: with -B pointing at the
        // sources, the set must verify, which it only can on bare names.
        let (code, outText) = try par2cmd(["v", "-B", src.path, out.appendingPathComponent("set.par2").path], cwd: out)
        XCTAssertEqual(code, 0, outText)
        XCTAssertTrue(outText.contains("\"part1.bin\"") || outText.contains("part1.bin"), outText)
        XCTAssertFalse(outText.contains(src.path + "/part1.bin\" - missing"), outText)
        // Bare names mean the set verifies wherever it sits BESIDE its
        // members: copy the recovery files into the source folder and the
        // engine's verify is complete. (Left where it was written, the
        // engine and par2cmdline agree that both members are missing: a
        // source outside the set's folder is ignored by the reference too,
        // and the Verify pane has no base-path control.)
        for name in try FileManager.default.contentsOfDirectory(atPath: out.path) where name.hasSuffix(".par2") {
            try FileManager.default.copyItem(at: out.appendingPathComponent(name),
                                             to: src.appendingPathComponent(name))
        }
        app.open(paths: [src.appendingPathComponent("set.par2").path])
        _ = finish(app, app.verify.jobId, "verify beside the members")
        XCTAssertEqual(app.verify.survey?.verdict, .complete)
        XCTAssertEqual(Set(app.verify.survey?.files.map(\.name) ?? []), ["part1.bin", "part2.bin"],
                       "the set stores bare member names")
    }

    // MARK: - g. posting set never deletes its own source (A2)

    func testG_PostingSetOverwriteRefusesToDeleteASource() throws {
        let (app, core) = try makeApp()
        guard app.capabilities.hasPostingSet else { throw XCTSkip("core has no posting set") }
        let dir = scratch.appendingPathComponent("post")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let a = try writeFile(dir, "Movie.mkv", size: 600_000, seed: 41)
        try writeFile(dir, "Movie.nfo", size: 2_000, seed: 42)
        app.mode = .posting
        app.posting.addSources([a.path, dir.appendingPathComponent("Movie.nfo").path])
        XCTAssertEqual(app.posting.outputDir, dir.path)
        XCTAssertEqual(app.posting.name, "Movie")
        app.startPosting()
        let first = finish(app, app.posting.jobId, "posting set")
        XCTAssertEqual(first?.state, .done, first?.error?.message ?? "")
        let rar = dir.appendingPathComponent("Movie.rar")
        XCTAssertTrue(FileManager.default.fileExists(atPath: rar.path))

        // Now post that RAR as set "Movie" into the same folder with
        // overwrite on: the output Movie.rar IS the source.
        let rarSha = try sha(rar)
        let posting2 = PostingModel()
        posting2.addSources([rar.path])
        posting2.name = "Movie"; posting2.nameEdited = true
        posting2.outputDir = dir.path; posting2.outputEdited = true
        posting2.overwrite = true
        let id = app.submit(.postingSet(posting2.spec()), showSheet: false)
        if let id {
            let second = finish(app, id, "colliding posting set")
            XCTAssertEqual(second?.state, .failed)
            XCTAssertEqual(second?.error?.code, "output_is_a_source", second?.error?.message ?? "")
        } else {
            XCTAssertNotNil(app.alert, "a refused submit is reported")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: rar.path), "the source survived")
        XCTAssertEqual(try sha(rar), rarSha, "and is byte-identical")
        _ = core
    }

    // MARK: - h. cancel running / finished; a corrupt store at launch (A10, A3)

    func testH_CancelRunningCancelsAndCancelFinishedIsHarmless() throws {
        let (app, _) = try makeApp()
        // Big enough to still be running when the cancel lands.
        let big = try writeFile(scratch, "big.bin", size: 256 * 1024 * 1024, seed: 9)
        app.create.addSources([big.path])
        app.create.blockMode = .count
        app.create.blockCount = 4000
        app.create.recoveryPercent = 30
        app.startCreate()
        let id = app.create.jobId
        waitFor("create running", timeout: 60) { job(app, id)?.state == .running }
        app.cancel(id!)
        let cancelled = finish(app, id, "cancel")
        XCTAssertEqual(cancelled?.state, .cancelled)
        XCTAssertNil(app.alert?.message)

        // Cancel on a finished (Done) job: no alert, state and result kept.
        let small = try writeFile(scratch, "small.bin", size: 100_000, seed: 10)
        app.create.sources = []
        app.create.outputEdited = false
        app.create.addSources([small.path])
        app.startCreate()
        let doneId = app.create.jobId
        let done = finish(app, doneId, "small create")
        XCTAssertEqual(done?.state, .done)
        app.cancel(doneId!)
        XCTAssertNil(app.alert?.message, "cancelling a finished job raised an alert")
        let after = job(app, doneId)
        XCTAssertEqual(after?.state, .done)
        XCTAssertEqual(after?.result, done?.result)
    }

    func testH_ACorruptStoreIsReportedAndKeptAside() throws {
        let store = scratch.appendingPathComponent("queue.json")
        try Data("{ this is not json".utf8).write(to: store)
        let core = try XCTUnwrap(FfiCore())
        var opened: Error?
        do { try core.openQueueStore(at: store.path) } catch { opened = error }
        let error = try XCTUnwrap(opened, "a corrupt store must be refused")
        let app = AppModel(core: core)
        app.reportStoreOpenFailure(error)
        XCTAssertNotNil(app.alert)
        let names = try FileManager.default.contentsOfDirectory(atPath: scratch.path)
        let kept = names.filter { $0.hasPrefix("queue.json.unreadable-") }
        XCTAssertEqual(kept.count, 1, "kept aside: \(names)")
        if let k = kept.first {
            XCTAssertEqual(try String(contentsOf: scratch.appendingPathComponent(k)), "{ this is not json")
        }
        // And the session still persists from here on (the store is armed).
        app.setConcurrency(2)
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.path), "the store is written again")
    }

    #endif
}
