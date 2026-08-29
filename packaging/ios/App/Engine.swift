// The on-device engine (TODO 281 IO1): the same nzbfast that runs on a
// desktop, linked into this app as a staticlib and serving its API on
// 127.0.0.1 from a background thread.
//
// iOS forbids exec, so there is no child process to supervise the way
// the Android app supervises one - `nzbfast_start` spawns a thread in
// THIS process. That makes several things simpler than their Android
// twins and is worth stating, because the Android code they mirror
// spends real effort on problems that do not exist here.
import Foundation

@MainActor
final class Engine: ObservableObject {

    enum State: Equatable {
        case off
        case starting
        case up(port: UInt16)
        case stopping
        case failed(String)
    }

    @Published private(set) var state: State = .off

    /// The start in flight, if there is one.
    ///
    /// TWO CALLERS CAN RACE, and one of them found this by running: the
    /// root view starts the engine on a cold launch in on-device mode,
    /// and anything else that asks for the engine (the Connect button,
    /// a QA link) asks at the same moment. Without this the second call
    /// reaches `nzbfast_start` while the first is still in its
    /// bootstrap, gets -1 "already running" - which is the ABI behaving
    /// correctly - and reports a failure to a caller whose engine is in
    /// fact about to come up perfectly. The app then sits on the
    /// first-run screen with a healthy engine behind it.
    ///
    /// Awaiting the in-flight Task rather than refusing the second call
    /// is what makes `start()` mean "make sure it is up" to every
    /// caller, which is what all of them actually want.
    private var inFlight: Task<ServerConfig, Error>?

    /// Engine state: config, settings, the runtime record and the spool.
    ///
    /// Application Support and NOT Documents, which is the split the
    /// `out_dir` argument was added to `nzbfast_start` for: Documents is
    /// what `UIFileSharingEnabled` puts in front of the user, and none
    /// of this belongs there.
    static var stateDir: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("nzbfast", isDirectory: true)
    }

    /// Where finished downloads land, and the reason the app declares
    /// `UIFileSharingEnabled`: the Files app shows this directory, so a
    /// finished job is reachable with no export step and no second
    /// permission to ask for. That is the plan's decision for iOS and it
    /// is the opposite of the Android one, where a document tree has no
    /// `pwrite` and the payload has to be copied out after the fact.
    static var downloadsDir: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private static let runtimeName = "runtime.json"
    private static let keyDefault = "nzbfast.device.apikey"

    /// The per-install API key for the local engine.
    ///
    /// LOOPBACK IS NOT PRIVATE ON iOS. App sandboxing does not extend to
    /// 127.0.0.1: another app on the phone can connect to this listener,
    /// so an open API would hand it the queue, the history and
    /// `mode=server_secret`, which reads back the user's stored provider
    /// password. So a key is minted once and required.
    ///
    /// UserDefaults rather than the Keychain, matching where the remote
    /// mode's key already lives. Moving both is one job and is already
    /// written down as one; moving only this half would leave the two
    /// credentials in different places for no gain.
    static func apiKey() -> String {
        if let k = UserDefaults.standard.string(forKey: keyDefault), !k.isEmpty {
            return k
        }
        var bytes = [UInt8](repeating: 0, count: 24)
        // A failure here is not a reason to fall back to something
        // guessable: refuse the weak key and use the OS's other random
        // source rather than a timestamp.
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            bytes = (0..<24).map { _ in UInt8.random(in: 0...255) }
        }
        let key = bytes.map { String(format: "%02x", $0) }.joined()
        UserDefaults.standard.set(key, forKey: keyDefault)
        return key
    }

    /// Start the engine and hand back the endpoint to talk to it on.
    ///
    /// PORT 0, and the port read back afterwards. A fixed port is one a
    /// sibling app can pre-bind - the trap TODO 158 item 4 fixed on
    /// Android - and asking the OS for a free one removes the race
    /// rather than detecting it: nothing else can be holding a port the
    /// kernel has just handed us.
    func start() async throws -> ServerConfig {
        if case .up(let port) = state {
            return ServerConfig(baseURL: Self.localURL(port: port), apiKey: Self.apiKey())
        }
        if let inFlight { return try await inFlight.value }
        let task = Task { try await self.startOnce() }
        inFlight = task
        defer { inFlight = nil }
        return try await task.value
    }

    private func startOnce() async throws -> ServerConfig {
        state = .starting
        let stateDir = Self.stateDir
        let outDir = Self.downloadsDir
        let key = Self.apiKey()
        do {
            try Self.prepareDirectories(stateDir: stateDir, outDir: outDir)
        } catch {
            state = .failed("Could not create the app's folders.")
            throw EngineError.setup("Could not create the app's folders.")
        }
        // The record the port is read back out of. Removed BEFORE the
        // start so what turns up afterwards is provably from THIS run:
        // with the file gone and the app container private to us,
        // nothing else on the phone can put one there. That is a
        // stronger test than the Android app's `hs` challenge and is
        // available only because the engine is in-process - see
        // `awaitRuntime`.
        try? FileManager.default.removeItem(at: stateDir.appendingPathComponent(Self.runtimeName))

        // ANDROID HAS NO SYSTEM TRASH AND NEITHER DOES iOS, and this
        // one line is what stops every "delete the files too" being a
        // lie. MEASURED HERE, both ways, on 27 Aug 2026 in the
        // Simulator rather than inherited from the Android finding:
        // with this line a history delete took the app's Documents from
        // 286 MB to 28 KB, and with it commented out the identical call
        // answered `{"removed":1,"status":true}` and left all 38 MB in
        // place. The mechanism is that `trash_suits_this_platform()` is
        // `!(linux || freebsd)`, so the recoverable route is ON by
        // default here, while `trash_delete_bounded`'s
        // `cfg(any(android, ios))` arm can only ever answer "no system
        // trash on this platform" - so the delete refuses and the
        // engine logs a notice naming a dashboard setting this app does
        // not show.
        //
        // A LANE HOLDS `mobile-trash-default-ios` TO FIX THE ENGINE END
        // of that, off this measurement, by making
        // `trash_suits_this_platform()` agree with the cfg arm. If that
        // lands, this line becomes belt-and-braces rather than the fix -
        // which is a good place for it to be, and is not a reason to
        // delete it: it is what the Android launcher sets too, and it
        // keeps this app's behaviour independent of a default the engine
        // is free to change. `smart.rs`'s
        // recoverable-delete arm is a `cfg` that refuses on both by
        // construction, and the engine's own default sends deletes
        // there - so with this unset every "delete the files too" leaves
        // the payload on the phone under a success message, naming a
        // dashboard setting this app does not show. Measured on the
        // Android emulator at 40 MB kept after a delete that reported
        // success (TODO 281 AN3); the platform half of that finding is
        // identical here.
        setenv("NZBFAST_NO_TRASH", "1", 1)

        // AN4's CPU half, which iOS did not have until TODO 281 IO2.
        // Every CPU-bound pool in the engine - PAR2 verify and repair,
        // the syndrome fold, the matrix inversion, the settle pass, the
        // decoders, the archive backfill - sizes itself from
        // `available_parallelism`, which counts the efficiency cores as
        // if they were performance ones. `NZBFAST_CPU_WORKERS` is the
        // one ceiling that caps them all at once; see
        // `DeviceProfile.cpuWorkers` for why the answer is the
        // performance cluster.
        //
        // SET BEFORE THE START, and that is the whole of the safety
        // argument for it being an environment variable rather than an
        // argument: `nzbkit::mem::cpu_workers` latches its answer in a
        // `OnceLock`, so the read happens on the engine's first pool and
        // nothing writes the variable again. The MEMORY budget is an ABI
        // argument instead, and `nzbfast_start`'s doc comment says why
        // the two are not spelled alike.
        setenv("NZBFAST_CPU_WORKERS", String(DeviceProfile.cpuWorkers()), 1)

        // The engine's own default is a QUARTER OF PHYSICAL RAM, which
        // is a desktop figure and the one default a phone must not take:
        // measured on this dev box it comes out at the 16 GB ceiling.
        // Jetsam judges `phys_footprint` against a per-device limit and
        // kills a foreground app that crosses it outright, so the budget
        // has to be a number this side chooses. See
        // `DeviceProfile.memLimitBytes` for the rule and TODO 281 IO2
        // for the measurement behind it.
        let memLimit = DeviceProfile.memLimitBytes()
        let rc = stateDir.path.withCString { dir in
            outDir.path.withCString { out in
                key.withCString { k in nzbfast_start(dir, out, 0, k, memLimit) }
            }
        }
        guard rc == 0 else {
            let why = rc == -1
                ? "The engine is already running."
                : "The engine refused to start (code \(rc))."
            state = .failed(why)
            throw EngineError.start(why)
        }
        guard let port = await Self.awaitRuntime(stateDir: stateDir) else {
            // Do not leave a half-started engine registered: a host that
            // cannot find the port cannot use it either, and leaving it
            // up means the next start answers -1 forever. The stop blocks
            // up to 12 s (see nzbfast.h), so it runs off the main actor -
            // this await suspends rather than freezing the UI.
            _ = await Task.detached { nzbfast_stop() }.value
            state = .failed("The engine started but never said which port it was on.")
            throw EngineError.start("The engine started but never said which port it was on.")
        }
        state = .up(port: port)
        return ServerConfig(baseURL: Self.localURL(port: port), apiKey: key)
    }

    /// Stop the engine. Bounded by the ABI (12 s per call); -2 means it
    /// is still winding up, which is a state rather than a failure - see
    /// crates/nzbfast-ffi/include/nzbfast.h.
    ///
    /// The call can block for its full bound, so it never runs on the
    /// main actor: the wind-down happens on a detached task and only the
    /// published state comes back here. -2 re-calls `nzbfast_stop`, which
    /// is the header's documented way to wait longer - each re-call
    /// parks the worker thread for another bound, never the UI.
    func stop() {
        if case .stopping = state { return }  // a wind-down task already owns it
        state = .stopping
        Task.detached { [weak self] in
            var rc = nzbfast_stop()
            while rc == -2 { rc = nzbfast_stop() }
            await MainActor.run { self?.state = .off }
        }
    }

    var isRunning: Bool { nzbfast_is_up() == 1 }

    // MARK: - internals

    enum EngineError: LocalizedError {
        case setup(String)
        case start(String)

        var errorDescription: String? {
            switch self {
            case .setup(let m), .start(let m): return m
            }
        }
    }

    private static func localURL(port: UInt16) -> URL {
        // Force-unwrap of a URL built from a literal scheme, a literal
        // host and an integer: there is no input here that could make it
        // fail.
        URL(string: "http://127.0.0.1:\(port)")!
    }

    private static func prepareDirectories(stateDir: URL, outDir: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: stateDir, withIntermediateDirectories: true)
        try fm.createDirectory(at: outDir, withIntermediateDirectories: true)
        // Engine state is re-creatable and some of it is large (the
        // spool holds part-downloaded articles), so it is kept out of
        // iCloud and iTunes backups. Documents is NOT excluded: that is
        // the user's finished media, and deciding for them is not this
        // code's call.
        var mutable = stateDir
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? mutable.setResourceValues(values)

        // SEED THE CONFIG, always, and this is not a convenience.
        // `nzbkit::config::Config::load` answers a MISSING file by going
        // and finding a SABnzbd install's `sabnzbd.ini` through `$HOME`.
        // On a phone there is none, so the practical result is an engine
        // configured by whatever that search happens to return rather
        // than by this app - the same class of defect
        // tools/host-config-gate.py exists to refuse in the test tree.
        // An empty server list is a definite answer; the setup screen
        // fills it in through `mode=server_save`, so no provider
        // credential is ever written from Swift.
        //
        // `nzbfast_start` refuses (-3) rather than reaching $HOME since
        // 28 Aug 2026, so this seed is what keeps the start ACCEPTED -
        // not, as it was, what keeps it honest.
        let config = stateDir.appendingPathComponent(nzbfastConfigFile)
        if !fm.fileExists(atPath: config.path) {
            try Data(#"{"servers":[]}"#.utf8).write(to: config, options: .atomic)
        }
    }

    /// Poll for the runtime record this run wrote, and take the port out
    /// of it.
    ///
    /// `pid` is checked against our own, which on any other platform
    /// would be a weak test and here is the decisive one: the engine
    /// runs INSIDE this process, so `std::process::id()` is this app's
    /// pid. Combined with deleting the file before the start, a record
    /// that matches is one this run wrote - it cannot be a leftover from
    /// a previous launch (different pid) and it cannot be a plant (the
    /// app container is private).
    private static func awaitRuntime(stateDir: URL, tries: Int = 100) async -> UInt16? {
        let path = stateDir.appendingPathComponent(runtimeName)
        let mypid = Int(ProcessInfo.processInfo.processIdentifier)
        for _ in 0..<tries {
            if let data = try? Data(contentsOf: path),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let port = obj["port"] as? Int, (1...65535).contains(port),
               let pid = obj["pid"] as? Int, pid == mypid,
               // We pass no TLS material, so a record claiming https is
               // not describing our listener.
               (obj["tls"] as? Bool) != true {
                return UInt16(port)
            }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return nil
    }
}

/// The config file name `nzbfast_start` loads out of its state
/// directory.
///
/// It mirrors `nzbfast_ffi::CONFIG_FILE` and has to: the engine joins
/// that name itself, so a seed written under any other one is a seed the
/// engine never reads, and the failure is the silent one above - a
/// config search that reaches past the app instead of a file that is
/// missing. Kept beside the only code that writes it.
let nzbfastConfigFile = "config.local.json"
