import Foundation
// Launcher handshake only (see `isNzbfast`): the engine proves it holds the
// token in runtime.json before this wrapper hands it the stored API key.
import CryptoKit
import os

/// Owns the bundled `nzbfast serve` engine: attach to an already-running
/// daemon on the persisted port, or spawn our own as a managed child.
/// Program/data separation per packaging/INSTALLER-SPEC.md: binaries stay
/// in the bundle, mutable state in ~/Library/Application Support/nzbfast,
/// downloads in "~/Downloads/nzbfast downloads", and ~/Downloads itself
/// is the watch folder - save an .nzb anywhere you normally download and
/// it's queued automatically (only .nzb files are touched; the watcher
/// is non-recursive so the output folder below it is never scanned).
final class Daemon {
    static let shared = Daemon()
    private static let log = Logger(subsystem: "com.nzbfast.app", category: "daemon")

    /// Rehearsal isolation. When set, EVERY mutable path - data dir,
    /// downloads, watch folder, and the persisted port - lives under this
    /// root, so a test build can never see the real install's state,
    /// attach to its daemon, or upgrade-restart it. Overriding $HOME is
    /// NOT enough for that: FileManager's user-domain lookups in a GUI
    /// app resolve the real home regardless, which is how a quit
    /// rehearsal build found the live data dir and put a crash alert on
    /// the user's screen (8 Aug 2026). Never set in production.
    static let testRoot: URL? = ProcessInfo.processInfo.environment["NZBFAST_TEST_ROOT"]
        .map { URL(fileURLWithPath: $0, isDirectory: true) }

    let dataDir = testRoot?.appendingPathComponent("data")
        ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("nzbfast")
    /// The user's Downloads folder - watch target and output parent.
    let watchDir = testRoot?.appendingPathComponent("watch")
        ?? FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
    /// Pre-1.0.2 builds downloaded to ~/Downloads/nzbfast - keep using it
    /// when it already exists so an upgrade doesn't split the library.
    let downloadsDir: URL = {
        if let root = testRoot { return root.appendingPathComponent("downloads") }
        let dl = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let legacy = dl.appendingPathComponent("nzbfast")
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: legacy.path, isDirectory: &isDir), isDir.boolValue {
            return legacy
        }
        return dl.appendingPathComponent("nzbfast downloads")
    }()
    var logURL: URL { dataDir.appendingPathComponent("daemon.log") }

    /// The port the dashboard lives on. Persisted so relaunches attach to
    /// the same daemon instead of scanning again. Under a test root the
    /// persistence moves to a file there - UserDefaults reaches the real
    /// preference store whatever $HOME says, and a remembered REAL port
    /// is an attach (and §98 upgrade-restart) waiting to happen.
    private(set) var port: Int = {
        guard let root = testRoot else {
            return UserDefaults.standard.integer(forKey: "daemonPort")
        }
        let f = root.appendingPathComponent("port.txt")
        return Int((try? String(contentsOf: f, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "") ?? 0
    }()

    /// The one writer of the persisted port (see `port` above for why the
    /// test root gets a file).
    private func persistPort(_ p: Int) {
        port = p
        if let root = Daemon.testRoot {
            try? String(p).write(
                to: root.appendingPathComponent("port.txt"), atomically: true, encoding: .utf8)
        } else {
            UserDefaults.standard.set(p, forKey: "daemonPort")
        }
    }
    private(set) var child: Process?
    /// True when THIS app launched the engine - only then may quit stop it.
    private(set) var spawnedByUs = false
    /// Did the last successful probe PROVE the listener's identity, via
    /// the runtime.json token challenge? Legacy adoption - an
    /// nzbfast-shaped reply with no runtime.json to hold it to - attaches
    /// but stays `false`, and `keyBearingAllowed` then strips the stored
    /// API key from every URL this wrapper builds: sending it to a
    /// listener whose identity is only a reply shape hands any local
    /// port-squatter daemon control and, through `mode=server_secret`,
    /// the provider password (Codex sweep 10 Aug M10). A child we
    /// spawned ourselves is covered by `spawnedByUs` instead.
    private(set) var identityProven = false
    /// May a URL we build carry the stored API key? See `identityProven`.
    /// Unproven-and-not-ours means keyless calls: the engine refuses
    /// them (harmless), and the dashboard prompts rather than being
    /// handed the key.
    private var keyBearingAllowed: Bool { identityProven || spawnedByUs }
    /// Forget that the listener proved itself, because the generation
    /// that proved it is over.
    ///
    /// The proof is a statement about ONE process: the engine that
    /// answered `hs=<nonce>` with sha256 of the token in `runtime.json`.
    /// It used to be set once and never cleared, so a child that died -
    /// or was replaced by Try Again, or by an upgrade restart - left the
    /// flag standing, and the next URL this wrapper built carried the
    /// stored API key to whatever now held 127.0.0.1 on that port. That
    /// key is full control and, through `mode=server_secret`, the
    /// provider password in cleartext (Codex sweep 26 Aug, P1-2) - the
    /// same disclosure `identityProven` exists to prevent, one daemon
    /// generation later. The Windows tray clears and re-arms the same
    /// latch around its own restart; this is that rule.
    ///
    /// Nothing has to hand the proof back by hand: `isNzbfast` mints it,
    /// and every path that ends a generation is followed by a probe -
    /// `start()` probes before it attaches, `waitUntilUp` probes after a
    /// spawn. Until one of them answers, `keyBearingAllowed` is false and
    /// the URLs this wrapper builds are keyless, which the engine refuses
    /// harmlessly and an impostor learns nothing from.
    private func clearIdentityProof(_ why: String) {
        guard identityProven else { return }
        identityProven = false
        Self.log.notice("listener proof cleared: \(why, privacy: .public)")
    }
    /// The listener on `port` answered the challenge. Logged only on the
    /// transition, and it is the half the log was missing: since the
    /// proof started going DOWN mid-session (`recheckListener`), a log
    /// that records only the drops describes a wrapper that stopped
    /// trusting its engine and never started again, which is not what
    /// happened. The pair is how a support log shows a blip.
    private func armIdentityProof(_ port: Int) {
        if !identityProven {
            Self.log.notice("listener proof armed: port \(port, privacy: .public)")
        }
        identityProven = true
    }
    /// A listener that ANSWERED and is not the engine we proved. Whatever
    /// proof was standing described a different process, so drop it -
    /// this is the authentication-failure arm of the rule above.
    ///
    /// The no-reply arm reaches `clearIdentityProof` too, but only
    /// through `recheckListener` and never through the attach scan in
    /// `start()`, which walks up to three candidate PORTS and would
    /// otherwise disarm the port we hold a proof for because a different
    /// one did not answer. Until 26 Aug 2026 nothing cleared on a silent
    /// probe at all: nothing here re-probed on a schedule, so one
    /// transient timeout would have stripped the key from a healthy
    /// ATTACHED engine for the rest of the session with no path back
    /// short of relaunching. `recheckListener` is that path, which is
    /// what makes the silent arm affordable.
    private func refuseListener(_ port: Int, _ why: String) -> Daemon.ProbeVerdict {
        clearIdentityProof("port \(port): \(why)")
        return .stranger
    }

    /// What one keyless probe of one port concluded.
    ///
    /// `isNzbfast` collapses this to attach / do-not-attach, which is all
    /// the attach scan needs. The periodic re-proof needs the three-way
    /// answer, because "answered, and is not ours" and "nothing answered"
    /// are different kinds of evidence and this wrapper acts on each
    /// differently - see `recheckListener` and the counters in
    /// `StatusItemController`.
    enum ProbeVerdict {
        /// Answered and proved it holds `runtime.json`'s token.
        case proven
        /// Answered in the nzbfast shape with no `runtime.json` naming
        /// this port to hold it to. Attachable, but key-bearing URLs
        /// stay keyless for it - see `identityProven`.
        case adopted
        /// Something answered and it is not the engine we proved.
        case stranger
        /// Nothing answered.
        case silent

        /// May `start()` attach to this listener?
        var attachable: Bool { self == .proven || self == .adopted }
    }

    /// Ask the listener on the CURRENT port to prove itself again, and
    /// forget the proof if it cannot.
    ///
    /// The proof is a statement about one process and the port outlives
    /// it (see `clearIdentityProof`). Every generation-ending path this
    /// wrapper can SEE - the termination handler, the reap, the restart -
    /// belongs to a child. An engine this app ATTACHED to has no child
    /// and no termination handler, so its death was invisible: the proof
    /// stood, `keyBearingAllowed` stood with it, and the menu bar poll
    /// went on posting the master API key every 3 to 5 seconds at a
    /// 127.0.0.1 port nothing of ours held. Measured 26 Aug 2026 against
    /// a recording listener bound to the freed port: `mode=queue` with
    /// `apikey=` in the query every 3 s from here, and `mode=dashboard`
    /// with the same key in an `X-Api-Key` header every second from the
    /// embedded page. That key is full control and, through
    /// `mode=server_secret`, the provider password in cleartext.
    ///
    /// The probe carries no key and a fresh nonce, so running it against
    /// a stranger teaches the stranger nothing, and a success re-mints
    /// the proof by itself - which is what lets the silent arm clear at
    /// all. The caller decides what a verdict is worth; this only decides
    /// what the wrapper may still put on the wire.
    func recheckListener() async -> ProbeVerdict {
        let verdict = await probe(port: port)
        if verdict == .silent {
            clearIdentityProof("port \(port) stopped answering the keyless challenge")
        }
        return verdict
    }
    /// Set before any stop we initiate, so terminationHandler can tell a
    /// crash from a requested exit.
    private var deliberateStop = false
    /// Set for good once stop() begins. spawn() refuses past this point,
    /// so a quit that lands mid-startup can't have start() bring up a
    /// fresh engine AFTER the stop already swept - that engine would
    /// outlive the app as an orphan.
    private var stopping = false
    /// Called on the main queue when the child dies on its own.
    var onUnexpectedExit: ((String) -> Void)?

    /// The session every call to our own engine goes through.
    ///
    /// It differs from `URLSession.shared` in exactly one way: it accepts
    /// the certificate on 127.0.0.1 (see `LoopbackTrust`). A shared
    /// session cannot carry a delegate, which is why this exists at all.
    static let loopback: URLSession = URLSession(
        configuration: .ephemeral, delegate: LoopbackTrust(), delegateQueue: nil)

    /// Accept whatever certificate our own engine presents on loopback.
    ///
    /// A TLS-enabled install points `tls_cert` at an operator-supplied
    /// certificate: self-signed, and issued for the hostname the LAN or a
    /// proxy reaches it by, never for 127.0.0.1. So a verifying client
    /// refuses it - and refusing is precisely what left this wrapper
    /// unable to manage a TLS engine at all.
    ///
    /// Accepting it gives nothing away, because the certificate was never
    /// what identified this engine. The connection is to 127.0.0.1, which
    /// nothing on the network can sit in the middle of; the threat is a
    /// local process squatting the port, and that is what the
    /// `runtime.json` token handshake answers - a challenge only the
    /// engine that wrote a file this user alone can read can pass. The
    /// API key still rides behind that proof, exactly as on plain HTTP.
    ///
    /// Scoped to 127.0.0.1 and to server trust: every other host and
    /// every other kind of challenge falls through to the default
    /// handling, so this cannot become a blanket opt-out.
    private final class LoopbackTrust: NSObject, URLSessionDelegate {
        func urlSession(
            _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            let space = challenge.protectionSpace
            guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  space.host == "127.0.0.1",
                  let trust = space.serverTrust
            else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }

    /// Scheme + authority for everything this wrapper addresses at the
    /// engine, and for the dashboard it loads into the web view.
    ///
    /// Saving a valid `tls_cert`/`tls_key` pair and restarting makes the
    /// engine bind HTTPS. The wrapper used to probe `http://` regardless,
    /// see a healthy listener answer nothing it recognised, classify its
    /// own engine as foreign, and then be unable to open, stop, upgrade
    /// or quit it. `runtime.json` carries the scheme (§129 2a); this is
    /// the single place that turns it into a URL, so no call site can
    /// drift back to a hardcoded one.
    func origin(_ port: Int, tls: Bool) -> String {
        "\(tls ? "https" : "http")://127.0.0.1:\(port)"
    }

    var baseURL: URL { URL(string: "\(origin(port, tls: runtimeTLS(forPort: port)))/")! }

    /// For QuitWatchdog's last resort ONLY: the pid of the engine WE
    /// spawned, readable from the watchdog's background thread. Nil when
    /// attached - an attached engine is never ours to kill, even then.
    var childPidForEmergencyKill: pid_t? {
        guard spawnedByUs, let c = child, c.isRunning else { return nil }
        return c.processIdentifier
    }

    private var engineURL: URL {
        Bundle.main.resourceURL!.appendingPathComponent("bin/nzbfast")
    }

    /// The daemon's full API key. Two sources, in the daemon's own
    /// precedence order (serve.rs applies settings.json first, and
    /// first_run_apikey then bows out if a key is already set):
    ///   1. a key the user set in the dashboard - settings.json
    ///   2. the one the daemon minted for itself on a first run - the
    ///      `apikey` file next to config.local.json (serve::first_run_apikey
    ///      writes `config.with_file_name("apikey")`, and we pass
    ///      --config dataDir/config.local.json, so that is dataDir/apikey)
    /// An install that is deliberately keyless (NZBFAST_OPEN=1, or a
    /// pre-minting upgrade that never set one) has neither, and nil is the
    /// right answer there. Lets the wrapper authenticate its own
    /// housekeeping calls (shutdown, addfile, version).
    private var apiKey: String? {
        let fromSettings: String? = {
            let settings = dataDir.appendingPathComponent("settings.json")
            guard let data = try? Data(contentsOf: settings),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let key = obj["apikey"] as? String else { return nil }
            let k = key.trimmingCharacters(in: .whitespacesAndNewlines)
            return k.isEmpty ? nil : k
        }()
        if let fromSettings { return fromSettings }
        let keyfile = dataDir.appendingPathComponent("apikey")
        guard let raw = try? String(contentsOf: keyfile, encoding: .utf8) else { return nil }
        let k = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return k.isEmpty ? nil : k
    }

    /// The dashboard port saved in settings.json, if the user has set one.
    /// Read with the same approach as the apikey fallback above.
    ///
    /// The dashboard's Port setting is restart-only: it is persisted here
    /// and the engine's own apply_saved_settings overrides its `--port`
    /// with it at startup. So a saved port is the port the engine WILL
    /// bind whatever we ask for, and the wrapper has to follow it.
    private func savedPort() -> Int? {
        let settings = dataDir.appendingPathComponent("settings.json")
        guard let data = try? Data(contentsOf: settings),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return Daemon.savedPort(inSettings: obj)
    }

    /// Pull a usable port out of a decoded settings.json. Split out so the
    /// rule is testable without a file.
    ///
    /// Matches what the daemon accepts: a JSON number, and the same 1-65535
    /// range the config writer validates. Anything else (absent, null, a
    /// string, out of range) means "no saved port", which is exactly the
    /// case where the engine keeps the `--port` we pass it.
    static func savedPort(inSettings obj: [String: Any]) -> Int? {
        guard let n = obj["port"] as? NSNumber else { return nil }
        // JSON true bridges to NSNumber too and would read as port 1. The
        // daemon's as_u64 rejects a bool, so we reject it as well.
        guard CFGetTypeID(n as CFTypeRef) != CFBooleanGetTypeID() else { return nil }
        let p = n.intValue
        return (1...65535).contains(p) ? p : nil
    }

    /// Percent-encode a query value. The daemon urldecodes every query
    /// value and reads a bare `+` as a space, so a key with punctuation in
    /// it has to arrive encoded; the dashboard's URLSearchParams adoption
    /// hook decodes the same way. `%`-encoding everything outside the
    /// unreserved set keeps both readers honest.
    private func queryEscaped(_ s: String) -> String {
        var unreserved = CharacterSet.alphanumerics
        unreserved.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s
    }

    func apiURL(_ mode: String, _ extra: String = "") -> URL {
        var q = "mode=\(mode)"
        if keyBearingAllowed, let k = apiKey { q += "&apikey=\(queryEscaped(k))" }
        if !extra.isEmpty { q += "&\(extra)" }
        return URL(string: "\(origin(port, tls: runtimeTLS(forPort: port)))/api?\(q)")!
    }

    /// The dashboard URL to load, carrying the API key when we know one.
    /// web/dashboard.html adopts `?apikey=` into localStorage and then
    /// history.replaceState's it out of the address bar, so a fresh install
    /// isn't met by a prompt for a credential the daemon minted seconds
    /// earlier and only ever printed to a log this user never sees. A
    /// keyless install gets the plain baseURL, exactly as before.
    ///
    /// Only ever hand this to a port we have confirmed is nzbfast - i.e.
    /// after start() returns .attached/.spawned, never to a bare port
    /// number.
    var dashboardURL: URL {
        // Two independent gates: `keyBearingAllowed` decides whether the
        // key may ride at all (M10), `origin` decides how to reach the
        // listener (M1). An unproven TLS engine gets https WITHOUT a key.
        guard keyBearingAllowed, let k = apiKey else { return baseURL }
        let base = origin(port, tls: runtimeTLS(forPort: port))
        return URL(string: "\(base)/?apikey=\(queryEscaped(k))") ?? baseURL
    }

    // MARK: probing

    /// The port `runtime.json` says a listener actually BOUND, whatever
    /// port it was asked for.
    ///
    /// The only file the engine itself writes, and the only one that
    /// records the address the listener GOT rather than the address
    /// somebody wanted - so it is the first place to look for a live
    /// engine, and `runtimeFile(forPort:)` below cannot answer that
    /// question because it takes the port as a premise. Without it the
    /// attach scan asked only `settings.json` and the port we last used:
    /// an engine started while the configured port was taken (by a CLI
    /// `nzbfast serve`, or by a previous run that scanned past it) sits
    /// on a port neither of them names, this app finds the configured
    /// port free, spawns, and there are two engines over one spool, one
    /// index and one watch folder. The Windows tray's
    /// `handoff_candidates` has ordered its sources this way all along.
    private func runtimePort() -> Int? {
        guard let data = try? Data(contentsOf: dataDir.appendingPathComponent("runtime.json")),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let p = obj["port"] as? Int, (1...65535).contains(p)
        else { return nil }
        return p
    }

    /// `runtime.json`, parsed, when it describes the engine on `port`.
    /// Written by the engine once its listener exists; absent for an
    /// engine older than the handshake, or one started elsewhere.
    private func runtimeFile(forPort port: Int) -> [String: Any]? {
        guard let data = try? Data(contentsOf: dataDir.appendingPathComponent("runtime.json")),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let filePort = obj["port"] as? Int, filePort == port
        else { return nil }
        return obj
    }

    /// The per-start secret the engine on `port` can prove it holds.
    private func runtimeToken(forPort port: Int) -> String? {
        guard let obj = runtimeFile(forPort: port),
              let token = (obj["token"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token.isEmpty
        else { return nil }
        return token
    }

    /// Does the engine on `port` speak TLS? Only `runtime.json` knows,
    /// and only when it names THIS port - an engine from another data
    /// dir, or one older than the key, leaves us guessing, and the probe
    /// resolves that by trying both (see `isNzbfast`).
    ///
    /// The key is additive, so absent, non-boolean and false all have to
    /// read as plain HTTP: assuming https for an engine that never bound
    /// it would break the ordinary attach this whole change exists to
    /// preserve.
    func runtimeTLS(forPort port: Int) -> Bool {
        (runtimeFile(forPort: port)?["tls"] as? Bool) ?? false
    }

    /// sha256("token:nonce") as lowercase hex - the answer the engine
    /// returns for `hs=<nonce>`, computed here to compare with it.
    static func launcherProof(token: String, nonce: String) -> String {
        let digest = SHA256.hash(data: Data("\(token):\(nonce)".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// May `start()` attach to the listener on `port`? The two-way form
    /// of `probe`, which is where the whole rule lives.
    func isNzbfast(port: Int, timeout: TimeInterval = 1.5) async -> Bool {
        await probe(port: port, timeout: timeout).attachable
    }

    /// `probe`, three-way. Split out from `isNzbfast` because the
    /// periodic re-proof (`recheckListener`) has to tell a stranger from
    /// a silence, and the attach scan does not care.
    ///
    /// Does `port` answer /api?mode=version as an nzbfast daemon?
    /// A keyed daemon's refusal counts too: only nzbfast answers in that
    /// shape, and the dashboard is handed the key (or prompts) after attach.
    ///
    /// A reply shape is not identity, though, and a true answer here means
    /// attach-and-then-hand-over-the-API-key. So when `runtime.json` names
    /// THIS port, the listener must also prove it holds that file's token:
    /// any local account can print our JSON, but only this user can read
    /// that file (Application Support is user-only). The token never
    /// travels in either direction - the engine returns
    /// sha256(token:nonce) for a nonce we make up per probe - so probing an
    /// impostor teaches it nothing.
    ///
    /// An engine that answers with no proof while `runtime.json` names
    /// this port is REFUSED (see `provesIdentity`): a token in that file
    /// can only have been written by an engine that also answers the
    /// challenge, so proofless-with-token is a stranger, not an upgrade
    /// case. Only when there is no runtime.json for the port - the actual
    /// pre-handshake engine, or one from another data dir - is the reply
    /// shape alone accepted.
    ///
    /// The scheme comes from `runtime.json` too. When it names this port
    /// its `tls` is authoritative - one request, as before. When it does
    /// NOT, we no longer assume plain HTTP: a TLS listener answers a
    /// plaintext GET with an alert and a close, which URLSession reports
    /// as a transport error, so the wrapper called its own healthy engine
    /// unreachable. Only that miss costs a second request.
    private func probe(port: Int, timeout: TimeInterval = 1.5) async -> ProbeVerdict {
        // Probe WITHOUT the key. Nothing has authenticated the far side yet, so
        // any unprivileged local process that binds this port first (6789 is
        // well known and the port is readable from UserDefaults) would receive
        // the full API key in the query string - and that key unlocks
        // get_config/server_secret, i.e. the Usenet provider password in
        // cleartext. The key isn't needed here: the refusal phrases below are
        // signature enough, and only nzbfast answers in that shape.
        // The challenge rides the same keyless probe: a fresh nonce per
        // call, so a recorded answer cannot be replayed at us later.
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let q = "mode=version&hs=\(nonce)"
        let file = runtimeFile(forPort: port)
        let ask: (Bool) async -> [String: Any]? = { tls in
            guard let url = URL(string: "\(self.origin(port, tls: tls))/api?\(q)") else {
                return nil
            }
            var req = URLRequest(url: url)
            req.timeoutInterval = timeout
            guard let (data, _) = try? await Daemon.loopback.data(for: req) else { return nil }
            return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        }
        let reply: [String: Any]?
        if let file {
            reply = await ask((file["tls"] as? Bool) ?? false)
        } else if let plain = await ask(false) {
            reply = plain
        } else {
            reply = await ask(true)
        }
        guard let obj = reply else { return .silent }
        guard Daemon.isNzbfastReply(obj) else {
            return refuseListener(port, "answered, but not as an nzbfast engine")
        }
        let token = runtimeToken(forPort: port)
        guard Daemon.provesIdentity(obj, token: token, nonce: nonce) else {
            return refuseListener(port, "failed the runtime.json challenge")
        }
        // Proven only when a token was actually challenged. The legacy
        // arm (no runtime.json) attaches, but key-bearing URLs stay
        // keyless for it - see `identityProven`. That arm goes through
        // `clearIdentityProof` rather than assigning false, so a port
        // whose runtime.json has gone away under a standing proof says
        // so in the log instead of disarming in silence.
        guard token != nil else {
            clearIdentityProof("port \(port) answered with no runtime.json to hold it to")
            return .adopted
        }
        armIdentityProof(port)
        return .proven
    }

    /// The identity half of the probe, split out so it is testable without
    /// a socket. See `probe` for why each arm is what it is.
    static func provesIdentity(_ obj: [String: Any], token: String?, nonce: String) -> Bool {
        guard let token else {
            // Nothing to hold it to: no runtime.json for this port.
            return true
        }
        guard let proof = obj["hs_proof"] as? String else {
            // A token in runtime.json can only have been written by an
            // engine that also answers the challenge - the file write and
            // the proof reply shipped in the same release, and the write
            // is unconditional once the listener exists. So a reply with
            // no proof is NOT an older engine: an older engine leaves no
            // runtime.json and takes the `guard let token` arm above.
            // Refuse - attaching would disclose the stored API key, and
            // with it `mode=server_secret`.
            return false
        }
        let want = launcherProof(token: token, nonce: nonce)
        // Length first, then a full-width compare - no early exit on the
        // first differing byte.
        guard want.utf8.count == proof.utf8.count else { return false }
        return zip(want.utf8, proof.utf8).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// Classify a decoded /api?mode=version reply. Split out so the rule is
    /// testable without a socket.
    ///
    /// Since first-run key minting, a keyless probe of a keyed daemon gets
    /// "API Key Required" - serve.rs picks that exact phrase when no key is
    /// presented at all, and "API Key Incorrect" only when a wrong one is
    /// (they're the SAB phrases the *arrs substring-match). Accepting just
    /// the latter made this probe unable to recognise ANY daemon that had a
    /// key, which after minting is every fresh install: attach failed, the
    /// spawn's own daemon was then unrecognisable too, and start() reported
    /// failure while a healthy daemon was running.
    ///
    /// Keep this to those two exact phrases. A true return means "attach to
    /// this and never stop it", so treating any JSON reply as nzbfast would
    /// hand somebody else's server the dashboard - and our API key with it.
    static func isNzbfastReply(_ obj: [String: Any]) -> Bool {
        if obj["nzbfast"] != nil { return true }
        let err = obj["error"] as? String
        return err == "API Key Incorrect" || err == "API Key Required"
    }

    // MARK: §98 upgrade restart - version handshake on attach

    /// An engine version as ordered for the upgrade decision: the semver
    /// components, then the beta serial. A beta build is made AFTER the
    /// release its semver names (deploys bump packaging/beta-serial.txt;
    /// publish resets it), so "1.0.14 beta 5" is newer than "1.0.14" and
    /// older than "1.0.15".
    struct EngineVersion: Comparable, CustomStringConvertible {
        let nums: [Int]
        let beta: Int
        var description: String {
            let v = nums.map(String.init).joined(separator: ".")
            return beta > 0 ? "\(v) beta \(beta)" : v
        }
        static func parse(_ semver: String, beta: String) -> EngineVersion? {
            let nums = semver.split(separator: ".").compactMap { Int($0) }
            guard !nums.isEmpty else { return nil }
            return EngineVersion(nums: nums, beta: Int(beta) ?? 0)
        }
        static func < (a: EngineVersion, b: EngineVersion) -> Bool {
            for i in 0..<max(a.nums.count, b.nums.count) {
                let x = i < a.nums.count ? a.nums[i] : 0
                let y = i < b.nums.count ? b.nums[i] : 0
                if x != y { return x < y }
            }
            return a.beta < b.beta
        }
    }

    /// The version of the engine INSIDE this bundle, stamped into
    /// Info.plist by make-app.sh from the same two sources the engine's
    /// own build embeds (Cargo.toml + packaging/beta-serial.txt). Nil on
    /// a bundle without the beta key (predates §98) - the caller then
    /// attaches as it always did, which is the safe reading.
    static func bundledVersion() -> EngineVersion? {
        let info = Bundle.main.infoDictionary
        guard let v = info?["CFBundleShortVersionString"] as? String,
              let beta = info?["NzbFastBetaSerial"] as? String
        else { return nil }
        return EngineVersion.parse(v, beta: beta)
    }

    /// The version the engine on `self.port` is actually serving,
    /// AUTHENTICATED - the keyless probe of a keyed daemon only ever sees
    /// the refusal phrase, which carries no version. Nil when the key is
    /// missing or wrong (a daemon from another data dir): the caller must
    /// treat that as "not mine to restart" and attach.
    private func remoteVersion() async -> EngineVersion? {
        var req = URLRequest(url: apiURL("version"))
        req.timeoutInterval = 3
        guard let (data, _) = try? await Daemon.loopback.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let v = obj["nzbfast"] as? String
        else { return nil }
        return EngineVersion.parse(v, beta: obj["beta"] as? String ?? "")
    }

    /// §98: the running engine is OLDER than the one in this bundle -
    /// stop it and let the caller spawn ours. Shutdown by authenticated
    /// API on the port it serves, which reaches the old engine wherever
    /// its binary lives (the path-keyed sweep below only knows THIS
    /// bundle's path); the sweep is the backstop for an engine too wedged
    /// to answer. Returns true when the port came free - the caller then
    /// spawns; false means the old engine would not die, and attaching to
    /// it beats stranding the user with no engine at all.
    ///
    /// The wait is generous on purpose: mode=shutdown persists the queue
    /// first, and a busy engine has taken ~30 s to wind down (TODO §98
    /// point 2), so an impatient deadline here would fall through to the
    /// SIGTERM sweep and turn every slow-but-clean shutdown into an
    /// abrupt one.
    private func upgradeRestart() async -> Bool {
        var req = URLRequest(url: apiURL("shutdown"))
        req.httpMethod = "POST"
        req.timeoutInterval = 5
        _ = try? await Daemon.loopback.data(for: req)
        for _ in 0..<160 { // 40 s
            if !portTaken(port) { return oldEngineGone() }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        stopBundleOrphans()
        for _ in 0..<20 { // 5 s
            if !portTaken(port) { return oldEngineGone() }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    /// `upgradeRestart`'s "the old engine has let go of the port" answer,
    /// which is a generation boundary like any other: the engine that
    /// proved itself has exited, and its replacement proves itself again
    /// through `waitUntilUp` seconds later. The `false` answer keeps the
    /// proof on purpose - there the old engine is still running and still
    /// the one we attached to, and `start()` goes on to use it.
    private func oldEngineGone() -> Bool {
        clearIdentityProof("the engine being upgraded released :\(port)")
        return true
    }

    /// TCP-level check: is anything listening on 127.0.0.1:port?
    /// Localhost connects resolve immediately (accept or refuse), so a
    /// plain blocking connect is fine.
    private func portTaken(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return r == 0
    }

    // MARK: lifecycle

    enum StartResult {
        case attached           // daemon already up on the persisted port
        case spawned            // we launched a child
        case failed(String)     // couldn't start; message + log tail
    }

    /// Shared rule 4: attach to a port one of our engines already answers
    /// on; otherwise scan for a free port from 6789 and spawn.
    /// Never touches daemons on other ports.
    func start() async -> StartResult {
        // Resolve the port FIRST, before the spawn and the scan. A port
        // the user changed in the dashboard is applied by the engine at
        // startup no matter what `--port` says, so the value we
        // remembered in UserDefaults is stale the moment they change it.
        // Following it here is what keeps every later consumer - the
        // spawn argument, the health poll, the dashboard and API URLs,
        // and the shutdown POST - pointed at the one port the engine
        // actually binds. Without it start() reported failure against a
        // perfectly healthy child, and the quit sweep then killed that
        // child by executable path.
        let saved = savedPort()
        // Probe for a LIVE engine before any of that, over every port one
        // of ours could still be answering on.
        //
        // The saved port is restart-only - the engine reads it once at
        // startup - so right after a port change the engine that is still
        // running is on the PREVIOUS port. Attaching to it is the
        // single-engine-preserving choice: spawning on the new port
        // instead would leave two engines sharing config.local.json, the
        // index db and the watch folder. The new port applies on the next
        // restart, through the wrapper's normal stop/start path.
        //
        // `runtime.json` FIRST, by how much each source knows about where
        // the listener IS: the port it BOUND, then the port we last
        // attached to, then the port that was asked for, then the
        // shipped default. See `runtimePort()` for what the old
        // two-source scan missed.
        //
        // The trailing 6789 is what a true first run was missing: with no
        // runtime.json, no persisted port and no saved setting, the first
        // three all filter out to nothing, so the loop below never probed
        // 6789 at all - it went straight to the free-port scan, which
        // treats anything already bound there as a stranger (see the
        // comment on that scan). An engine of ours that was still up from
        // an earlier launch - crashed before it could persist a port,
        // started by hand, or simply not yet reflected in this process's
        // UserDefaults cache - was exactly that "anything", so first run
        // scanned past it to 6790 and spawned a second engine over the
        // same data directory. Probing 6789 here first, the same way the
        // Windows tray's `handoff_candidates` always does, means an
        // engine that proves itself as ours (see `isNzbfast`) is attached
        // to before the scan ever runs; the scan's stranger rule then
        // only fires for a listener that did NOT pass that proof, which
        // is genuinely not ours to touch.
        var candidates: [Int] = []
        for p in [runtimePort() ?? 0, port, saved ?? 0, 6789] where p > 0 && !candidates.contains(p) {
            candidates.append(p)
        }
        for candidate in candidates {
            guard await isNzbfast(port: candidate) else { continue }
            // Every consumer follows the port we ACTUALLY attached to.
            persistPort(candidate)
            // §98: an engine that outlives the app also outlives an
            // UPGRADE - installing a newer .dmg used to change nothing,
            // because this arm attached to the old engine and never
            // compared versions (localhost kept serving the previous
            // release with no hint). Restart it only when the bundle is
            // STRICTLY newer and both versions were readable; anything
            // ambiguous - unreadable Info.plist, a daemon whose key we
            // do not hold (another data dir's install) - attaches as it
            // always did. A newer RUNNING engine also just attaches:
            // downgrading a daemon someone deliberately updated ahead of
            // the app would be the same silent surprise in reverse.
            if let mine = Daemon.bundledVersion(),
               let running = await remoteVersion(),
               running < mine
            {
                NSLog(
                    "nzbfast: engine on :%d is v%@, bundle carries v%@ - upgrade restart",
                    port, running.description, mine.description)
                if await upgradeRestart() {
                    // The replacement engine binds the SAVED settings port,
                    // not the one the old engine held: the dashboard's Port
                    // setting is restart-only, and apply_saved_settings
                    // overrides `--port` with it at startup. Re-point the
                    // spawn argument and the health poll at it, or a port
                    // change followed by an upgrade waits 15 s on the dead
                    // old port and reaps the healthy child.
                    if let s = savedPort() { persistPort(s) }
                    do {
                        try spawn()
                    } catch {
                        return .failed(
                            "stopped the old engine but couldn't launch the new one: \(error.localizedDescription)")
                    }
                    if await waitUntilUp(timeout: 15) { return .spawned }
                    await reapFailedSpawn()
                    return .failed("the upgraded engine didn't answer on port \(port) within 15 s")
                }
                // The old engine would not stop. Attaching to it beats
                // stranding the user engineless; the log above says why
                // the dashboard still shows the old version.
                NSLog("nzbfast: old engine on :%d would not stop - attaching to it", port)
            }
            // ...unless the "external" engine is a child WE spawned that
            // is still running - attaching must not launder our own
            // child into an attachment, because quit's two sweeps each
            // excuse it: bundleOrphanPIDs excludes child.pid, and the
            // owned-child kill is gated on spawnedByUs. That laundering
            // is how a slow spawn plus Try Again left a daemon that
            // survived app quit (Codex sweep 24 Aug, F-14). The reap on
            // the timeout paths below makes this arm rare; it is the
            // belt for whatever still reaches here owning a live child.
            if !(spawnedByUs && child?.isRunning == true) {
                spawnedByUs = false
            }
            return .attached
        }
        // Nothing of ours is answering, so we spawn. A saved port wins
        // over the scan below: the engine binds it regardless of the
        // argument we pass, so a scanned port would just be ignored by
        // the child and strand us again. If something unrelated holds
        // that port the child can't bind it and says so in the log,
        // which is the honest outcome - the setting is the user's.
        //
        // Otherwise: free-port scan from 6789 (the shipped launchers'
        // rule). A port with ANY listener - nzbfast or not - is skipped.
        // By the time we get here, 6789 has already been probed above (it
        // is always in `candidates`, first run included) and did not
        // prove itself as ours, so a listener the scan finds there is
        // either a stranger's daemon or an nzbfast whose identity we
        // could not confirm - either way, not ours to attach to or
        // displace, so we skip past it rather than touch it.
        var chosen = saved ?? 0
        if chosen == 0 {
            for p in 6789..<6889 where !portTaken(p) {
                chosen = p
                break
            }
        }
        guard chosen > 0 else { return .failed("no free port between 6789 and 6889") }
        persistPort(chosen)
        do {
            try spawn()
        } catch {
            return .failed("couldn't launch the engine: \(error.localizedDescription)")
        }
        if await waitUntilUp(timeout: 15) {
            return .spawned
        }
        await reapFailedSpawn()
        return .failed("the engine didn't answer on port \(port) within 15 s")
    }

    /// A spawn whose child never answered inside the window must not
    /// report failure while still holding that child published. It did:
    /// Try Again re-entered start(), the probe attached to the same pid
    /// once it finally answered, the attach arm cleared spawnedByUs with
    /// `child` still naming the pid, and quit then skipped BOTH sweeps -
    /// bundleOrphanPIDs excludes child.pid and the owned-child kill is
    /// gated on spawnedByUs - so the daemon outlived the app (Codex
    /// sweep 24 Aug, F-14). The Windows tray has killed and waited on
    /// its child after the same 15 s timeout since it shipped; this is
    /// that rule. `deliberateStop` first, so the termination handler
    /// does not raise the crash alert about an exit we chose; SIGKILL
    /// after a bounded grace, the same journal-backed bargain stop()
    /// strikes for a child that ignores mode=shutdown.
    private func reapFailedSpawn() async {
        guard spawnedByUs, let c = child else { return }
        deliberateStop = true
        if c.isRunning { c.terminate() }
        for _ in 0..<20 {
            if !c.isRunning { break }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        if c.isRunning { kill(c.processIdentifier, SIGKILL) }
        child = nil
        spawnedByUs = false
        clearIdentityProof("the spawn that never answered was reaped")
    }

    /// Orders spawn's publish against stop's `stopping = true`. The two
    /// run on different cooperative-pool threads (startStack's Task vs
    /// the quit path's Task.detached), and a bare check-then-act let a
    /// quit land inside spawn's filesystem window: stop() saw no child,
    /// the app exited, and the process p.run() had just forked kept
    /// serving headless until the next launch adopted it.
    private let stateLock = NSLock()

    private func spawn() throws {
        stateLock.lock()
        let stopRequested = stopping
        stateLock.unlock()
        guard !stopRequested else {
            throw NSError(
                domain: "nzbfast", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "quit already in progress"])
        }
        let fm = FileManager.default
        for dir in [dataDir, downloadsDir] {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        rotateLog()
        if !fm.fileExists(atPath: logURL.path) {
            fm.createFile(atPath: logURL.path, contents: nil)
        }
        let log = try FileHandle(forWritingTo: logURL)
        log.seekToEndOfFile()

        let p = Process()
        p.executableURL = engineURL
        p.arguments = [
            "serve",
            "--port", String(port),
            "--config", dataDir.appendingPathComponent("config.local.json").path,
            "--out", downloadsDir.path,
            "--watch", watchDir.path,
            "--index-db", dataDir.appendingPathComponent("index.db").path,
        ]
        var env = ProcessInfo.processInfo.environment
        env["NZBFAST_BUNDLED"] = "1"   // S3: no self-swap inside the bundle
        p.environment = env
        p.currentDirectoryURL = dataDir
        p.standardOutput = log
        p.standardError = log
        // GENERATION-SAFE, and the `proc` this closure is handed is what
        // makes it so. The block used to ignore its argument and mutate
        // the globals outright: `child = nil` and a read of the CURRENT
        // `deliberateStop`. A child that timed out and was SIGKILLed is
        // abandoned by `reapFailedSpawn` without waiting for its
        // termination to be observed, so its block can run arbitrarily
        // later - and by then "Try Again" may have published a
        // replacement. The stale block then cleared ownership of the
        // LIVE child (which orphans it from `stop()`, whose guard is
        // `spawnedByUs, let c = child, c.isRunning`) and raised a
        // "stopped unexpectedly" alert over a perfectly healthy engine.
        //
        // Ordinarily the block drains inside the modal - `runModal`
        // services the main queue - and nothing goes wrong; the window
        // needs a child whose exit notification outlives the click,
        // which is a process wedged in an uninterruptible wait. This
        // fleet has documented exactly that class more than once.
        //
        // `deliberateStop` is then safe to read as it stands: past the
        // identity guard this IS the current child, and the flag was set
        // false at its own spawn and true by the `stop()` that is ending
        // it. `reapFailedSpawn` clears `child` before any replacement is
        // published, so a corpse's block can never match.
        p.terminationHandler = { [weak self] proc in
            try? log.close()
            guard let self else { return }
            DispatchQueue.main.async {
                guard self.child === proc else {
                    // A later generation already owns the field. This is
                    // a corpse's callback: say nothing, touch nothing.
                    return
                }
                self.child = nil
                // The child this flag vouched for is gone, and
                // `keyBearingAllowed` reads it: left true, a keyed URL
                // built between this callback and the user's Restart
                // would carry the master key toward a port nothing of
                // ours holds any more. `engineIsOurs` in AppDelegate
                // exists precisely because this clear happens here.
                self.spawnedByUs = false
                // The engine that proved itself is gone. A fresh listener
                // on the same port is a different generation and has to
                // prove itself again before this wrapper hands it the API
                // key - see `clearIdentityProof`.
                self.clearIdentityProof("the child that held it exited")
                if !self.deliberateStop {
                    self.onUnexpectedExit?(self.logTail())
                }
            }
        }
        deliberateStop = false
        try p.run()
        stateLock.lock()
        if stopping {
            // The quit arrived between the entry guard and run(). stop()
            // found no child to sweep, so this one is ours to kill right
            // here - published, it would outlive the app as a headless
            // engine until the next launch adopted it.
            stateLock.unlock()
            p.terminate()
            throw NSError(
                domain: "nzbfast", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "quit already in progress"])
        }
        child = p
        spawnedByUs = true
        stateLock.unlock()
    }

    /// Poll mode=version every 250 ms until the daemon answers.
    func waitUntilUp(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await isNzbfast(port: port, timeout: 0.25) { return true }
            // A child that died during startup will never answer.
            if spawnedByUs, let c = child, !c.isRunning { return false }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    /// Shared rule 6: graceful stop of OUR child - mode=shutdown persists
    /// the queue and exits; ≤5 s later we hard-kill whatever is left.
    /// In-flight downloads survive via the journal.
    ///
    /// Then the orphan sweep, which is what makes the app replaceable:
    /// see `stopBundleOrphans()`.
    func stop() async {
        // Under the lock so it orders against spawn's publish: after
        // this, spawn either saw the flag and threw, or published its
        // child where the guard below will find it.
        stateLock.lock()
        stopping = true
        stateLock.unlock()
        Self.log.notice(
            "stop: begin (spawnedByUs \(self.spawnedByUs), child pid \(self.child?.processIdentifier ?? -1), port \(self.port))")
        // Test hook for the quit watchdog (see QuitWatchdog): wedge here
        // forever so a rehearsal can prove the app still exits on time.
        // Never set outside that rehearsal.
        if ProcessInfo.processInfo.environment["NZBFAST_TEST_WEDGE_STOP"] != nil {
            Self.log.error("stop: NZBFAST_TEST_WEDGE_STOP set - wedging deliberately")
            while true { try? await Task.sleep(nanoseconds: 3_600_000_000_000) }
        }
        defer { Self.log.notice("stop: done") }
        if !spawnedByUs {
            // Attached, not spawned. If what we attached to is one of our
            // own bundle engines, it is ours to stop - and mode=shutdown
            // is the graceful route (it persists the queue), same as for
            // a child. Only then does the signal sweep below run, and by
            // then it usually has nothing left to do.
            deliberateStop = true
            var req = URLRequest(url: apiURL("shutdown"))
            req.httpMethod = "POST"
            req.timeoutInterval = 2
            if bundleOrphanPIDs().isEmpty == false {
                _ = try? await Daemon.loopback.data(for: req)
                for _ in 0..<50 {
                    if bundleOrphanPIDs().isEmpty { break }
                    try? await Task.sleep(nanoseconds: 100_000_000)
                }
            }
        }
        defer { stopBundleOrphans() }
        guard spawnedByUs, let c = child, c.isRunning else { return }
        deliberateStop = true
        var req = URLRequest(url: apiURL("shutdown"))
        req.httpMethod = "POST"
        req.timeoutInterval = 2
        _ = try? await Daemon.loopback.data(for: req)
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if !c.isRunning {
                Self.log.notice("stop: child exited after mode=shutdown")
                return
            }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        Self.log.error("stop: child ignored mode=shutdown for 5 s - SIGKILL")
        kill(c.processIdentifier, SIGKILL)
    }

    /// Stop any engine still running OUT OF THIS BUNDLE that is not our
    /// own child.
    ///
    /// "Never touch an attached daemon" protects a daemon the USER runs -
    /// from a terminal, from launchd, from their own copy of the binary.
    /// It was keyed on who started the process, which is the wrong test:
    /// an engine running out of `NzbFast.app/Contents/Resources/bin` is
    /// ours whoever started it. Leaving one alive wedges the app, because
    /// a crash or a force-quit orphans the engine, every later launch
    /// ATTACHES to that orphan instead of spawning, and every later quit
    /// then declined to stop it - so the bundle stays busy forever, with
    /// no visible app to quit, and dragging a new NzbFast.app over it
    /// fails with "the item is in use".
    ///
    /// Keyed on the executable path, so a user's own daemon (a different
    /// path) is still never touched - which is the rule this preserves.
    /// The backstop, after the graceful `mode=shutdown` above has had its
    /// turn. The engine installs no SIGTERM handler, so this is an abrupt
    /// exit and the journal is what makes it safe - the same bargain the
    /// existing 5-second SIGKILL fallback already strikes for a child.
    private func stopBundleOrphans() {
        for pid in bundleOrphanPIDs() {
            // IDENTITY IS RE-CHECKED BEFORE EVERY SIGNAL, because the
            // roster is one snapshot and this loop takes up to two
            // seconds PER ORPHAN. With two of them, orphan N's SIGTERM
            // fires up to 2*(N-1) seconds after its path was validated -
            // and if it exited on its own in the meantime, the signal
            // goes to whatever now holds that pid. The single-orphan
            // race the report worried about is not reachable (the poll
            // itself keeps the pid occupied, and macOS allocates pids
            // monotonically with a ~92 s wrap even on a build farm at
            // load 10), but the multi-orphan window is seconds wide and
            // costs one `proc_pidpath` to close.
            guard isBundleEngine(pid) else { continue }
            kill(pid, SIGTERM)
            for _ in 0..<20 {
                if kill(pid, 0) != 0 { break }
                usleep(100_000)
            }
            if kill(pid, 0) == 0, isBundleEngine(pid) { kill(pid, SIGKILL) }
        }
    }

    /// Is `pid` running THIS bundle's engine, right now? The one-pid
    /// form of [`bundleOrphanPIDs`]'s path compare, so a signal can be
    /// held to the identity a snapshot established seconds earlier.
    private func isBundleEngine(_ pid: pid_t) -> Bool {
        let canon = { (p: String) in
            URL(fileURLWithPath: p).resolvingSymlinksInPath().path
        }
        guard pid != getpid() else { return false }
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &buf, UInt32(MAXPATHLEN)) > 0 else { return false }
        return canon(String(cString: buf)) == canon(engineURL.path)
    }

    /// Engines running out of THIS bundle that are not our own child.
    ///
    /// BOTH sides of the path compare go through the same
    /// resolvingSymlinksInPath, because the two sources disagree on
    /// symlinked prefixes: proc_pidpath reports the kernel's resolved
    /// path (/private/tmp/...), while Foundation's resolver maps the
    /// /private aliases back OFF (/tmp/...). Canonicalising only our own
    /// side made every orphan invisible to the sweep - and to the
    /// graceful shutdown POST gated on it - whenever the bundle sat
    /// behind such a prefix.
    private func bundleOrphanPIDs() -> [pid_t] {
        let canon = { (p: String) in
            URL(fileURLWithPath: p).resolvingSymlinksInPath().path
        }
        let mine = canon(engineURL.path)
        let ours = child?.processIdentifier ?? -1
        return liveProcessIDs().filter { pid in
            guard pid != ours, pid != getpid() else { return false }
            var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard proc_pidpath(pid, &buf, UInt32(MAXPATHLEN)) > 0 else { return false }
            return canon(String(cString: buf)) == mine
        }
    }

    /// Every live pid, for the orphan sweep. Sized twice: the count can
    /// grow between the sizing call and the fetch.
    private func liveProcessIDs() -> [pid_t] {
        let cap = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard cap > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(cap) / MemoryLayout<pid_t>.size + 64)
        let got = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids,
                                Int32(pids.count * MemoryLayout<pid_t>.size))
        guard got > 0 else { return [] }
        return Array(pids.prefix(Int(got) / MemoryLayout<pid_t>.size)).filter { $0 > 0 }
    }

    /// Restart after an unexpected child death (alert button).
    func restart() async -> StartResult {
        child = nil
        spawnedByUs = false
        clearIdentityProof("restarting after the engine died")
        return await start()
    }

    // MARK: log handling

    /// Keep daemon.log under ~5 MB; one rotated generation.
    private func rotateLog() {
        let fm = FileManager.default
        let attrs = try? fm.attributesOfItem(atPath: logURL.path)
        let size = (attrs?[.size] as? NSNumber)?.intValue ?? 0
        if size > 5_000_000 {
            let old = dataDir.appendingPathComponent("daemon.log.1")
            try? fm.removeItem(at: old)
            try? fm.moveItem(at: logURL, to: old)
        }
    }

    func logTail(lines: Int = 20) -> String {
        guard let text = try? String(contentsOf: logURL, encoding: .utf8) else {
            return "(no daemon.log)"
        }
        return text.split(separator: "\n").suffix(lines).joined(separator: "\n")
    }

    // MARK: API helpers

    /// Daemon's own release version (for About).
    func daemonVersion() async -> String? {
        var req = URLRequest(url: apiURL("version"))
        req.timeoutInterval = 2
        guard let (data, _) = try? await Daemon.loopback.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return obj["nzbfast"] as? String
    }

    /// Multipart POST of an .nzb to mode=addfile. Returns nil on success,
    /// or an error message.
    func addNzb(_ file: URL) async -> String? {
        // REFUSE BEFORE READING. A file association points this at
        // whatever the user double-clicked, and the multipart body is a
        // second copy of the bytes - so a very large or sparse file
        // named `.nzb` took the wrapper to twice its size and could be
        // terminated for it, before the daemon's own 256 MiB cap on an
        // addfile body had any chance to refuse the upload. The
        // metadata read is the whole guard; the caller already renders
        // this String in an alert.
        let limit = 256 << 20
        if let size = try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize,
           size > limit {
            return "\(file.lastPathComponent) is \(size / (1 << 20)) MB - too large for an NZB "
                + "(the limit is \(limit / (1 << 20)) MB)"
        }
        guard let bytes = try? Data(contentsOf: file) else {
            return "couldn't read \(file.lastPathComponent)"
        }
        let boundary = "nzbfast-\(UUID().uuidString)"
        var req = URLRequest(url: apiURL("addfile"))
        req.httpMethod = "POST"
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"name\"; filename=\"\(file.lastPathComponent)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/x-nzb\r\n\r\n".data(using: .utf8)!)
        body.append(bytes)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)
        req.httpBody = body
        guard let (data, _) = try? await Daemon.loopback.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return "the daemon didn't answer" }
        if (obj["status"] as? Bool) == true { return nil }
        return (obj["error"] as? String) ?? "rejected"
    }

    /// Hand a clicked `nzblnk:` link to mode=addnzblnk. Returns nil on
    /// success, or a message to show.
    ///
    /// The link goes over VERBATIM, percent-encoded as one query value:
    /// `nzbkit::nzblnk` in the daemon is the only parser, and it is the
    /// one that is fuzzed. Nothing here inspects the link.
    ///
    /// Resolving a header can mean a round of searches against the
    /// user's indexers, so this waits longer than the status probes do.
    func addNzblnk(_ link: String) async -> String? {
        var req = URLRequest(url: apiURL("addnzblnk", "output=json&link=\(queryEscaped(link))"))
        req.timeoutInterval = 30
        guard let (data, _) = try? await Daemon.loopback.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return "the daemon didn't answer" }
        if (obj["status"] as? Bool) == true { return nil }
        return (obj["error"] as? String) ?? "rejected"
    }
    // MARK: menu bar status

    /// One queue poll, reduced to what the menu bar item and the Dock
    /// badge draw.
    struct QueueStatus {
        let paused: Bool
        /// Deliberately separate from `paused`, as the daemon keeps it:
        /// offline means every provider connection is hung up so another
        /// machine can have the account, and the two look identical from
        /// the queue's point of view while meaning different things.
        let offline: Bool
        /// MB/s, decimal. `kbpersec` / 1000, exactly as
        /// web/dashboard.html derives its own base speed number.
        let mbps: Double
        /// SAB's `noofslots`: the whole queue. Counted BEFORE the
        /// caller's window in sabcompat/walk.rs, so it stays honest
        /// however few rows we ask for below.
        let slots: Int
        /// SAB's own word for the queue: Paused, Idle or Downloading.
        let status: String
        /// The speed ceiling in force, bytes/sec, 0 for none. While
        /// `autoSpeed` is on this is the number the governor picked for
        /// this instant rather than a ceiling anyone set.
        let limitBps: Int
        /// Is the auto governor holding the wheel?
        let autoSpeed: Bool
        /// The configured line speed, bytes/sec, 0 when unset. The
        /// percentage rows of the limit menu appear only once it is
        /// known - see StatusItemController.limitRows.
        let lineSpeed: Int
    }

    /// Poll mode=queue for the handful of numbers the status item shows.
    ///
    /// `start=0&limit=1` because we want the header, not the rows. The
    /// walk has to visit every job either way (the byte totals beside
    /// `noofslots` are summed on that one pass, which is what keeps them
    /// describing the same instant), but without a window it would also
    /// serialise a JSON row per job every few seconds for a menu nobody
    /// may have open. nil means the daemon did not answer.
    func queueStatus() async -> QueueStatus? {
        var req = URLRequest(url: apiURL("queue", "start=0&limit=1"))
        req.timeoutInterval = 2
        guard let (data, _) = try? await Daemon.loopback.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let q = obj["queue"] as? [String: Any]
        else { return nil }
        // A STRING on the wire - SAB's own type for this field - so it
        // is parsed rather than cast.
        let kb = (q["kbpersec"] as? String).flatMap(Double.init) ?? 0
        // Also a string on the wire, and for the same reason - but
        // mode=status once sent this one as a number, so both are read.
        let limit = (q["speedlimit_abs"] as? String)
            .flatMap { Int($0.trimmingCharacters(in: .whitespaces)) }
            ?? (q["speedlimit_abs"] as? Int) ?? 0
        return QueueStatus(
            paused: (q["paused"] as? Bool) ?? false,
            offline: (q["offline"] as? Bool) ?? false,
            mbps: kb / 1000,
            slots: (q["noofslots"] as? Int) ?? 0,
            status: (q["status"] as? String) ?? "",
            limitBps: limit,
            autoSpeed: (q["auto_speed"] as? Bool) ?? false,
            lineSpeed: (q["line_speed"] as? Int) ?? 0)
    }

    /// Apply one speed-limit pick from the menu bar.
    ///
    /// The calls are made in the order `StatusItemController.limitCalls`
    /// returns them and the run STOPS on the first refusal: the two-call
    /// picks clear the governor before setting a ceiling, and setting one
    /// after failing to clear it would leave the governor free to
    /// overwrite it a second later - a limit that visibly refuses to
    /// stick. Returns true when every call was accepted.
    ///
    /// Values are digits and names are literals, so nothing here is
    /// escaped; `apiURL` escapes the key.
    @discardableResult
    func setSpeedLimit(_ calls: [(String, String)]) async -> Bool {
        for (name, value) in calls {
            var req = URLRequest(url: apiURL("config", "name=\(name)&value=\(value)"))
            req.timeoutInterval = 5
            guard let (data, _) = try? await Daemon.loopback.data(for: req),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (obj["status"] as? Bool) != false
            else { return false }
        }
        return true
    }

    /// mode=pause / mode=resume: the same two calls the dashboard's own
    /// header button makes.
    ///
    /// Pause is the GRACEFUL one, which is the default and is what we
    /// want here: in-flight articles finish and nothing re-downloads on
    /// resume. The abrupt form is `pause&value2=now`, which frees the
    /// line immediately at the cost of re-fetching whatever was in
    /// flight - a real choice, but not one to make on someone's behalf
    /// from a menu bar toggle with no way to say which it did.
    ///
    /// Returns true when the daemon accepted.
    @discardableResult
    func setPaused(_ want: Bool) async -> Bool {
        var req = URLRequest(url: apiURL(want ? "pause" : "resume"))
        req.timeoutInterval = 5
        guard let (data, _) = try? await Daemon.loopback.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        return (obj["status"] as? Bool) == true
    }

    /// `unit_bits`, the daemon setting that swaps MB/s for Mb/s
    /// everywhere a rate is printed.
    ///
    /// Read out of settings.json rather than fetched, for the same
    /// reason `apiKey` above is: that file is where the engine itself
    /// loads this flag from at startup (serve/startup.rs), so it is the
    /// same answer, and mode=get_config is a large body to pull every
    /// few seconds for one bool. Absent or unparseable means false,
    /// which is both the shipped default and what the engine does with
    /// the same file.
    var unitBits: Bool {
        let settings = dataDir.appendingPathComponent("settings.json")
        guard let data = try? Data(contentsOf: settings),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        return (obj["unit_bits"] as? Bool) ?? false
    }
}
