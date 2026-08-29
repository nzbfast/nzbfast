// Throwaway Simulator harness for the A3 spike: link the nzbfast engine
// staticlib, start it in-process, and show the dashboard it serves on
// 127.0.0.1 in a WKWebView. Start/Stop buttons exercise the FFI cycle.
// NOT a product app - the C1 SwiftUI shell is that; this exists to
// prove the engine runs inside an iOS process (no exec on iOS).
//
// The Simulator shares the host Mac's loopback, so the port must dodge
// real daemons on the machine (:6789 is live) - build-harness.sh bakes
// NZBFAST_HARNESS_PORT in via -D; default set there, not here.

import SwiftUI
import WebKit

// The staticlib's C ABI (crates/nzbfast-ffi/include/nzbfast.h), bound
// directly - three functions do not earn a bridging header.
@_silgen_name("nzbfast_start")
func nzbfast_start(
    _ configDir: UnsafePointer<CChar>, _ outDir: UnsafePointer<CChar>?,
    _ port: UInt16, _ apikey: UnsafePointer<CChar>?,
    _ memLimitBytes: UInt64
) -> Int32
@_silgen_name("nzbfast_stop")
func nzbfast_stop() -> Int32
@_silgen_name("nzbfast_is_up")
func nzbfast_is_up() -> Int32

let harnessPort: UInt16 = 8724
// Explicit key: a NULL apikey makes the engine's first run MINT one
// (secure-by-default), and the dashboard then wants it typed in. The
// product app must do the same (or read the minted key back).
let harnessKey = "spike-harness"

@main
struct HarnessApp: App {
    var body: some Scene {
        WindowGroup { HarnessView() }
    }
}

struct HarnessView: View {
    @State private var status = "engine: not started"
    @State private var webKey = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button("Start") { start() }
                Button("Stop") { status = "stop -> \(nzbfast_stop())" }
                Button("Reload") { webKey += 1 }
                Text(status).font(.footnote).lineLimit(2)
            }
            .padding(8)
            DashboardView(port: harnessPort).id(webKey)
        }
        .onAppear { start() }
    }

    func start() {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        )[0].appendingPathComponent("nzbfast", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // Seed a definite config: with no file, the engine's
        // Config::load goes searching $HOME for a SABnzbd sabnzbd.ini,
        // so an unseeded start is configured by whatever that search
        // returns rather than by this harness (the class
        // tools/host-config-gate.py refuses in the test tree). Same
        // name and shape as Engine.swift's seed - the name mirrors
        // nzbfast_ffi::CONFIG_FILE, and the seed stays OUT of
        // nzbfast_start itself because the Docker sabnzbd.ini import
        // path depends on the missing-file fallthrough. Since 28 Aug
        // 2026 the engine REFUSES an unseeded directory (-3) rather
        // than reaching $HOME, so forgetting this is loud rather than
        // silent - but the seed is still ours to write.
        let config = dir.appendingPathComponent("config.local.json")
        if !FileManager.default.fileExists(atPath: config.path) {
            try? Data(#"{"servers":[]}"#.utf8).write(to: config, options: .atomic)
        }
        let rc = dir.path.withCString { d in
            // NULL out_dir: the harness has no Files-app story to keep
            // separate, so it takes the derived <config_dir>/downloads.
            // The product shell passes Documents (TODO 281 IO1).
            // 0 for the memory budget: this is a throwaway that proves
            // the engine LINKS and RUNS, and it is only ever run in the
            // Simulator, where there is no jetsam limit to size against.
            // The product shell passes a phone-sized figure (TODO 281
            // IO2, `DeviceProfile.memLimitBytes`).
            harnessKey.withCString { k in nzbfast_start(d, nil, harnessPort, k, 0) }
        }
        status = "start -> \(rc), up=\(nzbfast_is_up()), port \(harnessPort)"
        // Give the listener a beat, then load the dashboard.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { webKey += 1 }
    }
}

struct DashboardView: UIViewRepresentable {
    let port: UInt16
    func makeUIView(context: Context) -> WKWebView {
        let v = WKWebView()
        v.load(URLRequest(url: URL(string: "http://127.0.0.1:\(port)/?apikey=\(harnessKey)")!))
        return v
    }
    func updateUIView(_ v: WKWebView, context: Context) {}
}
