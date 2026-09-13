import SwiftUI
import ParfastCore

/// The screenshot harness, driven over the app's own URL scheme.
///
/// Phase 0's deliverable is a picture of every screen and state, in light and
/// dark (plan 5, chip B). Driving that by clicking is slow and, worse, not
/// reproducible: a screenshot set retaken next week has to land on the same
/// states or it is not a comparison. So the mock build understands one extra
/// URL, and `Tools/shoot.sh` walks it.
///
/// It is gated on the core ACTUALLY being a `MockCore`, so a build against
/// the real engine has no such route at all - there is nothing here to reach
/// once `FfiCore` is linked, by construction rather than by discipline.
///
///     parfast://demo?screen=verify&scenario=damaged&repair=1&speed=20
///                   &sheet=1&log=1&appearance=dark&size=1280x860
@MainActor
enum DemoRoute {

    /// The window-appearance and size half of this route is available in a
    /// REAL build too, gated on `PARFAST_SCREENSHOT=1` in the environment.
    /// Chip D's QA lane has to take a light and a dark shot of the app driving
    /// the real engine, and the alternative is flipping the whole Mac's
    /// appearance between takes on somebody's desktop. It can reach nothing
    /// else: no scenario, no mock, no state.
    static var screenshotModeAllowed: Bool {
        ProcessInfo.processInfo.environment["PARFAST_SCREENSHOT"] == "1"
    }

    static func handle(_ url: URL, app: AppModel) -> Bool {
        guard url.host == "demo" else { return false }
        // NOTHING A SHOOT DOES TO THE WINDOW IS PERSISTED. `resize` below sets
        // an explicit size so a round of pictures stays comparable with the
        // round before it, and with frame persistence live (12 Sep 2026) that
        // size would otherwise be written straight into the user's remembered
        // window. Suspended for the whole process on the first demo URL, not
        // just around the resize, because `center()` moves it too and the next
        // thing a shoot learns to drive would inherit the same trap.
        MainWindowFrame.suspend()
        guard app.core is MockCore else {
            return handleScreenshotOnly(url)
        }
        let q = Dictionary(
            uniqueKeysWithValues: (URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems ?? []).map { ($0.name, $0.value ?? "") })

        // Each shot starts from a clean app. Without this the set is one long
        // stateful session and a sheet left up by shot 15 lands in shot 16 -
        // which is exactly what happened the first time this ran.
        if q["keep"] != "1" { reset(app) }

        if let size = q["size"] { resize(size) }
        if let appearance = q["appearance"] { setAppearance(appearance) }
        if let speed = q["speed"].flatMap(Double.init) {
            app.demoSpeed = speed
            (app.core as? MockCore)?.speed = speed
        }

        switch q["screen"] {
        case "create": setUpCreate(app, q)
        case "checksums": setUpChecksums(app, q)
        case "queue": setUpQueue(app, q)
        case "settings": NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        case "empty": app.mode = AppModel.Mode(rawValue: q["mode"] ?? "verify") ?? .verify
        default: setUpVerify(app, q)
        }

        app.logOpen = q["log"] == "1"
        return true
    }

    /// Back to a freshly launched app: no sheet, no alert, no open set, no
    /// sources, an empty queue.
    private static func reset(_ app: AppModel) {
        app.progressJob = nil
        app.alert = nil
        app.toast = nil
        app.logOpen = false
        app.verify.par2Path = nil
        app.verify.setTarget("")
        app.verify.par2Path = nil
        app.verify.extraDirs = []
        app.create.sources = []
        app.create.selection = []
        app.create.preview = nil
        app.create.jobId = nil
        app.create.snapshot = nil
        app.create.outputEdited = false
        app.create.baseEdited = false
        app.create.output = ""
        app.create.comment = ""
        app.create.applyDefaults(app.settings)
        app.checksums.sources = []
        app.checksums.file = ""
        app.checksums.jobId = nil
        app.checksums.snapshot = nil
        app.checksums.outputEdited = false
        app.checksums.subMode = .create
        for job in app.queue.jobs {
            if !job.state.isFinished { app.cancel(job.id) }
            app.remove(job.id)
        }
        app.refresh()
    }

    /// A real build understands exactly two keys, and only under the flag.
    private static func handleScreenshotOnly(_ url: URL) -> Bool {
        guard screenshotModeAllowed else { return false }
        let q = Dictionary(
            uniqueKeysWithValues: (URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems ?? []).map { ($0.name, $0.value ?? "") })
        if let size = q["size"] { resize(size) }
        if let appearance = q["appearance"] { setAppearance(appearance) }
        return true
    }

    private static func setUpVerify(_ app: AppModel, _ q: [String: String]) {
        app.mode = .verify
        guard let id = q["scenario"], let scenario = MockScenario.named(id) else { return }
        app.verify.setTarget(scenario.par2Path)
        if q["repair"] == "1" {
            app.startRepair()
        } else {
            app.startVerify()
        }
        if q["sheet"] == "1" { app.progressJob = app.verify.jobId }
    }

    private static func setUpCreate(_ app: AppModel, _ q: [String: String]) {
        app.mode = .create
        if app.create.sources.isEmpty {
            let spec = MockScenario.longCreateSpec()
            app.create.addSources(spec.sources.map(\.path))
            app.create.output = spec.output
            app.create.outputEdited = true
            app.create.comment = spec.comment
        }
        if let family = q["scheme"] {
            app.create.schemeFamily = VolumeScheme.Family(rawValue: family) ?? .pow2
        }
        app.create.recompute(with: app.core)
        if q["run"] == "1" {
            app.startCreate()
            if q["sheet"] != "1" { app.progressJob = nil }
        }
    }

    private static func setUpChecksums(_ app: AppModel, _ q: [String: String]) {
        app.mode = .checksums
        if q["sub"] == "create" {
            app.checksums.subMode = .create
            if app.checksums.sources.isEmpty {
                app.checksums.addSources(MockScenario.longCreateSpec().sources.map(\.path))
            }
        } else {
            app.openChecksumFile("\(MockScenario.mockRoot)/checksums/archive-set.sfv")
        }
    }

    private static func setUpQueue(_ app: AppModel, _ q: [String: String]) {
        app.mode = .queue
        guard app.queue.jobs.isEmpty else { return }
        for scenario in [MockScenario.tenThousandBlocks, .damagedRepairable, .unicodeNames] {
            _ = app.submit(.verify(VerifySpec(par2: scenario.par2Path)), showSheet: false)
        }
        if q["create"] == "1" {
            _ = app.submit(.create(MockScenario.longCreateSpec()), showSheet: false)
        }
        app.refresh()
    }

    /// A screenshot set has to be light AND dark, and switching the whole Mac
    /// between takes is not something a build script should do to somebody's
    /// desktop. Overriding the app's own appearance is the polite version.
    private static func setAppearance(_ name: String) {
        switch name {
        case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
        case "light": NSApp.appearance = NSAppearance(named: .aqua)
        default: NSApp.appearance = nil
        }
    }

    private static func resize(_ spec: String) {
        let parts = spec.split(separator: "x").compactMap { Double($0) }
        guard parts.count == 2, let window = NSApp.windows.first(where: { $0.isVisible }) else { return }
        window.setContentSize(NSSize(width: parts[0], height: parts[1]))
        window.center()
    }
}
