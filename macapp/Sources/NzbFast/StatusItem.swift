import AppKit

/// The menu bar item: a template bolt, an optional speed readout beside
/// it, a short menu of the things worth doing without opening a window,
/// and the Dock badge, which is fed by the same poll.
///
/// Every action it offers is one the app already had: the closures are
/// handed in by AppDelegate rather than reimplemented here, so "Open in
/// Browser" from the menu bar is the same guarded call as "Open in
/// Browser" from the View menu, API key and all.
@MainActor
final class StatusItemController: NSObject, NSMenuDelegate {
    /// Show the menu bar item at all. On by default: it is the point of
    /// the feature, and the app already keeps running with its window
    /// closed, which is the state nothing used to make visible.
    static let showKey = "ShowInMenuBar"
    /// Put the current speed beside the icon. OFF by default. Menu bar
    /// space is contested and every item that claims some of it forever
    /// has to earn it; the icon alone says "nzbfast is running", the
    /// menu says the rest, and someone who wants the number in front of
    /// them the whole time can say so once.
    static let speedKey = "MenuBarShowSpeed"

    /// Both defaults, registered before anything reads them - an
    /// unregistered `bool(forKey:)` is false, which would ship the menu
    /// bar item off.
    static func registerDefaults() {
        UserDefaults.standard.register(defaults: [showKey: true, speedKey: false])
    }

    private let daemon = Daemon.shared
    private var item: NSStatusItem?
    private var timer: Timer?
    /// The last poll that answered, or nil when the last one did not.
    /// Never a stale copy kept for looks: a menu bar reading numbers off
    /// a daemon that has stopped answering is worse than one that says
    /// so.
    private var last: Daemon.QueueStatus?
    private var polling = false
    /// Has the daemon ever answered? Only after that does a failed poll
    /// mean something is wrong rather than "not up yet".
    private var everAnswered = false
    /// AppDelegate's `stackReady`: the port is confirmed to be an
    /// nzbfast and may be handed the key.
    private var stackReady = false
    /// The dashboard's own end-of-job spike guard, carried across polls.
    private var lastGoodMbps: Double = 0

    /// The actions AppDelegate already owns.
    var onOpenWindow: () -> Void = {}
    var onOpenBrowser: () -> Void = {}
    var onOpenDownloads: () -> Void = {}

    private let stateItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let openItem = NSMenuItem(title: "Open nzbfast", action: nil, keyEquivalent: "")
    private let browserItem = NSMenuItem(title: "Open in Browser", action: nil, keyEquivalent: "")
    private let pauseItem = NSMenuItem(title: "Pause", action: nil, keyEquivalent: "")
    private let downloadsItem = NSMenuItem(
        title: "Open Downloads Folder", action: nil, keyEquivalent: "")

    // MARK: lifecycle

    /// Called by AppDelegate when the daemon handshake succeeds, and
    /// again with false if the engine dies under us.
    func setStackReady(_ ready: Bool) {
        stackReady = ready
        if !ready {
            last = nil
            everAnswered = false
        }
        syncPolling()
        refresh()
    }

    /// Quit is in flight: stop polling before the engine stop begins, so
    /// no request races it and no timer keeps a dying app alive.
    func suspend() {
        stackReady = false
        timer?.invalidate()
        timer = nil
        NSApp.dockTile.badgeLabel = nil
    }

    /// Apply the two preferences. Idempotent, so the menu items can just
    /// flip a default and call it.
    func applyPreferences() {
        if UserDefaults.standard.bool(forKey: Self.showKey) {
            if item == nil { install() }
        } else if let shown = item {
            NSStatusBar.system.removeStatusItem(shown)
            item = nil
        }
        syncPolling()
        refresh()
    }

    private func install() {
        let new = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = new.button {
            button.image = MenuBarIcon.image
            button.imagePosition = .imageOnly
            // Monospaced digits: without them the speed readout changes
            // width on every sample and drags the whole right-hand end
            // of the menu bar with it.
            button.font = .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
            button.toolTip = "nzbfast"
        }
        new.menu = menu
        item = new
    }

    // MARK: menu

    /// Built once and handed to every status item this controller
    /// installs. An NSMenuItem belongs to one menu at a time and the
    /// items below are held for the life of the app so their labels can
    /// be relabelled off a poll, so rebuilding the menu each time the
    /// preference is switched back on would be handing already-owned
    /// items to a second owner.
    private lazy var menu: NSMenu = buildMenu()

    private func buildMenu() -> NSMenu {
        let menu = NSMenu()
        // Every item's enablement is decided in refresh() against the
        // last poll, so AppKit's own validation would only be a second
        // opinion arriving at a different moment.
        menu.autoenablesItems = false
        menu.delegate = self

        stateItem.isEnabled = false
        menu.addItem(stateItem)
        menu.addItem(.separator())

        openItem.action = #selector(openWindow)
        openItem.target = self
        menu.addItem(openItem)

        browserItem.action = #selector(openBrowser)
        browserItem.target = self
        menu.addItem(browserItem)

        menu.addItem(.separator())

        pauseItem.action = #selector(togglePause)
        pauseItem.target = self
        menu.addItem(pauseItem)

        menu.addItem(.separator())

        downloadsItem.action = #selector(openDownloadsFolder)
        downloadsItem.target = self
        menu.addItem(downloadsItem)

        menu.addItem(.separator())
        let quit = NSMenuItem(
            title: "Quit nzbfast", action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "")
        quit.target = NSApp
        quit.isEnabled = true
        menu.addItem(quit)
        return menu
    }

    /// Opening the menu draws whatever the last poll said and asks for a
    /// fresh one behind it - the answer lands within a few hundred
    /// milliseconds and NSMenu redraws an item whose title changes while
    /// it is open, so the reading catches up under the cursor rather
    /// than the menu blocking on a request.
    func menuNeedsUpdate(_ menu: NSMenu) {
        refresh()
        poll()
    }

    // MARK: actions

    @objc private func openWindow() { onOpenWindow() }
    @objc private func openBrowser() { onOpenBrowser() }
    @objc private func openDownloadsFolder() { onOpenDownloads() }

    @objc private func togglePause() {
        guard let want = last.map({ !$0.paused }) else { return }
        Task {
            await daemon.setPaused(want)
            // Confirm from the daemon rather than assuming: a pause can
            // be refused, and the label has to end up describing what
            // the queue actually did.
            poll()
        }
    }

    // MARK: polling

    /// The poll runs whenever the daemon is up, not only while the menu
    /// bar item is shown, because the Dock badge is the other consumer
    /// and it has no preference behind it. Turning the item off does
    /// slow it down - the badge is a job count, which changes when a
    /// job starts or finishes, while the speed readout is a number
    /// somebody is watching.
    private var pollInterval: TimeInterval { item == nil ? 5 : 3 }

    private func syncPolling() {
        timer?.invalidate()
        timer = nil
        guard stackReady else {
            NSApp.dockTile.badgeLabel = nil
            return
        }
        let t = Timer.scheduledTimer(withTimeInterval: pollInterval, repeats: true) {
            [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
        // Let the OS coalesce these with whatever else it is waking for.
        // Nothing here needs to land on the second.
        t.tolerance = 0.5
        timer = t
        poll()
    }

    private func poll() {
        guard stackReady, !polling else { return }
        polling = true
        Task {
            let s = await daemon.queueStatus()
            polling = false
            if let s {
                everAnswered = true
                // The dashboard's own guard, for the same reason it has
                // one: `kbpersec` is computed over the sample's elapsed
                // time, and at the end of a job that elapsed can be
                // near zero, which prints a rate no line can carry.
                // Past ~40 Gbps, keep the last believable reading.
                let mbps = s.mbps > 5000 ? lastGoodMbps : s.mbps
                lastGoodMbps = mbps
                last = Daemon.QueueStatus(
                    paused: s.paused, offline: s.offline, mbps: mbps,
                    slots: s.slots, status: s.status)
            } else {
                last = nil
            }
            refresh()
        }
    }

    // MARK: drawing

    private func refresh() {
        let live = stackReady && last != nil
        let showSpeed = UserDefaults.standard.bool(forKey: Self.speedKey)

        if let button = item?.button {
            // A dimmed icon is the one signal that works without opening
            // anything: the app is there, the engine is not answering.
            button.appearsDisabled = !live
            if showSpeed, let s = last, !s.paused, !s.offline, s.mbps >= Self.rateFloor {
                button.title = " \u{2193} " + Self.rateText(s.mbps, bits: daemon.unitBits)
                button.imagePosition = .imageLeading
            } else {
                button.title = ""
                button.imagePosition = .imageOnly
            }
        }

        stateItem.title = stateLine()
        openItem.isEnabled = true
        downloadsItem.isEnabled = true
        // Same gate as the View menu's own item, and for the same reason
        // (see AppDelegate.openInBrowser): the key may only go to a port
        // the handshake has confirmed.
        browserItem.isEnabled = stackReady
        pauseItem.isEnabled = live
        pauseItem.title = (last?.paused ?? false) ? "Resume" : "Pause"

        // Empty when idle, per the Dock's own convention - a badge
        // reading 0 is a badge saying nothing, loudly.
        if live, let s = last, s.slots > 0 {
            NSApp.dockTile.badgeLabel = String(s.slots)
        } else {
            NSApp.dockTile.badgeLabel = nil
        }
    }

    /// Below this the queue is not moving bytes in any sense a status
    /// line can report, so the line drops the field rather than print
    /// "0 MB/s", which reads as broken rather than as busy. The
    /// post-network tail - verifying, repairing, unpacking - sits here
    /// for minutes at a time on a job that is perfectly healthy, so
    /// this is the common case and not the edge.
    ///
    /// It is not a promise that the printed number is never 0: MB/s
    /// prints whole, so anything under half a megabyte a second still
    /// rounds down to it. That is what the dashboard shows for the same
    /// sample, and one rounding rule across the product is worth more
    /// than a second one invented in the wrappers. The floor is only
    /// about telling "stopped" from "slow".
    ///
    /// The Windows tray holds to the same floor (RATE_FLOOR_MBPS in
    /// crates/nzbtray/src/main.rs); see the wording note below.
    static let rateFloor = 0.05

    /// The one live line in the menu: what the engine is doing, how much
    /// of it, and how fast.
    ///
    /// ```text
    /// Downloading · 3 jobs · 42 MB/s
    /// Downloading · 2 jobs            (the tail: nothing measurable moving)
    /// Paused · 4 jobs
    /// Offline · 4 jobs
    /// Idle
    /// ```
    ///
    /// THE SAME LINE IS DRAWN BY THE WINDOWS TRAY, as its hover tooltip:
    /// tip_from_queue in crates/nzbtray/src/main.rs builds these same
    /// three fields in this same order with this same separator, and
    /// differs only in putting `nzbfast - ` in front - it labels a
    /// nameless icon in a tray of nameless icons, where this line hangs
    /// under a menu whose title already says the name. The two landed
    /// hours apart on 24 Aug 2026 from lanes that could not see each
    /// other (27cc66897 here, c6a2f8ecd there) and described the same
    /// five states in different words, different field order and
    /// different case; a user with both saw the product say two things.
    /// Change the wording in one and change it in the other, in the same
    /// commit.
    ///
    /// The three fields, and the rules that decide whether each appears:
    ///
    /// - The STATE WORD is the daemon's own (`QueueStatus.status` is one
    ///   of Downloading / Idle / Paused), so the menu cannot drift from
    ///   what the dashboard's rows say. `offline` OUTRANKS it: the two
    ///   are different states (see `QueueStatus.offline`) and offline is
    ///   the one that explains the silence, so it takes the word. The
    ///   derived fallback exists only for a body with no `status` at
    ///   all, which would otherwise open the line with the separator.
    /// - The COUNT is omitted at zero rather than printed as "0 jobs",
    ///   which is a phrase for saying nothing loudly - the same reason
    ///   the Dock badge goes empty rather than reading 0.
    /// - The RATE appears only while the queue is actually downloading
    ///   and something measurable is moving (see `rateFloor`).
    ///
    /// Two of the lines this returns are not queue states at all and
    /// keep their own words: the engine has not started yet, or it has
    /// stopped answering.
    private func stateLine() -> String {
        if !stackReady || (last == nil && !everAnswered) { return "Starting…" }
        guard let s = last else { return "Engine not answering" }
        var parts = [Self.stateWord(s)]
        if s.slots > 0 { parts.append(s.slots == 1 ? "1 job" : "\(s.slots) jobs") }
        if s.mbps >= Self.rateFloor, !s.paused, !s.offline {
            parts.append(Self.rateText(s.mbps, bits: daemon.unitBits))
        }
        return parts.joined(separator: " · ")
    }

    /// Offline, or the daemon's own word for the queue - see the field
    /// note on `stateLine`.
    static func stateWord(_ s: Daemon.QueueStatus) -> String {
        if s.offline { return "Offline" }
        if !s.status.isEmpty { return s.status }
        return s.paused ? "Paused" : (s.slots == 0 ? "Idle" : "Downloading")
    }

    /// The dashboard's `rateParts` / `fmtRate` pair (web/dashboard.html)
    /// in Swift: MB/s is the base unit, GB/s past 1000 with two
    /// decimals, and the daemon's `unit_bits` setting swaps the whole
    /// scale to bits - x8, Mb/s and Gb/s.
    ///
    /// Written out again rather than shared, because the wrapper has no
    /// way to call into the page. It is the THIRD copy, not the second:
    /// `fmt_rate` in crates/nzbtray/src/main.rs is the Windows tray's,
    /// landed the same afternoon by a lane that could not see this one.
    /// The dashboard's is canonical and the other two follow it. The rule the unit
    /// convention exists to keep is that one number never appears in two
    /// units in one product, so if that function's thresholds ever move,
    /// this one moves with it. The localised unit symbols do NOT come
    /// across: these strings sit beside native menus that are English
    /// throughout, and the app ships no catalogue to translate them
    /// from.
    static func rateText(_ mbps: Double, bits: Bool) -> String {
        if bits {
            let mb = mbps * 8
            return mb >= 1000
                ? String(format: "%.2f Gb/s", mb / 1000)
                : String(format: "%.0f Mb/s", mb)
        }
        return mbps >= 1000
            ? String(format: "%.2f GB/s", mbps / 1000)
            : String(format: "%.0f MB/s", mbps)
    }
}
