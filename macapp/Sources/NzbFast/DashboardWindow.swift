import AppKit
import WebKit

/// The single main window: a WKWebView onto the daemon's dashboard, with
/// a lightweight "starting…" overlay until the daemon answers. The web
/// dashboard is the only UI - this window adds no native features.
final class DashboardWindowController: NSWindowController, NSWindowDelegate,
    WKNavigationDelegate, WKUIDelegate
{
    private let webView: WKWebView
    private let overlay = NSView()
    private let overlayLabel = NSTextField(labelValue: "starting nzbfast…")
    private let spinner = NSProgressIndicator()

    init() {
        let config = WKWebViewConfiguration()
        // Dashboard state (API key, chart prefs) lives in localStorage -
        // use the default (persistent) data store.
        webView = WKWebView(frame: .zero, configuration: config)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 820),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered, defer: false)
        window.title = "nzbfast"
        window.minSize = NSSize(width: 720, height: 480)
        // Naming the frame only makes AppKit WRITE it: every resize was
        // saved to "NSWindow Frame nzbfast.main" and nothing ever read it
        // back, so each launch reopened at the hardcoded size above no
        // matter what the user had set. setFrameUsingName is the read
        // half, and it must come after the name is set. It answers false
        // on a first run (nothing saved yet) - only then do we place the
        // window ourselves, because center() would otherwise overwrite a
        // restored position with the default one.
        window.setFrameAutosaveName("nzbfast.main")
        if !window.setFrameUsingName("nzbfast.main") {
            window.center()
        }
        // Closing hides the window; the daemon (and the app) keep running.
        window.isReleasedWhenClosed = false
        super.init(window: window)
        // NSWindowController offsets each window it shows from the last
        // one; with a single restored window that just walks it down the
        // screen a little further on every launch.
        shouldCascadeWindows = false
        window.delegate = self

        webView.navigationDelegate = self
        webView.uiDelegate = self
        let content = window.contentView!
        webView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(webView)
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: content.topAnchor),
            webView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
        ])

        // "starting…" overlay, dashboard-dark to avoid a white flash.
        overlay.wantsLayer = true
        overlay.layer?.backgroundColor = NSColor(red: 0.055, green: 0.063, blue: 0.078, alpha: 1).cgColor
        overlay.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(overlay)
        NSLayoutConstraint.activate([
            overlay.topAnchor.constraint(equalTo: content.topAnchor),
            overlay.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            overlay.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            overlay.trailingAnchor.constraint(equalTo: content.trailingAnchor),
        ])
        spinner.style = .spinning
        spinner.controlSize = .regular
        spinner.appearance = NSAppearance(named: .darkAqua)
        spinner.startAnimation(nil)
        overlayLabel.textColor = NSColor(red: 0.91, green: 0.92, blue: 0.94, alpha: 1)
        overlayLabel.font = .systemFont(ofSize: 15, weight: .medium)
        let stack = NSStackView(views: [spinner, overlayLabel])
        stack.orientation = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        overlay.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: overlay.centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("unused") }

    func showDashboard(_ url: URL) {
        webView.load(URLRequest(url: url))
    }

    func setOverlay(visible: Bool, text: String = "starting nzbfast…") {
        overlayLabel.stringValue = text
        overlay.isHidden = !visible
        if visible { spinner.startAnimation(nil) } else { spinner.stopAnimation(nil) }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        setOverlay(visible: false)
    }

    /// Load the dashboard even when the engine serves it over TLS with a
    /// certificate WebKit will not vouch for.
    ///
    /// A TLS install points `tls_cert` at an operator-supplied
    /// certificate - self-signed, and issued for whatever hostname the
    /// LAN reaches it by, never for 127.0.0.1. In a browser the user
    /// clicks through that warning; a WKWebView has no such affordance
    /// and simply fails the navigation, leaving this window stuck on the
    /// "starting…" overlay with no way forward.
    ///
    /// Same reasoning as `Daemon.LoopbackTrust`, and the same narrow
    /// scope: server trust on 127.0.0.1 only. The certificate was never
    /// what identified this engine - the `runtime.json` token handshake
    /// is, and `Daemon.start()` has already passed it before any URL
    /// reaches this window. Everything else gets default handling.
    func webView(
        _ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
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

    /// Regular navigations that leave localhost (a clicked external link)
    /// go to the default browser; the wrapper only ever shows the
    /// dashboard.
    func webView(
        _ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        if action.navigationType == .linkActivated,
           let url = action.request.url, !isLocal(url)
        {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    /// target=_blank (no matter the host) opens in the default browser -
    /// the dashboard uses it for the manual, the wall, and outbound links,
    /// all of which belong in a real browser tab.
    func webView(
        _ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
        for action: WKNavigationAction, windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        if let url = action.request.url {
            NSWorkspace.shared.open(url)
        }
        return nil
    }

    /// window.confirm(). Same story as prompt() below: with no WKUIDelegate
    /// implementation WebKit answers `false` to every confirm() in the page,
    /// so six dashboard actions that ask before doing something irreversible
    /// - stop download, remove-with-files, add-all-groups, import config,
    /// remove server, wipe index - returned early and did nothing. It fails
    /// safe (the action is skipped, never performed), but the buttons look
    /// broken because nothing at all happens when you click them.
    ///
    /// completionHandler MUST run exactly once on every path or WebKit
    /// leaves the page's JS suspended for good.
    func webView(
        _ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping (Bool) -> Void
    ) {
        // Only the local dashboard gets to put a native dialog on screen.
        let host = frame.securityOrigin.host
        guard host == "127.0.0.1" || host == "localhost" || host == "::1" else {
            completionHandler(false)
            return
        }
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        completionHandler(alert.runModal() == .alertFirstButtonReturn)
    }

    /// window.prompt(). WebKit has no built-in panel for it: with no
    /// WKUIDelegate implementation every prompt() in the page silently
    /// evaluates to null, so the dashboard's archive-password, new-folder
    /// and move-to-category asks are dead, and so is its API-key prompt -
    /// which is the fallback for a daemon whose key we cannot read (one the
    /// user started themselves, or a data dir we have no access to). The
    /// normal path hands the key over in the URL instead; this is the
    /// backstop.
    ///
    /// completionHandler MUST run exactly once on every path or WebKit
    /// leaves the page's JS suspended for good.
    func webView(
        _ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
        defaultText: String?, initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping (String?) -> Void
    ) {
        // Only the local dashboard gets to put a native dialog on screen.
        let host = frame.securityOrigin.host
        guard host == "127.0.0.1" || host == "localhost" || host == "::1" else {
            completionHandler(nil)
            return
        }
        let alert = NSAlert()
        alert.messageText = prompt
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.stringValue = defaultText ?? ""
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        let ok = alert.runModal() == .alertFirstButtonReturn
        completionHandler(ok ? field.stringValue : nil)
    }

    private func isLocal(_ url: URL) -> Bool {
        let host = url.host ?? ""
        return host == "127.0.0.1" || host == "localhost" || host == "::1"
    }
}

private extension NSTextField {
    convenience init(labelValue: String) {
        self.init(labelWithString: labelValue)
    }
}
