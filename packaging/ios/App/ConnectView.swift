// First run: which machine downloads.
//
// TODO 281 IO1 gave this screen its first real choice. Until then the
// only answer was a daemon elsewhere; the engine now links into this app
// as a staticlib and runs on the phone, which is what the whole
// downloader-first plan is about.
//
// BOTH ANSWERS ARE BRING-YOUR-OWN-SERVER. Neither has an indexer, a
// search box or a content link in it. That is the posture the four
// approved App Store downloaders share and the one this app keeps
// (research/PLAN-MOBILE-DOWNLOADER-2026-08-24.md section 1).
import SwiftUI

struct ConnectView: View {
    @EnvironmentObject var state: AppState
    @State private var urlString = ""
    @State private var apiKey = ""
    @State private var busy = false
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("nzbfast downloads NZB files from the Usenet provider you already pay for. Choose where the downloading happens.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("On this device") {
                    Text("The engine runs inside this app. Finished files appear in the Files app. You will need your provider's server details.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button {
                        Task { await startLocal() }
                    } label: {
                        if busy {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text("Download on this device").frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(busy)
                }

                Section("On your own server") {
                    Text("Point this app at an nzbfast you already run. Copy the address and API key from its dashboard settings.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    TextField("http://192.168.1.10:6789", text: $urlString)
                        .keyboardType(.URL)
                        .textContentType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    SecureField("API key", text: $apiKey)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button {
                        Task { await connectRemote() }
                    } label: {
                        Text("Connect").frame(maxWidth: .infinity)
                    }
                    .disabled(busy || urlString.isEmpty)
                }

                if let errorText {
                    Section {
                        Label(errorText, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
            }
            .navigationTitle("nzbfast")
        }
    }

    private func startLocal() async {
        busy = true
        errorText = nil
        do {
            try await state.useDevice()
        } catch {
            errorText = (error as? LocalizedError)?.errorDescription
                ?? "The engine would not start."
        }
        busy = false
    }

    private func connectRemote() async {
        busy = true
        errorText = nil
        do {
            state.useRemote()
            try await state.connect(urlString: urlString, apiKey: apiKey)
        } catch {
            errorText = (error as? LocalizedError)?.errorDescription
                ?? "Could not reach that server."
        }
        busy = false
    }
}

/// On-device first run: the engine needs a provider before it can
/// download.
///
/// THE CREDENTIAL NEVER TOUCHES SWIFT'S FILESYSTEM CODE. These fields go
/// straight to the running engine through `mode=server_save`, the same
/// door the dashboard wizard and the Android setup screen use, so the
/// config schema, the password handling and the atomic write all stay in
/// the one place that already does them.
struct ServerSetupView: View {
    @EnvironmentObject var state: AppState
    @StateObject private var link = LinkWatcher()
    @State private var server = NewsServer()
    @State private var portText = "563"
    @State private var connText = ""
    /// Set once the user types in the connections field, after which
    /// the suggestion stops moving under them.
    @State private var connEdited = false
    @State private var busy = false
    @State private var note: String?
    @State private var noteIsError = false

    var body: some View {
        Form {
            Section {
                Text("Enter the Usenet provider you already have an account with. nzbfast does not supply one and has no search.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Section("Server") {
                TextField("news.example.com", text: $server.host)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                TextField("Port", text: $portText)
                    .keyboardType(.numberPad)
                // The port follows the SSL toggle only while it still
                // holds the OTHER standard value: a user who typed their
                // own port keeps it. Done in the binding rather than
                // with `onChange(of:initial:_:)`, which is iOS 17 and
                // this project targets 16.
                Toggle("Use SSL", isOn: Binding(
                    get: { server.tls },
                    set: { on in
                        if portText == (on ? "119" : "563") { portText = on ? "563" : "119" }
                        server.tls = on
                    }))
            }
            Section("Account") {
                TextField("Username", text: $server.username)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                SecureField("Password", text: $server.password)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            }
            Section {
                TextField("Connections", text: Binding(
                    get: { connText },
                    set: { connText = $0; connEdited = true }))
                    .keyboardType(.numberPad)
            } header: {
                Text("Connections")
            } footer: {
                Text("\(DeviceProfile.lineNote(link.status)) Your provider's account limit is the number that matters; this is only a starting point.")
            }
            if let note {
                Section {
                    Label(note, systemImage: noteIsError ? "exclamationmark.triangle" : "checkmark.circle")
                        .foregroundStyle(noteIsError ? .orange : .green)
                }
            }
            Section {
                Button("Test") { Task { await run(save: false) } }
                    .disabled(busy || !current.looksComplete)
                Button("Save and start") { Task { await run(save: true) } }
                    .disabled(busy || !current.looksComplete)
            }
        }
        .navigationTitle("Your provider")
        // FOLLOWS THE LINK, and this is a defect found by running it
        // rather than by reading it: `NWPathMonitor` is a callback, so
        // on first appearance it has not answered yet and the status is
        // `.unknown`. A one-shot `onAppear` therefore filled the field
        // with the unknown-network figure and left it there while the
        // note under it went on to say "on a wired connection" - the
        // screen contradicting itself, in the one place a wrong number
        // costs the user connections they are paying for.
        //
        // `task(id:)` re-runs on every change, and `connEdited` is what
        // stops it overwriting a number the user typed.
        .task(id: link.status) {
            guard !connEdited else { return }
            connText = String(DeviceProfile.suggestedConnections(link.status))
        }
    }

    /// The server as the fields currently read it, with the two numeric
    /// fields parsed and clamped.
    private var current: NewsServer {
        var s = server
        s.host = s.host.trimmingCharacters(in: .whitespaces)
        s.port = Int(portText) ?? (s.tls ? 563 : 119)
        s.connections = (Int(connText) ?? 8).clamped(to: 1...60)
        return s
    }

    private func run(save: Bool) async {
        busy = true
        note = nil
        do {
            guard let api = state.api() else { throw ApiError.daemon("The engine is not running.") }
            if save {
                try await api.serverSave(current)
                state.markServerConfigured()
                await state.refresh()
            } else {
                let greeting = try await api.serverTest(current)
                note = greeting
                noteIsError = false
            }
        } catch {
            note = (error as? LocalizedError)?.errorDescription ?? "That did not work."
            noteIsError = true
        }
        busy = false
    }
}

extension Comparable {
    func clamped(to r: ClosedRange<Self>) -> Self {
        min(max(self, r.lowerBound), r.upperBound)
    }
}
