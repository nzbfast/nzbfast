// TODO 281 IO0: ONE settings sheet, which is the whole of what the
// plan's addendum A asks for - server, folder, cellular and keep-awake.
//
// Everything the desktop dashboard does beyond this (whyslow, the wall,
// graphs, the language switcher) stays desktop. A phone app that grows a
// second settings screen has stopped being the minimal native shape the
// plan describes, so the rule is worth stating where the file is.
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    @State private var pauseOnCellular = AppSettings.pauseOnCellular
    @State private var keepAwake = AppSettings.keepAwake

    // Written through on set rather than watched with `onChange`: the
    // two-closure `onChange(of:initial:_:)` is iOS 17 and this project
    // targets 16, and a binding that persists as it changes has one
    // fewer moving part than a mirror plus a watcher anyway.
    private var cellularBinding: Binding<Bool> {
        Binding(get: { pauseOnCellular },
                set: { on in
                    pauseOnCellular = on
                    AppSettings.pauseOnCellular = on
                    // Apply NOW, against the link as it stands: the
                    // policy task keys on link CHANGES, so a toggle
                    // flipped on an already-cellular link would
                    // otherwise wait for the network to move (C16).
                    Task { await state.applyCellularPolicy(state.lastLinkStatus) }
                })
    }

    private var awakeBinding: Binding<Bool> {
        Binding(get: { keepAwake },
                set: {
                    keepAwake = $0
                    AppSettings.keepAwake = $0
                    state.updateKeepAwake()
                })
    }

    var body: some View {
        List {
            Section("Downloading") {
                switch state.source {
                case .device:
                    LabeledContent("Runs on", value: "This device")
                    LabeledContent("Engine", value: engineStatus)
                case .remote:
                    LabeledContent("Runs on", value: "Your server")
                    LabeledContent("Address",
                                   value: state.config?.baseURL.absoluteString ?? "")
                    LabeledContent("Version", value: state.serverVersion ?? "unknown")
                }
            }

            Section {
                if state.source == .device {
                    LabeledContent("Folder", value: "Files app, in nzbfast")
                    Text("Finished downloads land in this app's folder in the Files app, so nothing has to be exported.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    Text("Files land on your server, in the folder it is configured to use.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                LabeledContent("Free space",
                               value: String(format: "%.1f GB", state.freeSpaceGB))
            } header: {
                Text("Where files go")
            }

            // Both of these are about an engine running HERE. With the
            // downloading on the user's own server, holding off on
            // cellular would pause a machine whose link this phone knows
            // nothing about, and keeping the screen awake would guard
            // work that is not on this device - so the section is not
            // shown rather than shown and quietly inert.
            if state.source == .device {
                Section {
                    Toggle("Hold off on cellular", isOn: cellularBinding)
                    Toggle("Keep the screen awake", isOn: awakeBinding)
                } header: {
                    Text("On this phone")
                } footer: {
                    // The honest copy the plan asks for. Every bad review
                    // in this category is "it stopped when I switched
                    // apps", so the limit is stated in the app rather
                    // than left to be discovered.
                    Text("Downloads run while this app is open. Switch away and iOS suspends them within seconds; they pick up again from where they stopped when you come back. Keeping the screen awake, or watching a file while it downloads, keeps them going.")
                }
            } else {
                Section {
                    Text("Your server keeps downloading whatever this app is doing.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                Button(state.source == .device ? "Stop and change source" : "Disconnect",
                       role: .destructive) {
                    state.disconnect()
                }
            }
        }
        .navigationTitle("Settings")
    }

    private var engineStatus: String {
        switch state.engine.state {
        case .off: return "Stopped"
        case .starting: return "Starting"
        case .stopping: return "Stopping"
        case .up(let port): return "Running on port \(port)"
        case .failed(let why): return why
        }
    }
}
