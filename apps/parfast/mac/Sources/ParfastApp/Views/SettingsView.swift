import SwiftUI
import ParfastCore

/// Settings, plan 5.6. A mac `Settings` scene, Cmd-comma.
///
/// The DEFAULTS are the core's (`pf_settings_get` on a fresh session), so
/// nothing here carries a second copy of them; this screen only edits the
/// object the core handed over and hands it back.
struct SettingsView: View {
    @EnvironmentObject var app: AppModel
    @State private var draft = CoreSettings()
    @State private var confirmingReset = false
    @State private var confirmingClear = false
    @State private var digestCacheCleared = false

    var body: some View {
        TabView {
            general.tabItem { Label(S.settingsGeneral, systemImage: "gearshape") }
            createDefaults.tabItem { Label(S.settingsCreate, systemImage: "plus.square.on.square") }
            performance.tabItem { Label(S.settingsPerformance, systemImage: "speedometer") }
            integration.tabItem { Label(S.settingsIntegration, systemImage: "square.and.arrow.down.on.square") }
            advanced.tabItem { Label(S.settingsAdvanced, systemImage: "wrench.adjustable") }
        }
        .frame(width: 520, height: 360)
        .onAppear { draft = app.settings }
        .onChange(of: draft) { _, newValue in app.apply(settings: newValue) }
    }

    private var general: some View {
        Form {
            Picker(S.settingsOnOpen, selection: $draft.general.open_par2) {
                Text(S.settingsOnOpenVerify).tag(CoreSettings.OpenAction.verify)
                Text(S.settingsOnOpenRepair).tag(CoreSettings.OpenAction.verifyThenRepair)
            }
            Toggle(S.settingsPurgeDefault, isOn: $draft.general.purge_after_repair)
            Toggle(S.settingsKeepDamagedDefault, isOn: $draft.general.keep_damaged_copies)
            Toggle(S.settingsNotifications, isOn: $draft.general.notifications)
            Toggle(S.settingsAutoClose, isOn: $draft.general.auto_close_progress)
            Picker(S.settingsLanguage, selection: $draft.general.language) {
                Text(S.settingsLanguageEn).tag("en")
            }
        }
        .formStyle(.grouped)
    }

    private var createDefaults: some View {
        Form {
            Picker(S.settingsBlockAllocation, selection: $draft.create.block_allocation) {
                Text(S.createBlocksBySize).tag(CoreSettings.BlockAllocation.size)
                Text(S.createBlocksByCount).tag(CoreSettings.BlockAllocation.count)
            }
            if draft.create.block_allocation == .size {
                LabeledContent(S.createBlocksBySize) {
                    SizeField(bytes: $draft.create.block_size, multipleOfFour: true)
                }
            } else {
                LabeledContent(S.createBlocksByCount) {
                    NumberField(value: $draft.create.block_count, range: 1...MockPlanner.maxSourceBlocks)
                }
            }
            Picker(S.settingsRecoveryAllocation, selection: $draft.create.recovery_allocation) {
                Text(S.createRecoveryPercent).tag(CoreSettings.RecoveryAllocation.percent)
                Text(S.createRecoveryCount).tag(CoreSettings.RecoveryAllocation.count)
                Text(S.createRecoverySize).tag(CoreSettings.RecoveryAllocation.size)
            }
            Picker(S.settingsDefaultScheme, selection: $draft.create.scheme) {
                Text(S.createOutputSchemeNone).tag("none")
                Text(S.createOutputSchemeUniform).tag("uniform")
                Text(S.createOutputSchemePow2).tag("pow2")
                Text(S.createOutputSchemePow2Limit).tag("pow2_limit")
            }
            if app.capabilities.std_naming {
                Toggle(S.createOutputStdNaming, isOn: $draft.create.std_naming)
            }
            if app.capabilities.unicode_policy {
                Picker(S.createOutputUnicode, selection: Binding(
                    get: { UnicodePolicy(rawValue: draft.create.unicode) ?? .auto },
                    set: { draft.create.unicode = $0.rawValue })) {
                    Text(S.createOutputUnicodeAuto).tag(UnicodePolicy.auto)
                    Text(S.createOutputUnicodeNever).tag(UnicodePolicy.never)
                    Text(S.createOutputUnicodeAlways).tag(UnicodePolicy.always)
                }
            }
            Toggle(S.createOutputOverwrite, isOn: $draft.create.overwrite)
        }
        .formStyle(.grouped)
    }

    private var performance: some View {
        Form {
            Picker(S.settingsThreads, selection: Binding(
                get: { draft.performance.threads ?? 0 },
                set: { draft.performance.threads = $0 == 0 ? nil : $0 })) {
                Text(S.commonAuto).tag(0)
                ForEach([1, 2, 4, 8, 16], id: \.self) { Text(Fmt.count($0)).tag($0) }
            }
            Picker(S.settingsMemoryLimit, selection: Binding(
                get: { draft.performance.memory_mb ?? 0 },
                set: { draft.performance.memory_mb = $0 == 0 ? nil : $0 })) {
                Text(S.commonAuto).tag(0)
                ForEach([512, 1024, 2048, 4096, 8192], id: \.self) {
                    Text("\(Fmt.count($0)) MiB").tag($0)
                }
            }
            if app.capabilities.fast_solver {
                Toggle(S.settingsFastSolver, isOn: $draft.performance.fast_solver)
            }
            if app.capabilities.low_priority {
                Toggle(S.settingsLowPriority, isOn: $draft.performance.low_priority)
            }
            VStack(alignment: .leading, spacing: 2) {
                Toggle(S.settingsDigestCache, isOn: $draft.performance.digest_cache)
                Text(S.settingsDigestCacheNote)
                    .font(.system(size: 11))
                    .foregroundStyle(T.textSecondary)
                // Not gated on the toggle: records written while it was on
                // stay on disk after it is turned off, and this is how they go.
                HStack(spacing: 8) {
                    Button(S.settingsDigestCacheClear) { confirmingClear = true }
                        // Title is the question, explanation goes in `message`,
                        // the same split ProgressSheet's cancel dialog uses. A
                        // confirmationDialog renders its title in bold and has
                        // nowhere else to put a second sentence, so carrying
                        // both in the title gave a two-line bold heading.
                        .confirmationDialog(S.settingsDigestCacheClearConfirm,
                                            isPresented: $confirmingClear) {
                            Button(S.settingsDigestCacheClear, role: .destructive) {
                                digestCacheCleared = app.clearDigestCache()
                            }
                            Button(S.commonCancel, role: .cancel) {}
                        } message: {
                            Text(S.settingsDigestCacheClearConfirmBody)
                        }
                    if digestCacheCleared {
                        Text(S.settingsDigestCacheCleared)
                            .font(.system(size: 11))
                            .foregroundStyle(T.textSecondary)
                    }
                }
                .padding(.top, 4)
            }
            VStack(alignment: .leading, spacing: 2) {
                Toggle(S.settingsPairLargeCreates, isOn: $draft.performance.pair_large_creates)
                Text(S.settingsPairLargeCreatesNote)
                    .font(.system(size: 11))
                    .foregroundStyle(T.textSecondary)
            }
            LabeledContent(S.appName) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.capabilities.engine)
                        .font(.system(size: 11))
                        .foregroundStyle(T.textSecondary)
                    Text("\(app.capabilities.cpu) - \(app.capabilities.kernel)")
                        .font(.system(size: 11))
                        .foregroundStyle(T.textTertiary)
                }
            }
        }
        .formStyle(.grouped)
    }

    private var integration: some View {
        Form {
            Toggle(S.settingsRegisterTypes, isOn: $draft.integration.handle_par2)
            Toggle(S.settingsQuickActions, isOn: $draft.integration.shell_menu)
            LabeledContent("") {
                VStack(alignment: .leading, spacing: 3) {
                    Text(AppModel.checksumExtensions.map { ".\($0)" }.joined(separator: "  ") + "  .par2")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(T.textSecondary)
                    Text(S.settingsIntegrationContextNote)
                        .font(.system(size: 11))
                        .foregroundStyle(T.textTertiary)
                    // Empty on this platform: the string table's split says
                    // the line does not apply here, so it is omitted rather
                    // than rendered as a blank row.
                    if !S.settingsIntegrationWin11Note.isEmpty {
                        Text(S.settingsIntegrationWin11Note)
                            .font(.system(size: 11))
                            .foregroundStyle(T.textTertiary)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var advanced: some View {
        Form {
            Toggle(S.settingsShowCommand, isOn: $draft.advanced.show_command)
            // The core's log level is `verbose - quiet`, the two CLI counters
            // as one number: 0 is the reference's default and -2 is silence.
            Picker(S.settingsLogLevel, selection: $draft.advanced.log_level) {
                Text(S.settingsLogQuiet).tag(-2)
                Text(S.settingsLogNormal).tag(0)
                Text(S.settingsLogVerbose).tag(1)
            }
            LabeledContent(S.settingsLogFolder) {
                PathField(path: Binding(
                    get: { draft.advanced.log_folder ?? "" },
                    set: { draft.advanced.log_folder = $0.isEmpty ? nil : $0 }),
                          chooseDirectory: true)
            }
            Button(S.settingsReset, role: .destructive) { confirmingReset = true }
                .confirmationDialog(S.settingsResetConfirm, isPresented: $confirmingReset) {
                    Button(S.settingsReset, role: .destructive) {
                        draft = CoreSettings()
                    }
                    Button(S.commonCancel, role: .cancel) {}
                }
        }
        .formStyle(.grouped)
    }
}
