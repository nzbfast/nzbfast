import SwiftUI
import UniformTypeIdentifiers
import ParfastCore

// The small pieces every screen is built from. Kept in one file so the visual
// language in plan 5.7 has one place to live: a card is a card everywhere, a
// pill is a pill everywhere, and a spacing change is one edit.

/// The grouped container the header, the map, the tables and the option
/// groups all sit in.
struct Card<Content: View>: View {
    var title: String?
    var accessory: AnyView?
    @ViewBuilder var content: () -> Content

    init(_ title: String? = nil, accessory: AnyView? = nil,
         @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.accessory = accessory
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: T.spacingM) {
            if title != nil || accessory != nil {
                HStack(alignment: .firstTextBaseline) {
                    if let title {
                        Text(title)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(T.textPrimary)
                    }
                    Spacer(minLength: T.spacingS)
                    if let accessory { accessory }
                }
            }
            content()
        }
        .padding(T.spacingL)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: T.radiusCard, style: .continuous)
                .fill(T.surfaceCard)
        )
        .overlay(
            RoundedRectangle(cornerRadius: T.radiusCard, style: .continuous)
                .strokeBorder(T.surfaceCardBorder, lineWidth: 1)
        )
    }
}

/// The verdict pill (5.2). A tinted chip with a dot, and a cross-fade between
/// tones so a verdict arriving does not read as a layout jump.
///
/// A TINT AND A DOT RATHER THAN A SOLID FILL, since 12 Sep 2026, ported from the
/// Windows control `StatusPill.cs` so both apps draw the same picture. The pill
/// used to take the tone at full strength as its ground with a contrasting text
/// colour on top, which at this size reads as a marker pen and, on the verify
/// screen, shouted over the set name it sits beside. Tinted ground, the tone
/// itself as ink, a 1px border of the tone, and a dot of the full-strength
/// colour is the current idiom on both platforms.
///
/// The dot is not decoration. It is the same mark the legend puts beside each
/// state, so the verdict and the key agree; and it is the secondary channel that
/// keeps the verdict from being carried by colour alone, which the tint on its
/// own would not do at 15% of a hue.
///
/// A SOFT RADIUS, NOT A CAPSULE: `T.radiusControl`, so the verdict belongs to the
/// same family as the buttons under it rather than reading as a highlighter
/// stroke through the header.
///
/// The tint and border strengths are DERIVED FROM THE TONE rather than kept as a
/// second table. Five tones times two themes is ten more colours to hold in step
/// with the five that already exist, and the tint is a function of the tone
/// rather than an independent choice - which is also why one constant works on
/// both appearances: what the tint does not cover is the card behind it.
struct StatusPill: View {
    enum Tone { case neutral, working, good, warn, bad }

    var text: String
    var tone: Tone
    var busy: Bool = false

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Alpha 38 and 70 of 255, the Windows control's measured values.
    private static let tintAlpha = 38.0 / 255.0
    private static let borderAlpha = 70.0 / 255.0

    /// The tone's own colour, which is the ink, the dot and - diluted - the
    /// ground and the border.
    private var ink: Color {
        switch tone {
        case .neutral: return T.statusNeutral
        case .working: return T.statusWorking
        case .good: return T.statusGood
        case .warn: return T.statusWarn
        case .bad: return T.statusBad
        }
    }

    var body: some View {
        HStack(spacing: 7) {
            if busy {
                // The ring REPLACES the dot rather than joining it. Two marks
                // before the label is one too many, and the ring is already
                // saying "working" louder than a static dot can.
                ProgressView()
                    .controlSize(.small)
                    .tint(ink)
                    .scaleEffect(0.7)
                    .frame(width: 12, height: 12)
            } else {
                Circle()
                    .fill(ink)
                    .frame(width: 8, height: 8)
            }
            Text(text)
                .font(.system(size: 12, weight: .semibold))
                .monospacedDigit()
        }
        .foregroundStyle(ink)
        .padding(.leading, 10)
        .padding(.trailing, 12)
        .padding(.vertical, 4)
        .background(
            RoundedRectangle(cornerRadius: T.radiusControl, style: .continuous)
                .fill(ink.opacity(Self.tintAlpha))
        )
        .overlay(
            RoundedRectangle(cornerRadius: T.radiusControl, style: .continuous)
                .strokeBorder(ink.opacity(Self.borderAlpha), lineWidth: 1)
        )
        .animation(reduceMotion ? nil : .easeInOut(duration: T.motionPillCrossfadeMs / 1000),
                   value: text)
        .accessibilityLabel(text)
    }
}

/// A figure with its label under it, tabular digits, for the header card and
/// the readout rows.
struct Figure: View {
    var label: String
    var value: String
    var tone: Color = T.textPrimary

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.system(size: 15, weight: .semibold))
                .monospacedDigit()
                .foregroundStyle(tone)
            Text(label)
                .font(.system(size: 11))
                .foregroundStyle(T.textSecondary)
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// A label and a control on one line, aligned down the screen.
struct Row<Content: View>: View {
    var label: String
    var help: String?
    @ViewBuilder var content: () -> Content

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: T.spacingM) {
            HStack(spacing: 4) {
                Text(label)
                    .font(.system(size: 12))
                    .foregroundStyle(T.textSecondary)
                if let help {
                    InfoTip(text: help)
                }
            }
            .frame(width: 132, alignment: .trailing)
            content()
            Spacer(minLength: 0)
        }
    }
}

struct InfoTip: View {
    var text: String
    @State private var showing = false

    var body: some View {
        Button {
            showing.toggle()
        } label: {
            Image(systemName: "info.circle")
                .font(.system(size: 11))
                .foregroundStyle(T.textTertiary)
        }
        .buttonStyle(.plain)
        .popover(isPresented: $showing, arrowEdge: .bottom) {
            Text(text)
                .font(.system(size: 12))
                .padding(T.spacingM)
                .frame(width: 260)
        }
        .accessibilityLabel(text)
    }
}

/// The empty state (5.1): the drop zone is the WHOLE content area, not a box
/// inside it.
struct DropZone<Buttons: View>: View {
    var symbol: String
    var title: String
    var body1: String
    @ViewBuilder var buttons: () -> Buttons

    var body: some View {
        VStack(spacing: T.spacingL) {
            Image(systemName: symbol)
                .font(.system(size: 46, weight: .light))
                .foregroundStyle(T.accentPrimary)
            VStack(spacing: T.spacingS) {
                Text(title)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(T.textPrimary)
                Text(body1)
                    .font(.system(size: 13))
                    .foregroundStyle(T.textSecondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 420)
            }
            HStack(spacing: T.spacingM) { buttons() }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            RoundedRectangle(cornerRadius: T.radiusCard, style: .continuous)
                .fill(T.surfaceDropFill)
        )
        .overlay(
            RoundedRectangle(cornerRadius: T.radiusCard, style: .continuous)
                .strokeBorder(T.surfaceDropBorder, style: StrokeStyle(lineWidth: 1.5, dash: [7, 5]))
        )
        .padding(T.spacingL)
    }
}

/// A byte field with a unit stepper: the user types 1 and picks MiB rather
/// than typing 1048576.
struct SizeField: View {
    @Binding var bytes: Int64
    var multipleOfFour: Bool = false

    private static let units: [(String, Int64)] = [
        ("bytes", 1), ("KiB", 1024), ("MiB", 1_048_576), ("GiB", 1_073_741_824),
    ]

    @State private var text: String = ""
    @State private var unitIndex: Int = 2

    var body: some View {
        HStack(spacing: T.spacingS) {
            TextField("", text: $text)
                .textFieldStyle(.roundedBorder)
                .frame(width: 90)
                .monospacedDigit()
                .multilineTextAlignment(.trailing)
                .onSubmit(commit)
                .onChange(of: text) { _, _ in commit() }
            Picker("", selection: $unitIndex) {
                ForEach(Self.units.indices, id: \.self) { i in
                    Text(Self.units[i].0).tag(i)
                }
            }
            .labelsHidden()
            .frame(width: 82)
            .onChange(of: unitIndex) { _, _ in commit() }
        }
        .onAppear(perform: load)
        .onChange(of: bytes) { _, _ in
            if parsed() != bytes { load() }
        }
    }

    private func load() {
        var index = 0
        for (i, unit) in Self.units.enumerated() where bytes >= unit.1 && bytes % unit.1 == 0 {
            index = i
        }
        unitIndex = index
        let scale = Self.units[index].1
        text = Fmt.count(bytes / scale)
    }

    private func parsed() -> Int64 {
        let digits = text.filter { $0.isNumber }
        let value = Int64(digits) ?? 0
        return value * Self.units[unitIndex].1
    }

    private func commit() {
        var value = parsed()
        if multipleOfFour { value = (value + 3) / 4 * 4 }
        if value != bytes { bytes = max(0, value) }
    }
}

/// An integer field that refuses anything but digits, clamped to a range.
struct NumberField: View {
    @Binding var value: Int
    var range: ClosedRange<Int> = 0...Int.max
    var width: CGFloat = 90

    @State private var text: String = ""

    var body: some View {
        TextField("", text: $text)
            .textFieldStyle(.roundedBorder)
            .frame(width: width)
            .monospacedDigit()
            .multilineTextAlignment(.trailing)
            .onAppear { text = Fmt.count(value) }
            .onChange(of: text) { _, _ in
                let digits = text.filter { $0.isNumber }
                let parsed = Int(digits) ?? range.lowerBound
                let clamped = min(max(parsed, range.lowerBound), range.upperBound)
                if clamped != value { value = clamped }
            }
            .onChange(of: value) { _, newValue in
                let digits = text.filter { $0.isNumber }
                if Int(digits) != newValue { text = Fmt.count(newValue) }
            }
    }
}

/// A path field with a Browse button beside it.
struct PathField: View {
    @Binding var path: String
    var chooseDirectory: Bool = false
    var allowedExtensions: [String]? = nil
    var isSave: Bool = false
    var onEdit: (() -> Void)?

    var body: some View {
        HStack(spacing: T.spacingS) {
            TextField("", text: $path)
                .textFieldStyle(.roundedBorder)
                .onChange(of: path) { _, _ in onEdit?() }
            Button(S.commonBrowse) {
                if let picked = FilePicker.choose(
                    directory: chooseDirectory, extensions: allowedExtensions,
                    save: isSave, suggestion: path) {
                    path = picked
                    onEdit?()
                }
            }
        }
    }
}

enum FilePicker {
    static func choose(directory: Bool, extensions: [String]?, save: Bool,
                       suggestion: String) -> String? {
        if save {
            let panel = NSSavePanel()
            panel.canCreateDirectories = true
            if !suggestion.isEmpty {
                panel.nameFieldStringValue = (suggestion as NSString).lastPathComponent
                panel.directoryURL = URL(fileURLWithPath: (suggestion as NSString).deletingLastPathComponent)
            }
            if let extensions { panel.allowedContentTypes = extensions.compactMap(Self.type(for:)) }
            return panel.runModal() == .OK ? panel.url?.path : nil
        }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = directory
        panel.canChooseFiles = !directory
        panel.allowsMultipleSelection = false
        if let extensions, !directory {
            panel.allowedContentTypes = extensions.compactMap(Self.type(for:))
        }
        return panel.runModal() == .OK ? panel.url?.path : nil
    }

    static func chooseMany(directories: Bool) -> [String] {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = directories
        panel.canChooseFiles = !directories
        panel.allowsMultipleSelection = true
        return panel.runModal() == .OK ? panel.urls.map(\.path) : []
    }

    static func type(for ext: String) -> UTType? {
        UTType(filenameExtension: ext)
    }
}

/// A toast that says what just happened and gets out of the way.
struct ToastView: View {
    var text: String

    var body: some View {
        Text(text)
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(T.statusOnNeutral)
            .padding(.horizontal, T.spacingL)
            .padding(.vertical, T.spacingS)
            .background(Capsule().fill(T.statusNeutral.opacity(0.92)))
            .shadow(radius: 8, y: 2)
    }
}

/// A thin progress bar that never jumps backwards (5.7).
struct SmoothBar: View {
    var value: Double
    var tint: Color = T.accentPrimary
    var height: CGFloat = 6

    @State private var shown: Double = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(T.surfaceWell)
                Capsule().fill(tint)
                    .frame(width: max(0, min(1, shown)) * geo.size.width)
            }
        }
        .frame(height: height)
        .onAppear { shown = value }
        .onChange(of: value) { _, newValue in
            let target = max(shown, newValue)
            if reduceMotion {
                shown = target
            } else {
                withAnimation(.linear(duration: 0.12)) { shown = target }
            }
        }
        .accessibilityValue(Fmt.progressPercent(value))
    }
}
