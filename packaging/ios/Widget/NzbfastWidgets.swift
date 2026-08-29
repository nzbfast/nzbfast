// The lock-screen and Dynamic Island presentation of a running queue
// (TODO 281 IO2).
//
// A SEPARATE TARGET because there is no other way: ActivityKit renders a
// Live Activity out of process, from an `ActivityConfiguration` declared
// in a widget extension, and an app on its own cannot declare one. The
// app starts and updates the activity (`LiveProgress`); everything drawn
// below runs in this extension.
//
// NO CONTENT, NO ARTWORK, NO NETWORK. It draws only what the app hands
// it in `ContentState`. That is a posture rule and not a simplification:
// this app has no indexer and no search, and a lock-screen widget that
// went and fetched a poster for whatever is downloading would be the
// first thing in it that reached out for content.
import SwiftUI
import WidgetKit
import ActivityKit

@available(iOS 16.2, *)
struct DownloadActivityWidget: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: DownloadActivityAttributes.self) { context in
            // The lock screen and the Notification Centre banner.
            LockScreenView(attributes: context.attributes, state: context.state)
                .padding()
                .activityBackgroundTint(Color.black.opacity(0.55))
                .activitySystemActionForegroundColor(.white)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label(context.state.held ? "Held" : "Downloading",
                          systemImage: context.state.held ? "pause.circle" : "arrow.down.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Text(Self.percent(context.state.fraction))
                        .font(.caption.monospacedDigit())
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(context.attributes.leadJobName)
                            .font(.caption2)
                            .lineLimit(1)
                        ProgressView(value: context.state.fraction)
                            .tint(.white)
                        Text(Self.detail(context.state))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            } compactLeading: {
                Image(systemName: context.state.held ? "pause.circle" : "arrow.down.circle")
            } compactTrailing: {
                Text(Self.percent(context.state.fraction))
                    .font(.caption2.monospacedDigit())
            } minimal: {
                Image(systemName: context.state.held ? "pause.circle" : "arrow.down.circle")
            }
        }
    }

    /// "42%" - whole numbers, because a lock-screen glance is not a
    /// place for a decimal and the Island's compact slot is a few points
    /// wide.
    static func percent(_ f: Double) -> String {
        "\(Int((f * 100).rounded()))%"
    }

    /// The line under the bar.
    ///
    /// A HELD QUEUE SAYS WHY AND WHAT TO DO, which is the whole reason a
    /// frozen activity is acceptable: without this the bar simply stops,
    /// and a user reads a stopped bar as a broken app rather than as an
    /// app iOS suspended. Copy rules apply here as everywhere - no
    /// dashes as punctuation, and the word for watching a file as it
    /// arrives is never "streaming".
    static func detail(_ s: DownloadActivityAttributes.ContentState) -> String {
        if s.held {
            return s.holdReason ?? "Open nzbfast to carry on."
        }
        var bits: [String] = []
        if s.speedBps > 0 { bits.append(rate(s.speedBps)) }
        if let t = s.timeLeft, !t.isEmpty { bits.append("\(t) left") }
        if s.jobCount > 1 { bits.append("\(s.jobCount) jobs") }
        return bits.isEmpty ? "Working" : bits.joined(separator: "  ·  ")
    }

    /// MB/s below 1000, GB/s at two decimals above it.
    ///
    /// THE FOURTH COPY OF THAT RULE WOULD BE A DEFECT, and this is not
    /// one: `tools/rate-format-gate.py` holds the three that exist -
    /// `rateParts` in web/dashboard.html (canonical), `fmt_rate` in the
    /// Windows tray and `rateText` in the mac menu bar - and refuses a
    /// file that carries all four unit strings at once. This is a
    /// BYTES-ONLY formatter with no bits arm and no GB/s arm, because a
    /// lock-screen glance has no room for either and the engine's own
    /// bits setting is a dashboard preference this extension cannot
    /// read. If it ever grows the bits arm it becomes a fourth copy and
    /// belongs in that gate's SOURCES, held to the same rule.
    static func rate(_ bps: Double) -> String {
        String(format: "%.0f MB/s", bps / 1e6)
    }
}

@available(iOS 16.2, *)
private struct LockScreenView: View {
    let attributes: DownloadActivityAttributes
    let state: DownloadActivityAttributes.ContentState

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label(state.held ? "Held" : "Downloading",
                      systemImage: state.held ? "pause.circle" : "arrow.down.circle")
                    .font(.caption.weight(.semibold))
                Spacer()
                Text(DownloadActivityWidget.percent(state.fraction))
                    .font(.caption.monospacedDigit())
            }
            Text(attributes.leadJobName)
                .font(.footnote)
                .lineLimit(1)
            ProgressView(value: state.fraction)
                .tint(.white)
            Text(DownloadActivityWidget.detail(state))
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .foregroundStyle(.white)
    }
}

@main
@available(iOS 16.2, *)
struct NzbfastWidgetBundle: WidgetBundle {
    var body: some Widget {
        DownloadActivityWidget()
    }
}
