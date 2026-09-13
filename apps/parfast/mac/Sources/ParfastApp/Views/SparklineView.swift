import SwiftUI
import ParfastCore

/// The read rate over the last couple of minutes: a gradient wash under a 2 point
/// line, with the endpoint emphasised.
///
/// Section 4 of the 12 September 2026 prettiness review, chart (b), and the
/// treatment nzbfast's own dashboard is known for. The sheet showed one
/// instantaneous rate and threw the previous value away; `RateHistory` is the ring
/// buffer that keeps them and is the only new data in the whole change.
///
/// WHAT IS BORROWED FROM THE DASHBOARD'S `drawArea` AND WHAT IS NOT. Borrowed: the
/// gradient wash under a two point line, the endpoint marker, and the VU-meter
/// y-scale rule - scale UP instantly so a spike is never clipped, ease DOWN when
/// the window maximum falls, because a spiky series that re-scales on every sample
/// judders and the judder is read as information. That rule lives in
/// `RateHistory.displayMax` so it is testable without a window. NOT borrowed: any
/// of the code, which is canvas and JavaScript, and the per-frame x-glide, which
/// needs an animation loop this app does not have and does not want.
///
/// MOTION: THERE IS NONE, WHICH IS HOW THE REST OF THIS APP RESPECTS THE SETTING.
/// parfast runs no storyboards and no transitions anywhere - the block map, the
/// status pill and the progress bar all simply redraw - so a chart that animated
/// would be the first moving thing in the window rather than one more. The single
/// motion-shaped behaviour is the y-scale easing above, and it is switched off
/// from `accessibilityReduceMotion`, which leaves a chart that steps rather than
/// glides and is otherwise identical. Read on every redraw rather than once in
/// `onAppear`: the sheet hands the history over after the view first appears, and
/// a one-shot read would have left a reduced-motion reader with the easing anyway,
/// silently. (The Windows lane hit exactly that and its control's comment says so;
/// the mac's environment value simply makes the right thing the easy thing.)
///
/// A SINGLE SERIES, SO THERE IS NO LEGEND: the Rate figure above names what is
/// plotted, and a box with one swatch would restate it. The endpoint is the only
/// direct label, which is the house rule - a value on every point goes unread.
struct SparklineView: View {

    @ObservedObject var history: RateHistory

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// The series line's thickness, per the house mark spec.
    private let lineWidth: CGFloat = 2

    /// The endpoint marker's diameter, and the surface ring around it.
    ///
    /// Eight points is the floor for a marker; the two point ring in the surface
    /// colour is what keeps it legible where it sits on the line it terminates.
    private let markerSize: CGFloat = 8
    private let markerRing: CGFloat = 2

    /// How many points each sample gets at least, so a narrow strip draws a
    /// shorter window rather than several seconds per point.
    private let pointsPerSample: CGFloat = 2

    /// Air above the peak, so the highest sample is a line and not the ceiling.
    private let topPadding: CGFloat = 3

    /// Air at the right, wide enough for the endpoint marker AND its ring.
    ///
    /// Without it the plot runs to the view's own edge, the marker is clamped
    /// flush against it, and the surface ring - the thing that makes the marker
    /// read as a marker rather than as a blob on the end of the line - is cut in
    /// half by the edge. Seen on the first Windows frame of this chart; the clamp
    /// was doing its job and the job was the wrong one.
    private var rightPadding: CGFloat { markerSize / 2 + markerRing }

    var body: some View {
        Canvas { context, size in
            // The easing is set from the environment on every pass, so a reader
            // who changes the setting mid-job gets the new behaviour on the next
            // snapshot rather than on the next launch.
            history.smoothScale = !reduceMotion
            draw(context: context, size: size)
        }
        .accessibilityElement()
        .accessibilityLabel(S.progressRate)
        .accessibilityValue(accessibleValue)
    }

    /// The picture is unreadable to a screen reader by construction, so the value
    /// IS the answer - the rate now and which way it is going - rather than a
    /// label saying "chart" (plan 5.7, the rule the block map already follows).
    private var accessibleValue: String {
        let now = Fmt.rate(history.current)
        let trend = history.trendText
        return trend.isEmpty ? now : now + ". " + trend
    }

    private func draw(context: GraphicsContext, size: CGSize) {
        guard history.hasShape, size.width > 2, size.height > 2 else { return }
        let wanted = Int(max(2, size.width / pointsPerSample))
        let samples = history.visible(wanted)
        guard samples.count >= 2 else { return }

        let maxValue = history.displayMax
        let right = max(1, size.width - rightPadding)
        let step = right / CGFloat(samples.count - 1)
        let plot = max(1, size.height - topPadding)

        // THE HISTORY IS STRETCHED ACROSS THE PLOT rather than laid out at a fixed
        // step anchored to the right, which is the one thing this does differently
        // from the dashboard's `drawArea`. That chart has a fixed window it scrolls
        // through, so a short history filling only the right quarter is right
        // there. Here a whole create can be twenty seconds, and a chart that spends
        // three quarters of itself on time that has not happened yet reads as
        // broken. The cost is that the x scale narrows as the buffer fills, which
        // is ordinary sparkline behaviour and is invisible without an axis - and
        // there is no axis, by design: this is a shape, and the figure above it is
        // the value.
        var points: [CGPoint] = []
        points.reserveCapacity(samples.count)
        for (i, sample) in samples.enumerated() {
            let y = size.height - CGFloat(Double(sample) / maxValue) * plot
            points.append(CGPoint(x: CGFloat(i) * step,
                                  y: min(max(y, topPadding), size.height)))
        }

        // THE AREA IS A WASH AND NOT A BLOCK: the accent at about a fifth at the
        // top falling to nothing at the baseline. A saturated fill under a two
        // point line is the "thick saturated block" the house guidance names, and
        // it would make the line - which is the data - the quietest thing in the
        // sheet.
        var area = Path()
        area.move(to: CGPoint(x: points[0].x, y: size.height))
        area.addLines(points)
        area.addLine(to: CGPoint(x: right, y: size.height))
        area.closeSubpath()
        context.fill(area, with: .linearGradient(
            Gradient(colors: [T.accentPrimary.opacity(0.20), T.accentPrimary.opacity(0.02)]),
            // Top to bottom, and stated as two points rather than as an angle: a
            // wash that runs sideways is not a wash, it is a second and wrong
            // encoding.
            startPoint: CGPoint(x: 0, y: 0),
            endPoint: CGPoint(x: 0, y: size.height)))

        var line = Path()
        line.addLines(points)
        context.stroke(line, with: .color(T.accentPrimary),
                       style: StrokeStyle(lineWidth: lineWidth, lineCap: .round, lineJoin: .round))

        // The endpoint, which is "now" and the only point worth marking. The ring
        // is in the SURFACE colour rather than a stroke of the accent, so the
        // marker separates from the line by negative space.
        guard let last = points.last else { return }
        let ringed = markerSize + markerRing * 2
        context.fill(Path(ellipseIn: CGRect(x: last.x - ringed / 2, y: last.y - ringed / 2,
                                            width: ringed, height: ringed)),
                     with: .color(T.surfaceCard))
        context.fill(Path(ellipseIn: CGRect(x: last.x - markerSize / 2, y: last.y - markerSize / 2,
                                            width: markerSize, height: markerSize)),
                     with: .color(T.accentPrimary))
    }
}
