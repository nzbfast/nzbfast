import Foundation
import ParfastCore

/// The last couple of minutes of a job's read rate, so the progress sheet can
/// answer "is it going fast" and "is it slowing down" instead of only "how fast
/// is it right now".
///
/// Section 4 of the 12 September 2026 prettiness review, chart (b), ported from
/// `Parfast.ViewModels/RateHistory.cs` rather than re-derived, because every
/// decision below was argued there and the two apps must draw the same series.
///
/// `JobSnapshot.rate_bytes_per_s` arrives on every snapshot and the sheet used to
/// print it and throw the previous value away. This is the ring buffer that keeps
/// them, and it is the only new DATA in the whole charts change - the other two
/// charts draw numbers that were already on the wire.
///
/// THE X AXIS IS THE ENGINE'S OWN CLOCK, ONE SLOT PER ELAPSED SECOND, NOT ONE
/// SLOT PER SNAPSHOT. This is the decision in this chart worth reading. Snapshots
/// do not arrive on a clock: the core promises at most about twenty wakes a
/// second, `AppModel`'s poll coalesces a burst of them into one refresh, and a
/// busy main actor can miss several in a row. A chart fed one sample per snapshot
/// therefore has an x axis of POLLS, which stretches and compresses time
/// silently - so a real slowdown and a poll gap draw identically. Bucketing by
/// `elapsed_ms` costs nothing, needs no timer of its own, uses a clock the engine
/// already guarantees is monotone, and makes the series deterministic under test.
///
/// A SECOND WITH NO SNAPSHOT IS CARRIED FORWARD, up to `maxCarry` seconds, and
/// past that the history is CLEARED rather than bridged. Carrying one or two
/// seconds keeps the axis a real time axis and claims only "as far as the UI could
/// see, the rate did not change", which is the truth about a step-sampled series.
/// Bridging a ten second stall would manufacture a long flat plateau nobody
/// observed. Clearing is honest and visibly different: the chart starts again.
///
/// A CLASS AND NOT A STRUCT, unlike the other two chart models, because it is
/// STATE that has to outlive the view. `ProgressSheet` is a struct rebuilt on
/// every snapshot; the history is held in a `@StateObject` beside it so the ring
/// survives the rebuild. The other two models are derived wholly from the
/// snapshot in hand and have nothing to remember.
@MainActor
final class RateHistory: ObservableObject {

    /// How many one-second slots are kept: two minutes of history.
    ///
    /// A sparkline is a shape rather than a measurement, and two minutes is the
    /// window over which "it was faster a moment ago" is a useful thing to see. A
    /// longer window on a strip this wide would put several seconds in a point and
    /// flatten exactly the dip it is there to show.
    static let capacity = 120

    /// The longest run of unobserved seconds this will fill in before giving up
    /// and clearing. See the type's own note.
    static let maxCarry = 4

    /// How much of the way the drawn y scale moves toward a new window maximum per
    /// second.
    ///
    /// The VU-meter rule the nzbfast dashboard's own throughput chart uses: scale
    /// UP instantly so an incoming spike is never clipped, and decay DOWN gently
    /// so the whole chart does not re-scale under a spiky series - which reads as
    /// judder rather than as information. That chart decays per ANIMATION FRAME;
    /// this one advances once per SAMPLE, which is once per second, so the
    /// fraction is much larger for the same settling time: at 0.35 a scale that
    /// has to fall settles most of the way in about three seconds.
    static let scaleDecayPerSecond: Double = 0.35

    private var slots = [Int64](repeating: 0, count: RateHistory.capacity)
    private var start = 0
    private var displayMaxValue: Double = 0
    private var lastSecond: Int64 = -1
    /// Which job the samples belong to, so `apply(_:)` can tell a fresh snapshot
    /// of the same job from the first snapshot of a different one.
    private var jobId: Int64?

    /// How many seconds of history are held.
    private(set) var count = 0

    /// Whether the y scale eases toward a falling window maximum, or snaps to it.
    ///
    /// The view sets this from `accessibilityReduceMotion`, and the easing is the
    /// only motion this chart has, so turning it off leaves a chart that is still
    /// entirely correct and merely steps rather than glides. It lives HERE rather
    /// than in the view so the behaviour is testable without a window.
    var smoothScale = true

    init() {}

    /// True once there is a shape to draw at all.
    var hasShape: Bool { count >= 2 && peak > 0 }

    /// The newest sample, in bytes per second.
    var current: Int64 { count == 0 ? 0 : self[count - 1] }

    /// The largest sample held.
    var peak: Int64 {
        var best: Int64 = 0
        for i in 0..<count { best = max(best, self[i]) }
        return best
    }

    /// Sample `index`, oldest first.
    subscript(index: Int) -> Int64 { slots[(start + index) % Self.capacity] }

    /// The y scale the chart should draw against right now: at least the visible
    /// peak, eased downward when it falls.
    ///
    /// Never zero, so a series of zeroes draws a flat line along the bottom rather
    /// than dividing by nothing. A job whose engine reports no rate at all is
    /// answered by `hasShape` instead - the chart is not shown, because there is
    /// nothing to show and a flat line at the floor would read as a stall.
    var displayMax: Double { max(displayMaxValue, 1) }

    /// Takes a snapshot's rate, bucketed into the elapsed second it belongs to.
    ///
    /// - Parameters:
    ///   - elapsedMs: The job's own elapsed clock.
    ///   - rateBytesPerS: Its instantaneous rate.
    func push(elapsedMs: Int64, rateBytesPerS: Int64) {
        let second = max(0, elapsedMs) / 1000
        let rate = max(0, rateBytesPerS)

        if count == 0 {
            append(rate)
            lastSecond = second
            rescale()
            return
        }

        if second == lastSecond {
            // Several snapshots inside one second: the LATEST reading wins rather
            // than an average of them. The slot means "the rate as of this
            // second", and averaging would quietly smooth the series before the
            // chart's own smoothing got to it.
            slots[(start + count - 1) % Self.capacity] = rate
            rescale()
            return
        }

        if second < lastSecond {
            // The clock went backwards, which means this is a different run of
            // the job than the samples already held. Drawing across that would
            // join two unrelated series into one line.
            restart(with: rate, at: second)
            return
        }

        let missing = Int(second - lastSecond - 1)
        if missing > Self.maxCarry {
            restart(with: rate, at: second)
            return
        }

        let carry = current
        for _ in 0..<missing { append(carry) }
        append(rate)
        lastSecond = second
        rescale()
    }

    /// Takes one snapshot of the job the sheet is showing, and is the ONLY thing
    /// the view calls.
    ///
    /// The two rules that are easy to get wrong live here rather than in the
    /// sheet, so both are testable without a window and neither depends on the
    /// order SwiftUI happens to fire two `onChange` modifiers in - which was the
    /// first shape of this wiring and was a race between a push and a reset on
    /// the frame a second job opened.
    ///
    ///  * A NEW JOB CLEARS. The sheet is reused, and inheriting the shape of the
    ///    previous job would draw a history that never happened. Tracked by id
    ///    here, so "same sheet, different job" is one comparison in one place.
    ///  * A FINISHED JOB IS NOT PUSHED. Its last snapshot arrives on every poll
    ///    for as long as the sheet is open, so pushing unconditionally grows a
    ///    flat tail claiming the job is still running at the rate it stopped at.
    func apply(_ job: JobSnapshot) {
        if job.id != jobId {
            reset()
            jobId = job.id
        }
        guard job.state == .running, let rate = job.rate_bytes_per_s else { return }
        push(elapsedMs: job.elapsed_ms, rateBytesPerS: rate)
    }

    /// Throws the history away, for a new job in the same sheet.
    func reset() {
        count = 0
        start = 0
        lastSecond = -1
        displayMaxValue = 0
    }

    /// The most recent `maxSamples` samples, oldest first.
    ///
    /// The view asks for as many as it has points to give them, at two points a
    /// sample, so a narrow strip draws a shorter window rather than several
    /// seconds per point.
    func visible(_ maxSamples: Int) -> [Int64] {
        let take = min(max(maxSamples, 0), count)
        return (0..<take).map { self[count - take + $0] }
    }

    /// How the current rate compares with the median of the history, as a signed
    /// fraction, or nil while there is too little history to say.
    ///
    /// THE MEDIAN AND NOT THE MEAN, because the series this runs over is spiky by
    /// nature: one stalled second at zero drags a mean of twenty samples down by
    /// five per cent and would report a slowdown that did not happen. The median
    /// is unmoved by it.
    ///
    /// It answers the second half of the question the chart is here for. A shape
    /// says "slowing down" to somebody looking at it; this says the same thing in
    /// a sentence, which is what VoiceOver gets and what the line beside the chart
    /// prints.
    var trend: Double? {
        // Fifteen seconds before it says anything. A comparison over the first
        // three samples of a job flaps between large positive and large negative
        // numbers while the engine's own rate estimate is settling, and a figure
        // that flickers is read as the app being confused rather than the job
        // being uneven.
        guard count >= 15 else { return nil }
        let sorted = (0..<count).map { self[$0] }.sorted()
        let median = sorted.count % 2 == 1
            ? Double(sorted[sorted.count / 2])
            : Double(sorted[sorted.count / 2 - 1] + sorted[sorted.count / 2]) / 2
        guard median > 0 else { return nil }
        return (Double(current) - median) / median
    }

    /// The trend in words, or an empty string when there is not enough history.
    ///
    /// A band around zero reads as steady rather than as a tiny change in a
    /// direction: the rate wobbles by a few per cent under normal disk behaviour
    /// and labelling that "3% slower" invites a reader to chase noise.
    var trendText: String {
        guard let trend else { return "" }
        if abs(trend) < 0.08 { return S.progressRateSteady }
        // `Fmt.percent` does not clamp and takes a figure already out of a
        // hundred, which is what this needs: a job running at five times the
        // median is "500% faster". The Windows app has a second formatter that
        // DOES clamp to 0..1 and using it there would have understated exactly
        // this case by a factor of four; the mac has no such pair, and this
        // comment is why nobody should add one.
        let percent = Fmt.percent(abs(trend) * 100, decimals: 0)
        return trend > 0
            ? S.progressRateFaster(percent: percent)
            : S.progressRateSlower(percent: percent)
    }

    // MARK: - Internals

    private func restart(with rate: Int64, at second: Int64) {
        reset()
        append(rate)
        lastSecond = second
        rescale()
    }

    private func append(_ value: Int64) {
        if count < Self.capacity {
            slots[(start + count) % Self.capacity] = value
            count += 1
            return
        }
        slots[start] = value
        start = (start + 1) % Self.capacity
    }

    private func rescale() {
        let target = Double(peak)
        if !smoothScale || displayMaxValue <= 0 || target >= displayMaxValue {
            displayMaxValue = target
            return
        }
        let eased = displayMaxValue + (target - displayMaxValue) * Self.scaleDecayPerSecond
        // Snap when it is within a fraction of a per cent, or the scale creeps
        // downward for ever and the chart never settles.
        displayMaxValue = target > 0 && (eased - target) / target < 0.002 ? target : eased
    }
}
