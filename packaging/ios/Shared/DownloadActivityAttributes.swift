// The shape of the lock-screen and Dynamic Island activity (TODO 281
// IO2), shared by the app that starts it and the widget extension that
// draws it.
//
// ONE FILE IN TWO TARGETS, not two copies. ActivityKit matches a running
// activity to its presentation by the ATTRIBUTES TYPE, so the app and
// the extension have to agree exactly; two declarations that drift by a
// field are an activity that starts and never appears, with no error
// anywhere. `packaging/ios/Shared/` is a file-system synchronized group
// listed in BOTH targets for that reason, and it is the only thing in
// it.
//
// WHY IT FREEZES, which is the whole editorial decision behind this
// file. With the app suspended nothing here updates, so the bar stops
// where it was. That is TRUTHFUL and is the point: an activity that kept
// animating over a suspended engine would be telling the user their
// download was running when it was not, which is the single complaint
// this whole category of app collects. What the app does instead is push
// one FINAL update on its way out saying the queue is held - see
// `LiveProgress.hold` - so the frozen state reads as "waiting for you"
// rather than as a progress bar that mysteriously stopped.
import Foundation
import ActivityKit

@available(iOS 16.2, *)
struct DownloadActivityAttributes: ActivityAttributes {

    /// What changes while the activity is up.
    public struct ContentState: Codable, Hashable {
        /// 0...1. Weighted by BYTES across the queue rather than an
        /// average of per-job percentages - a 40 GB job at 10% beside a
        /// 200 MB one at 90% is not halfway done. The same figure the
        /// Home headline shows, computed in one place.
        var fraction: Double
        /// Bytes per second, 0 when held.
        var speedBps: Double
        /// The daemon's own words for how long is left, passed through
        /// rather than recomputed.
        var timeLeft: String?
        /// How many jobs the fraction covers, so one job can be named
        /// and several can be counted.
        var jobCount: Int
        /// Set while the app is suspended or the queue is otherwise
        /// held. It is what turns a frozen bar into an honest one.
        var held: Bool
        /// Why it is held, in the user's language, or nil.
        var holdReason: String?
    }

    /// The lead job's name, fixed for the life of the activity. In the
    /// attributes rather than the state because a queue whose front job
    /// changes should get a new activity rather than silently relabel
    /// the one on the lock screen.
    var leadJobName: String
}
