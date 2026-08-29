// Who owns `isIdleTimerDisabled`, and the reason there has to be an
// owner at all (TODO 281 IO2).
//
// It is a single process-wide boolean with THREE things wanting it: the
// keep-awake setting while the queue is working, the player while a
// video is on screen, and, in future, anything else that needs the
// display up. A boolean with several writers is a last-writer-wins
// race, and the losing write is silent in both directions - a screen
// that sleeps during a download the user asked to keep awake, or one
// that never sleeps again over an empty queue.
//
// THAT WAS LIVE, and it is what this file was written for.
// `PlayerView.onDisappear` set `isIdleTimerDisabled = false`
// unconditionally, so closing the player over a working queue with
// "Keep the screen awake" ON turned the keep-awake off until the next
// poll happened to turn it back on - and `AppState.refresh`'s error arm
// sets it false too, so a single failed poll during playback would put
// the display to sleep mid-video. Neither is visible in a screenshot and
// neither would ever have produced a crash.
//
// The fix is the smallest thing that removes the class rather than the
// two instances: reasons go in, the OR of them comes out, and no caller
// can express "nobody wants the screen" - only "I no longer do".
import Foundation
#if canImport(UIKit)
import UIKit
#endif

@MainActor
enum ScreenAwake {

    /// Why the display is being held up. One case per INDEPENDENT
    /// wanter: two reasons that always arrive together would be one
    /// reason, and two that can overlap must never share a slot.
    enum Reason: String, Hashable {
        /// The keep-awake setting, while there is work to keep awake for.
        case working
        /// A player is on screen. Separate from `working` because a
        /// finished job plays with an idle queue, and a working queue
        /// runs with no player.
        case playing
    }

    private static var held: Set<Reason> = []

    static func hold(_ reason: Reason) {
        held.insert(reason)
        apply()
    }

    static func release(_ reason: Reason) {
        held.remove(reason)
        apply()
    }

    /// Hold or release in one call, for the callers whose reason is a
    /// derived condition re-evaluated on every poll rather than an event.
    static func set(_ reason: Reason, _ on: Bool) {
        if on { hold(reason) } else { release(reason) }
    }

    /// Drop every hold. For teardown only - `disconnect()` - where the
    /// point really is that nothing wants the screen any more.
    static func releaseAll() {
        held.removeAll()
        apply()
    }

    /// True while anything is holding the display up. Read by the
    /// Settings sheet so the toggle's footnote can say what is actually
    /// happening rather than what the setting says.
    static var isHeld: Bool { !held.isEmpty }

    private static func apply() {
        #if canImport(UIKit)
        UIApplication.shared.isIdleTimerDisabled = !held.isEmpty
        #endif
    }
}
