package app.nzbfast.mobile

// The pause-on-metered decision, as arithmetic with no Android in it.
//
// WHY IT LIVES ON ITS OWN. `EngineService` asks this question from TWO
// places that learn their inputs differently - the default-network
// callback, which is told whether the new network is metered, and
// `applyMeteredPolicy`, which reads the current network because the
// SETTING moved rather than the network. Until 28 Aug 2026 those two
// sites each spelled the boolean algebra out by hand, and they were
// hand-copied siblings of each other: the same rule written twice, which
// is the shape this repo has been bitten by often enough to have gates
// about. Both of them were also WRONG in the same way, and the fix had
// to land in both - see `meteredAction` below.
//
// It is a file of its own, and not a member of `EngineService`, so that
// the host-side JUnit test can exercise it without loading a
// `android.app.Service` subclass. That is the whole reason a rule this
// small is not just an `if` at each call site.

/** What the metered policy wants done to the engine's global pause. */
enum class MeteredAction {
    /** Leave it exactly as it is. */
    NONE,

    /** Pause, and take the metered latch: this rule owns the pause. */
    PAUSE,

    /** Resume, and drop the latch: this rule is giving its pause back. */
    RESUME,
}

/**
 * Decide what the metered policy should do.
 *
 * @param settingOn        `Settings.pauseOnMetered` as it stands NOW,
 *                         read at decision time and never captured - a
 *                         network callback outlives the setting value it
 *                         was registered under.
 * @param metered          whether the network the engine's sockets are
 *                         on is metered.
 * @param pausedForMetered whether THIS rule is already holding a pause.
 * @param enginePaused     whether the engine's queue reads paused, from
 *                         the last snapshot the service rendered.
 *
 * THE `enginePaused` TERM IS THE FIX, and it is the reason this function
 * exists at all. Before it, both call sites gated the PAUSE edge on
 * `metered && !pausedForMetered` alone, with no idea whether the queue
 * was already stopped - so a queue the USER had paused took the metered
 * latch the moment the phone stepped onto cellular, and this rule then
 * believed it owned that pause. Everything downstream followed: a later
 * walk back into Wi-Fi resumed it, and so did turning the setting off,
 * which is the worst of the two because turning the setting off happens
 * WHILE STILL ON CELLULAR - a user-paused download resuming over
 * metered data, which costs real money. The comments at both sites
 * claimed "a pause the user asked for is never touched"; the latch alone
 * could never have made that true, and it now is: the RESUME arms are
 * gated on `pausedForMetered`, and with this term the latch can only
 * ever be set over a queue this rule really paused.
 *
 * The iOS side has had the equivalent guard since IO2 - see
 * `AppState.hold`, which refuses the hold when `snapshot?.paused` is
 * already true, for exactly this reason.
 *
 * STALENESS IS ACCEPTED AND BOUNDED, stated rather than papered over.
 * `enginePaused` comes from the service's own poll, so it is up to one
 * poll interval old: a user pause in the second before a network change
 * can still be latched over. That window is what it is on purpose -
 * asking the engine over HTTP at decision time would put a network
 * round trip inside a `ConnectivityManager` callback, and the answer
 * would be stale by a different amount rather than not stale. It is
 * strictly narrower than the previous behaviour, which had no guard at
 * any staleness, and it is the same window iOS accepts.
 *
 * `null` MEANS NEVER OBSERVED, and it is not the bounded staleness
 * above: the network callback is registered before the service's first
 * poll ever renders a snapshot, and Android delivers the current
 * network to a fresh default callback immediately - so a rule that read
 * unknown as "running" adopted a pause the user had left in place
 * before the service started. The PAUSE edge waits for the first
 * snapshot instead. The RESUME arm deliberately does not: it is already
 * gated on the latch, which means this rule really did the pausing, and
 * an unknown engine state must not stop it giving its own pause back.
 */
fun meteredAction(
    settingOn: Boolean,
    metered: Boolean,
    pausedForMetered: Boolean,
    enginePaused: Boolean?,
): MeteredAction = when {
    // Do not stack a second pause over our own: the latch is what makes
    // the resume arm below able to tell whose pause it is giving back.
    // `== false`, not `!`: an engine never yet observed refuses this
    // edge rather than assuming a running queue.
    settingOn && metered && !pausedForMetered && enginePaused == false -> MeteredAction.PAUSE
    // Give ours back when either half of the reason for it has gone. Not
    // guarded on `enginePaused`: this arm only ever runs when the latch
    // is held, which now means this rule really did the pausing, so
    // there is nobody else's pause here to protect.
    pausedForMetered && (!settingOn || !metered) -> MeteredAction.RESUME
    else -> MeteredAction.NONE
}
