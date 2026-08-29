package app.nzbfast.mobile

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The pause-on-metered rule, all sixteen rows of it.
 *
 * THE ROW THIS FILE EXISTS FOR is [a_user_pause_is_never_adopted]:
 * setting on, network metered, our latch not held, queue ALREADY paused.
 * The shipped rule gated its pause edge on `metered && !pausedForMetered`
 * and nothing else, so that row answered PAUSE - the metered rule
 * adopting a pause the user had asked for. Everything expensive followed
 * from the adoption rather than from the pause: the latch made this rule
 * believe the pause was its own, so a later step back onto Wi-Fi resumed
 * it, and so did turning the SETTING off, which happens while still on
 * cellular - a user-paused download resuming over metered data.
 *
 * HOW THE PRE-FIX FAILURE WAS CONFIRMED: the whole difference between
 * the shipped condition and [meteredAction] is the `!enginePaused` term,
 * and the sixteen-row table was enumerated both ways. Exactly ONE row
 * moves - this one, PAUSE to NONE - so dropping that term from
 * `MeteredPolicy.kt` turns this one case red and leaves the other
 * fifteen green. That is also the check to run if this ever needs
 * re-verifying: delete the term, expect exactly one failure here.
 *
 * The other fifteen are pinned deliberately rather than as padding. The
 * fix narrows one row and MUST NOT narrow any other - in particular the
 * two RESUME rows have to keep firing, or a phone that walks back into
 * Wi-Fi stays paused forever, and `enginePaused` reads true on every one
 * of them because our own pause is what made it true.
 */
class MeteredPolicyTest {

    private fun act(on: Boolean, metered: Boolean, latch: Boolean, paused: Boolean?) =
        meteredAction(
            settingOn = on,
            metered = metered,
            pausedForMetered = latch,
            enginePaused = paused,
        )

    @Test
    fun an_engine_never_observed_refuses_the_pause_edge() {
        // The startup adoption: the network callback is registered
        // before the first poll and Android delivers the current
        // network to it immediately, so at this instant the service has
        // never seen the queue. Reading unknown as "running" is exactly
        // the adoption the `enginePaused` term exists to prevent - the
        // rule waits one poll instead.
        assertEquals(
            MeteredAction.NONE,
            act(on = true, metered = true, latch = false, paused = null),
        )
    }

    @Test
    fun an_engine_never_observed_still_gives_our_own_pause_back() {
        // The RESUME arm is gated on the latch, which means this rule
        // really did the pausing (and, restored from Settings, may hold
        // it across a service restart before any snapshot arrives) - an
        // unknown engine state must not orphan that pause.
        assertEquals(
            MeteredAction.RESUME,
            act(on = false, metered = true, latch = true, paused = null),
        )
        assertEquals(
            MeteredAction.RESUME,
            act(on = true, metered = false, latch = true, paused = null),
        )
    }

    @Test
    fun a_user_pause_is_never_adopted() {
        // The regression. Metered, setting on, nothing held by us, and
        // the queue is stopped because the USER stopped it.
        assertEquals(
            MeteredAction.NONE,
            act(on = true, metered = true, latch = false, paused = true),
        )
    }

    @Test
    fun a_running_queue_on_a_metered_network_is_paused() {
        assertEquals(
            MeteredAction.PAUSE,
            act(on = true, metered = true, latch = false, paused = false),
        )
    }

    @Test
    fun our_own_pause_is_given_back_when_the_network_stops_being_metered() {
        // `paused = true` on both, because our pause is what made it so.
        assertEquals(
            MeteredAction.RESUME,
            act(on = true, metered = false, latch = true, paused = true),
        )
    }

    @Test
    fun our_own_pause_is_given_back_when_the_setting_goes_off() {
        // The one that used to cost money: on cellular still, setting
        // turned off, so the pause has to come back - and with the fix
        // the latch can only be held here if this rule really paused it.
        assertEquals(
            MeteredAction.RESUME,
            act(on = false, metered = true, latch = true, paused = true),
        )
        assertEquals(
            MeteredAction.RESUME,
            act(on = false, metered = false, latch = true, paused = true),
        )
    }

    @Test
    fun a_pause_we_already_hold_is_not_taken_twice() {
        // Idempotent, and it matters: a second pauseAll would be
        // harmless at the engine, but re-posting the metered
        // notification on every capability change is a phone that keeps
        // announcing itself.
        assertEquals(
            MeteredAction.NONE,
            act(on = true, metered = true, latch = true, paused = true),
        )
        assertEquals(
            MeteredAction.NONE,
            act(on = true, metered = true, latch = true, paused = false),
        )
    }

    @Test
    fun nothing_happens_with_the_setting_off_and_no_pause_of_ours() {
        for (metered in listOf(false, true)) {
            for (paused in listOf(false, true)) {
                assertEquals(
                    "off/metered=$metered/paused=$paused",
                    MeteredAction.NONE,
                    act(on = false, metered = metered, latch = false, paused = paused),
                )
            }
        }
    }

    @Test
    fun nothing_happens_on_an_unmetered_network_we_hold_nothing_on() {
        for (paused in listOf(false, true)) {
            assertEquals(
                "unmetered/paused=$paused",
                MeteredAction.NONE,
                act(on = true, metered = false, latch = false, paused = paused),
            )
        }
    }

    /**
     * Every row exactly once, so a rule rewritten in some other shape
     * still has to answer the same sixteen answers. The individual tests
     * above say WHY the interesting rows are what they are; this one
     * makes sure none of the boring ones drifted while nobody was
     * looking at them.
     */
    @Test
    fun the_whole_table() {
        val expected = mapOf(
            // on, metered, latch, enginePaused
            listOf(false, false, false, false) to MeteredAction.NONE,
            listOf(false, false, false, true) to MeteredAction.NONE,
            listOf(false, false, true, false) to MeteredAction.RESUME,
            listOf(false, false, true, true) to MeteredAction.RESUME,
            listOf(false, true, false, false) to MeteredAction.NONE,
            listOf(false, true, false, true) to MeteredAction.NONE,
            listOf(false, true, true, false) to MeteredAction.RESUME,
            listOf(false, true, true, true) to MeteredAction.RESUME,
            listOf(true, false, false, false) to MeteredAction.NONE,
            listOf(true, false, false, true) to MeteredAction.NONE,
            listOf(true, false, true, false) to MeteredAction.RESUME,
            listOf(true, false, true, true) to MeteredAction.RESUME,
            listOf(true, true, false, false) to MeteredAction.PAUSE,
            listOf(true, true, false, true) to MeteredAction.NONE,
            listOf(true, true, true, false) to MeteredAction.NONE,
            listOf(true, true, true, true) to MeteredAction.NONE,
        )
        // `.toLong()` rather than a bare 16: Kotlin does not widen Int to
        // Long for overload resolution, and spelling it out picks
        // JUnit's numeric overload instead of leaving the boxed one to
        // be chosen for us.
        assertEquals("every combination is covered exactly once", 16L, expected.size.toLong())
        for ((row, want) in expected) {
            val (on, metered, latch, paused) = row
            assertEquals(
                "on=$on metered=$metered latch=$latch enginePaused=$paused",
                want,
                act(on = on, metered = metered, latch = latch, paused = paused),
            )
        }
    }
}
