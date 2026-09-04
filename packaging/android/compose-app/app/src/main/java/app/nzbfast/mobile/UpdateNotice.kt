package app.nzbfast.mobile

import android.content.Context

// "A newer nzbfast is out", for a phone that cannot be told any other way.
//
// WHY THIS EXISTS. Every other shipped surface learns about a release
// from the daemon it is attached to: the desktop dashboard draws a banner
// off the queue payload, and the daemon's own log says so every six
// hours. This app draws neither - it never read the banner state and the
// engine's log is inside app-private storage - so an Android user's only
// notice was the release page, by hand. v1.4.0 is the first release to
// publish the APK at all, which is what makes that gap worth closing now.
//
// NOTIFY ONLY, and that is a hard boundary rather than a first cut.
// Android cannot silently replace its own package: an in-app install
// needs REQUEST_INSTALL_PACKAGES, which is a permission this app does not
// ask for and will not. So nothing here downloads, verifies or installs
// anything. It reads a version number off the daemon and offers a link.
// The engine has had no apply path of its own since self-update was
// removed in 1.0.5 (update.rs `DOWNLOAD_URL`), and this is the same
// posture on the phone.
//
// The arithmetic lives here, with no Android in it, for the reason
// [meteredAction] does: the host-side JUnit test then exercises exactly
// the rule the app runs, with no emulator and no Context.

/**
 * Where the notice sends people. The same page the desktop banner uses
 * (update.rs `DOWNLOAD_URL` is its `/latest` form), and hard-coded for
 * the same reason: the manifest carries a version string and never a
 * link, so a compromised update channel cannot redirect anyone.
 */
const val RELEASES_URL = "https://github.com/nzbfast/nzbfast/releases"

/** A day. The cadence a foreground check is allowed to ask again at. */
const val UPDATE_CHECK_INTERVAL_MS: Long = 24 * 60 * 60 * 1000

/**
 * The retry after a check that did not answer, which is a different
 * number on purpose: a phone that was offline, or an engine that had not
 * finished coming up, has learned nothing, and making it wait a full day
 * to find that out again would mean most installs check far less often
 * than daily. An hour is short enough to catch the next time the phone is
 * somewhere with a network and long enough that repeatedly opening the
 * app while offline is not a poll loop.
 */
const val UPDATE_RETRY_INTERVAL_MS: Long = 60 * 60 * 1000

/**
 * Dotted-numeric compare: is `remote` newer than `local`? The Kotlin twin
 * of `version_newer` in crates/nzbfast-daemon/src/update.rs, down to the
 * details that look like slop and are not - a leading `v` is stripped,
 * `-` splits like `.` so "1.4.0-beta" compares equal to "1.4.0", and a
 * fragment that is not a number counts as 0 rather than throwing.
 *
 * The app runs this over the daemon's answer even though the daemon has
 * already compared: see [app.nzbfast.mobile.api.UpdateStatus] for why the
 * two comparisons are against different versions in server mode.
 */
fun updateIsNewer(remote: String, local: String): Boolean {
    fun parse(s: String): List<Long> =
        s.trimStart('v', 'V').split('.', '-').map { it.toLongOrNull() ?: 0L }
    val r = parse(remote)
    val l = parse(local)
    for (i in 0 until maxOf(r.size, l.size)) {
        val a = r.getOrElse(i) { 0L }
        val b = l.getOrElse(i) { 0L }
        if (a != b) return a > b
    }
    return false
}

/**
 * Whether a foreground check may run now.
 *
 * The second arm is the clock-moved-backwards guard. The deadline is
 * stored as an absolute wall-clock instant, and `System.currentTimeMillis`
 * is not monotonic - a phone that picks up NTP after a flat battery, or
 * one whose date was set forward by hand and then corrected, can leave a
 * deadline arbitrarily far in the future and never check again for as
 * long as the install lives. Any stored deadline further out than the
 * longest interval we would ever write is therefore junk, and junk means
 * due.
 */
fun updateCheckDue(nowMs: Long, nextCheckAtMs: Long): Boolean =
    nowMs >= nextCheckAtMs || nextCheckAtMs - nowMs > UPDATE_CHECK_INTERVAL_MS

/**
 * The remembered half: when to ask again, the newest version we have been
 * told about, and which version the user has waved away.
 *
 * Its own prefs keys in the same file [Settings] uses. Nothing here is a
 * credential and nothing here is on the identity path - the worst a wrong
 * value can do is show a notice a day late or a day early.
 */
object UpdateNotice {
    private const val PREFS = "nzbfast"
    private const val KEY_NEXT = "update_next_check"
    private const val KEY_AVAILABLE = "update_available"
    private const val KEY_DISMISSED = "update_dismissed"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun due(ctx: Context, nowMs: Long): Boolean =
        updateCheckDue(nowMs, prefs(ctx).getLong(KEY_NEXT, 0L))

    fun recordChecked(ctx: Context, nowMs: Long) {
        prefs(ctx).edit().putLong(KEY_NEXT, nowMs + UPDATE_CHECK_INTERVAL_MS).apply()
    }

    fun recordFailed(ctx: Context, nowMs: Long) {
        prefs(ctx).edit().putLong(KEY_NEXT, nowMs + UPDATE_RETRY_INTERVAL_MS).apply()
    }

    /** The newest version this install has been told about, or null. */
    fun available(ctx: Context): String? =
        prefs(ctx).getString(KEY_AVAILABLE, null)?.ifEmpty { null }

    /**
     * Latch what the last check found. Persisted rather than held in
     * memory so the Settings row can answer on a cold start, hours after
     * the check that learned it, without asking the network again.
     */
    fun setAvailable(ctx: Context, version: String?) {
        val e = prefs(ctx).edit()
        if (version == null) e.remove(KEY_AVAILABLE) else e.putString(KEY_AVAILABLE, version)
        e.apply()
    }

    /** The version whose banner the user has waved away, or null. */
    fun dismissed(ctx: Context): String? =
        prefs(ctx).getString(KEY_DISMISSED, null)?.ifEmpty { null }

    /**
     * Dismissal is PER VERSION, not a mute. The next release raises the
     * banner again - which is the whole point of the feature - and this
     * one stays gone. The Settings row keeps showing it either way, so a
     * dismissal loses nothing but the banner.
     */
    fun dismiss(ctx: Context, version: String) {
        prefs(ctx).edit().putString(KEY_DISMISSED, version).apply()
    }
}
