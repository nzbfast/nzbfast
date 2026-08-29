package app.nzbfast.mobile

import android.content.Context
import android.content.Intent
import android.net.Uri

/**
 * The one settings sheet's worth of state, and nothing else.
 *
 * Separate from [Store], which answers "which daemon am I talking to" and
 * is on the identity path. These are product choices - where finished
 * downloads are copied to, whether to hold off on a metered network - and
 * a mistake here costs a preference, not a credential.
 */
object Settings {
    private const val PREFS = "nzbfast"
    private const val KEY_TREE = "export_tree"
    private const val KEY_METERED = "pause_on_metered"
    private const val KEY_METERED_HOLD = "metered_hold"
    private const val KEY_EXPORTED = "exported_ids"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * The user-chosen folder finished downloads are copied to, or null for
     * keep-in-app.
     *
     * AN3's decision, from the plan: downloads land in app-private storage
     * and are EXPORTED, rather than being written straight into a SAF tree.
     * A document URI is not a file: it has no `pwrite`, no preallocation
     * and no cheap re-open, so a one-pass writer aimed at one loses range
     * writes and preallocation both. Copying a finished payload out is a
     * sequential read and a sequential write, which is the one thing SAF
     * is good at.
     */
    fun exportTree(ctx: Context): Uri? =
        prefs(ctx).getString(KEY_TREE, null)?.let(Uri::parse)

    /**
     * Remember a tree the user picked, and TAKE the persistable grant.
     *
     * Without `takePersistableUriPermission` the grant dies with this
     * activity's task, so an export that worked when the folder was chosen
     * fails silently after the next cold start - and the service, which is
     * where the export actually runs, never had the grant at all.
     */
    fun setExportTree(ctx: Context, uri: Uri?) {
        if (uri == null) {
            prefs(ctx).edit().remove(KEY_TREE).apply()
            return
        }
        runCatching {
            ctx.contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }
        prefs(ctx).edit().putString(KEY_TREE, uri.toString()).apply()
    }

    /** Hold the queue while the phone is on a metered network. */
    fun pauseOnMetered(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_METERED, false)

    fun setPauseOnMetered(ctx: Context, on: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_METERED, on).apply()
    }

    /**
     * Whether the metered rule is currently HOLDING a pause it owes back.
     *
     * Persisted because the pause itself is: the daemon restores its
     * paused state across a restart, while the in-memory latch died with
     * the process - so a metered pause that outlived the service could
     * never be resumed by the policy again (the RESUME arm requires the
     * latch, and the PAUSE arm's already-paused guard stopped it being
     * re-taken). The iOS side persists its `.background` hold marker for
     * the same reason.
     */
    fun meteredHold(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_METERED_HOLD, false)

    fun setMeteredHold(ctx: Context, on: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_METERED_HOLD, on).apply()
    }

    /**
     * Jobs whose payload has already been copied to the export tree.
     *
     * Kept because the export runs off a POLL of the history list, and a
     * finished row stays in that list: without a record, every poll would
     * re-copy every finished job for as long as the row survives. Keyed by
     * nzo_id, which the daemon does not reuse.
     *
     * Bounded at [EXPORTED_CAP] entries, oldest dropped, so a long-lived
     * install cannot grow this without limit. Dropping the oldest is safe
     * in the direction that matters: the worst case is one extra copy of a
     * job old enough to have fallen off the end of a history page, and
     * [Exporter] skips a destination file that already exists anyway.
     */
    fun isExported(ctx: Context, nzoId: String): Boolean =
        exportedIds(ctx).contains(nzoId)

    fun markExported(ctx: Context, nzoId: String) {
        val cur = exportedIds(ctx).toMutableList()
        if (cur.contains(nzoId)) return
        cur.add(nzoId)
        while (cur.size > EXPORTED_CAP) cur.removeAt(0)
        // Stored as one ordered string rather than a StringSet, because a
        // set has no order and dropping "the oldest" out of one is not a
        // thing that can be done.
        prefs(ctx).edit().putString(KEY_EXPORTED, cur.joinToString("\n")).apply()
    }

    private const val EXPORTED_CAP = 500

    private fun exportedIds(ctx: Context): List<String> =
        prefs(ctx).getString(KEY_EXPORTED, "")
            ?.split('\n')
            ?.filter { it.isNotEmpty() }
            ?: emptyList()
}
