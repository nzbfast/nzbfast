package app.nzbfast.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import app.nzbfast.mobile.api.NzbfastClient
import app.nzbfast.mobile.api.PlaybackJob
import app.nzbfast.mobile.api.PlaybackSnapshot
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Foreground service hosting the on-device engine. The binary ships as
 * libnzbfast.so in jniLibs; with legacy packaging the installer puts a
 * real file in nativeLibraryDir, and exec from there is the
 * post-API-29-legal way to run a bundled binary. Same mechanism as the
 * proven packaging/android/app test APK.
 *
 * The daemon binds 127.0.0.1 only, on a port the OS chooses. Downloads
 * land in filesDir/downloads; [Exporter] copies finished payloads out to
 * a folder the user picked (TODO 281 AN3).
 *
 * TODO 281 AN2 made this a real downloader service rather than a shell
 * that starts a process. THREE THINGS COME WITH THAT, and each of them is
 * something no other part of the app can do:
 *
 *   - IT POLLS THE DAEMON ITSELF. The notification is the only surface a
 *     user who has left the app can see, so it has to be right when there
 *     is no activity at all - which means the poll behind it cannot live
 *     in one. It is a SECOND poll, slower than the activity's (see
 *     [POLL_MS]), and the duplication is deliberate: the two have
 *     different lifetimes, and a loopback GET of a few kilobytes is not
 *     worth coupling them over.
 *   - IT HOLDS A WAKELOCK WHILE WORK IS RUNNING. A foreground service is
 *     not exempt from suspend: without one, the CPU sleeps when the
 *     screen goes off and the download stops with the notification still
 *     claiming otherwise.
 *   - IT STOPS WHEN THE QUEUE DRAINS. The daemon answers that question
 *     itself, on `queue_idle` (contract addition, TODO 281 AN2), and the
 *     reason to ask rather than to look at an empty list is written up at
 *     that key in api/playback.rs: a job that has finished downloading is
 *     out of the queue and not yet in history for the whole length of its
 *     repair, extract and move.
 */
class EngineService : Service() {

    companion object {
        private const val CHANNEL = "engine"
        private const val NOTE_ID = 1

        /**
         * The notification poll cadence. Slower than the activity's 2 s
         * because nobody is watching a notification tick: it wants to be
         * right within a few seconds of a change, not to animate.
         */
        private const val POLL_MS = 5_000L

        /**
         * How many consecutive idle polls end the service.
         *
         * `queue_idle` is already the daemon's own settled answer, so this
         * is not covering a race in it. What it covers is the OTHER end -
         * the moment right after the user adds something, where the add
         * has been accepted but this service's poll has not come round
         * yet, and one stray idle reading would tear the engine down under
         * a job that is about to start. Two readings at [POLL_MS] apart
         * cannot both land in that window.
         */
        private const val IDLE_POLLS_TO_STOP = 2

        /** One spelling of the metered hold, so the message the hold
         *  posts and the one the next poll re-posts are the same
         *  sentence. */
        private const val METERED_TEXT = "Held: this network is metered."

        /**
         * How many on-device engine generations have ENDED, bumped by
         * [watchEngine] the moment one does.
         *
         * The UI holds a [Connection] naming a PORT, and the port outlives
         * the process that bound it: every app on a phone shares one
         * loopback namespace, so whatever binds next inherits an endpoint
         * this app is still sending the install's full API key to, in
         * `X-Api-Key`, every two seconds. That is the disclosure
         * [EngineIdentity] exists to prevent, arriving one engine
         * generation later (Codex sweep 26 Aug, P1-2). A collector - see
         * MainActivity - drops the credential here and re-enters the
         * proof path.
         *
         * A count rather than a flag, so two exits in a row are two
         * events; and process-wide rather than a binder, because the
         * service and the activity are one process and the activity may
         * not exist when the engine goes.
         */
        private val exits = MutableStateFlow(0)
        val engineExits: StateFlow<Int> = exits.asStateFlow()

        /**
         * Whether the app is IN USE - which is not the same as "an
         * activity is between onStart and onStop", and the difference
         * cost a real defect on the emulator.
         *
         * The service reads it for ONE decision: whether draining the
         * queue may stop the engine. Stopping it under a visible Home
         * screen would show the user an engine that died for no reason
         * they can see, and the activity's own reconnect path would then
         * start it again - a loop with a notification flickering through
         * it. Off screen there is nobody to confuse and the engine is
         * pure battery cost, so that is where it goes.
         *
         * THE FILE PICKER IS THE CASE THAT MAKES THIS SUBTLE. Choosing an
         * NZB or an export folder opens a SYSTEM activity, so ours stops -
         * and if the queue happens to be idle at that moment, which it is
         * every time somebody adds their first job, the engine was torn
         * down while they were still browsing. Seen 26 Aug 2026 on the
         * emulator, mid-pick, exactly that way. So MainActivity holds this
         * true across a picker it launched itself, and only a real
         * departure clears it.
         */
        private val foreground = MutableStateFlow(false)

        fun setForeground(on: Boolean) {
            foreground.value = on
        }

        /**
         * Bumped when [Settings.pauseOnMetered] changes, so a running
         * service applies the policy against the network the phone is on
         * NOW. The network callback only fires on a capability CHANGE:
         * without this, enabling the setting on an already-metered
         * network holds nothing until the network next moves, and
         * disabling it leaves a [pausedForMetered] pause standing (Codex
         * sweep 27 Aug, C15). Same shape as [foreground]: process-wide,
         * because the activity may not hold a binder to the service.
         */
        private val meteredPolicyEpoch = MutableStateFlow(0)

        fun notifyMeteredPolicyChanged() {
            meteredPolicyEpoch.update { it + 1 }
        }

        /** One API key per install, minted on first use. */
        fun apiKey(ctx: Context): String {
            val p = ctx.getSharedPreferences("nzbfast", Context.MODE_PRIVATE)
            p.getString("apikey", null)?.let { return it }
            val b = ByteArray(24)
            SecureRandom().nextBytes(b)
            val k = b.joinToString("") { "%02x".format(it) }
            p.edit().putString("apikey", k).apply()
            return k
        }
    }

    @Volatile private var engine: Process? = null

    /** Set before a stop WE perform, so [watchEngine] can tell an engine
     *  that died from one this service shut down. The Mac wrapper's
     *  `deliberateStop` and the Windows tray's restart latch are the same
     *  distinction. */
    @Volatile private var stopping = false

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var wakeLock: PowerManager.WakeLock? = null
    private var meteredCallback: ConnectivityManager.NetworkCallback? = null

    private var idleStreak = 0

    /**
     * The most recent start command, so [checkIdle] can stand down with
     * `stopSelfResult` rather than `stopSelf`.
     *
     * The difference is the whole race: `stopSelf` stops even when a start
     * command has arrived since, which is the activity coming back to a
     * queue that has just drained - it would ask for an engine and get one
     * torn down a moment later. `stopSelfResult` refuses when it is not
     * the latest start, which is exactly the question being asked.
     */
    @Volatile private var lastStartId = 0
    private var stopRequested = false

    /** Whether the queue was paused BY US for a metered network, so an
     *  unmetered network resumes only what this rule paused and never a
     *  pause the user asked for.
     *
     *  THAT SECOND CLAUSE WAS FALSE AS WRITTEN until 28 Aug 2026, and
     *  the latch alone could never have made it true: nothing stopped
     *  the latch being TAKEN over a queue the user had already paused,
     *  after which "only what this rule paused" was a statement about a
     *  pause this rule had merely adopted. It holds now because the
     *  pause edge consults [enginePaused] too - see [meteredAction].
     *
     *  `@Volatile` for the same reason as [enginePaused], and it needs
     *  its own marker rather than riding that one's: both call sites
     *  read this field BEFORE the volatile one, and an acquire does not
     *  order a read that precedes it. Seeded from [Settings.meteredHold]
     *  in [onCreate] and written back beside every transition, because
     *  the pause it tracks is persisted by the daemon across a restart
     *  while this field alone would die with the process - after which
     *  the RESUME arm could never fire (it requires the latch) and the
     *  PAUSE arm could never re-take it (the queue reads paused). */
    @Volatile private var pausedForMetered = false

    /**
     * Whether the engine's queue reads paused, from the last snapshot
     * [render] drew - or `null` before any snapshot has ever been
     * rendered. Read by the metered PAUSE edge so it cannot take
     * [pausedForMetered] over a pause the user asked for.
     *
     * `null` IS NOT `false`, and the distinction is the startup half of
     * that guard: [watchMetered] is registered before the first poll,
     * and Android delivers the current network to a fresh default
     * callback immediately - so a `false` start value let that first
     * callback adopt a pause the user had left in place before the
     * service ever observed the queue. Unknown refuses the PAUSE edge
     * (see [meteredAction]) and the rule simply waits one poll.
     *
     * `@Volatile` because it is written from the poll loop's coroutine
     * and read from the network callback's, which are different
     * coroutines on the IO dispatcher and so potentially different
     * threads.
     *
     * Kept in step with our OWN pause and resume at the moment we issue
     * them, rather than waiting up to a poll for [render] to confirm
     * them. That is not an optimisation: without it a fast Wi-Fi ->
     * cellular bounce reads a stale `true` left over from our own
     * just-released pause and REFUSES the next legitimate metered
     * pause, which is the expensive direction to be wrong in.
     */
    @Volatile private var enginePaused: Boolean? = null

    override fun onCreate() {
        // Before the poll loop and before [watchMetered] can fire: a
        // metered pause the previous process took is still in force in
        // the daemon (it persists its paused state), so the ownership
        // latch has to come back with it or the pause is orphaned - the
        // RESUME arm requires the latch and the PAUSE arm's
        // already-paused guard stops it ever being re-taken.
        pausedForMetered = Settings.meteredHold(this)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Downloads", NotificationManager.IMPORTANCE_LOW)
        )
        // drop(1): the current epoch value is not a change.
        scope.launch {
            meteredPolicyEpoch.drop(1).collect { applyMeteredPolicy() }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        stopping = false
        lastStartId = startId
        stopRequested = false
        val n = notification("Starting the engine", null, 0)
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            } else {
                startForeground(NOTE_ID, n)
            }
        } catch (e: Exception) {
            // Android 12 and later refuse a foreground service started
            // from the background, and START_STICKY means the system can
            // deliver this call with no activity anywhere. An uncaught
            // refusal there is a crash the user sees for having done
            // nothing; standing down is the honest answer, and the next
            // time they open the app the engine starts and the journal
            // picks the job back up.
            stopSelf()
            return START_NOT_STICKY
        }
        startEngine()
        startWatching()
        return START_STICKY
    }

    // ---- the notification ----

    /**
     * The one foreground notification.
     *
     * [progressPct] null means indeterminate-free: no bar at all, which is
     * what an idle or starting engine should show. A user who is not in
     * the app sees only this, so it must never go on claiming work that
     * has finished.
     */
    private fun notification(title: String, detail: String?, progressPct: Int?): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java)
                .setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val b = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(title)
            .setOngoing(true)
            .setContentIntent(open)
        if (detail != null) b.setContentText(detail)
        if (progressPct != null) b.setProgress(100, progressPct.coerceIn(0, 100), false)
        return b.build()
    }

    private fun post(title: String, detail: String?, progressPct: Int?) {
        runCatching {
            getSystemService(NotificationManager::class.java)
                .notify(NOTE_ID, notification(title, detail, progressPct))
        }
    }

    // ---- the poll behind the notification ----

    private var watching = false

    /**
     * The client for the engine generation that is running NOW, or null
     * while there is none proven.
     *
     * A field rather than a local because the metered-network callback
     * outlives any one generation and must not keep addressing a port that
     * generation gave back - see [watchMetered].
     */
    @Volatile private var current: NzbfastClient? = null

    /**
     * The token of the engine generation whose client [current] is.
     *
     * Bumped when a client is published and again when its generation is
     * RETIRED - by [watchEngine]'s exit branch or [onDestroy] - so the
     * poll loop can refuse to send a dead generation's key. Without it
     * the loop can be asleep in [POLL_MS] when the engine dies, wake, and
     * send one more keyed request to a port that may already belong to a
     * stranger (Codex sweep 27 Aug, C03). The null on [current] covers
     * the metered callback the same way; this covers the sleeper.
     */
    private val liveGen = java.util.concurrent.atomic.AtomicInteger(0)

    /**
     * Poll the engine, re-proving the listener every time that stops
     * working.
     *
     * THE OUTER LOOP IS THE POINT and it is the same rule the activity
     * follows (`MainActivity.startDeviceEngine`): a [Connection] names a
     * PORT, the port outlives the process that bound it, and every app on
     * a phone shares one loopback namespace - so a client kept across an
     * engine generation is the install's full API key addressed to
     * whatever bound that port next. Holding one client for the life of
     * the service would have put the Codex 26 Aug P1-2 disclosure back in,
     * on the one poller that keeps running when nobody is looking.
     *
     * Both ways a poll fails say the same thing. A transport failure means
     * nothing of ours is on that port; an authentication failure means
     * something is and it is not ours. Either way the credential is now
     * addressed to a stranger, so the client is dropped and
     * [EngineIdentity.awaitVerified] - which sends no key - is what earns
     * a new one.
     */
    private fun startWatching() {
        if (watching) return
        watching = true
        scope.launch {
            while (isActive) {
                // The same proof the activity takes, and for the same
                // reason: this service shares the process and the
                // app-private storage, so it can read runtime.json and
                // answer the challenge itself rather than being handed an
                // endpoint by the UI. Being handed one would mean trusting
                // a value that was proven for a different generation.
                val rt = EngineIdentity.awaitVerified(this@EngineService)
                if (rt == null) {
                    releaseWake()
                    post("nzbfast", "Waiting for the engine", null)
                    continue
                }
                val conn = Store.deviceConnection(this@EngineService, rt)
                val client = NzbfastClient(conn.baseUrl, conn.apiKey)
                val gen = liveGen.incrementAndGet()
                current = client
                watchMetered()
                while (isActive) {
                    // The token check, BEFORE the request: a wake from
                    // [POLL_MS] after the generation was retired must not
                    // send its key - see [liveGen].
                    if (gen != liveGen.get()) break
                    val snap = runCatching { client.playback(limit = 100) }.getOrNull()
                    if (snap == null) {
                        if (gen == liveGen.get()) current = null
                        releaseWake()
                        post("nzbfast", "Reconnecting to the engine", null)
                        break
                    }
                    render(snap)
                    exportFinished(client, snap)
                    checkIdle(snap)
                    delay(POLL_MS)
                }
            }
        }
    }

    /**
     * Aggregate progress across everything still to do.
     *
     * Weighted by BYTES rather than by averaging the per-job percentages:
     * a 40 GB job at 10% beside a 200 MB job at 90% is not halfway done,
     * and the arithmetic mean says it is. `mb` and `mbleft` are on every
     * queue row of the contract, so the honest figure costs nothing.
     */
    private fun render(s: PlaybackSnapshot) {
        // FIRST, ahead of every early return below: this is the only
        // place the service learns the engine's paused state, and the
        // metered PAUSE edge depends on it being current. An empty
        // queue returns out of this function a few lines down, and a
        // paused queue with nothing in it is exactly the state a user
        // leaves behind when they pause and then clear.
        //
        // A pause is ours only while the engine actually reads paused:
        // a resume by the user (or any other client) over metered data
        // gives our claim back, or the stale latch would RESUME their
        // NEXT pause - which is what turning the setting off while
        // still on cellular then does. A render carrying a pre-pause
        // snapshot can land just after our own PAUSE and clear the
        // latch; the cost is a duplicate pauseAll on the next callback,
        // which is the safe direction, same as [enginePaused]'s own
        // overwrite window.
        if (!s.paused && pausedForMetered) {
            pausedForMetered = false
            Settings.setMeteredHold(this, false)
        }
        enginePaused = s.paused
        val active = s.queue
        // THE WAKELOCK IS KEYED ON THE DRAIN LATCH, not on the queue list,
        // and that is not a detail. A job that has finished downloading is
        // out of the queue for the whole of its tail - the PAR2 repair,
        // the extract, the move - which is the most CPU-bound stretch of
        // the entire job. Keyed on `active.isEmpty()` this would drop the
        // lock precisely there and let the phone suspend mid-repair.
        if (!s.queueIdle) {
            holdWake()
        } else {
            releaseWake()
        }
        if (active.isEmpty()) {
            post(
                "nzbfast",
                when {
                    !s.queueIdle -> "Finishing up"
                    pausedForMetered -> METERED_TEXT
                    else -> "Ready. Nothing downloading."
                },
                null,
            )
            return
        }
        val total = active.sumOf { it.mb }
        val left = active.sumOf { it.mbLeft }
        val pct = if (total > 0.0) ((total - left) / total * 100.0).toInt() else 0
        val title = if (s.paused) {
            // WHY it is paused, not just that it is. The metered hold is
            // the one pause the user did not ask for, so a notification
            // that only says "Paused" is a phone that has stopped for a
            // reason nobody can see - and this render runs every five
            // seconds, so it overwrites the message the hold itself
            // posted. Measured on the emulator: the hold's own line
            // survived about three seconds.
            if (pausedForMetered) "Paused: this network is metered" else "Paused"
        } else {
            val n = active.size
            if (n == 1) active.first().name else "$n downloads"
        }
        val detail = buildString {
            append("$pct%")
            if (!s.paused && s.speedBps > 0.0) {
                append("  ")
                append("%.1f MB/s".format(s.speedBps / 1e6))
            }
            val eta = active.firstOrNull { it.status == "Downloading" }?.timeLeft.orEmpty()
            if (!s.paused && eta.isNotEmpty() && eta != "0:00:00") {
                append("  ")
                append("$eta left")
            }
            if (left > 0.0) {
                append("  ")
                append("%.0f MB to go".format(left))
            }
        }
        post(title, detail, pct)
    }

    /**
     * Stand the service down when the queue has drained.
     *
     * The condition is the daemon's own drain latch, plus
     * [IDLE_POLLS_TO_STOP], plus the app not being in use - see
     * [foreground], which is where the file-picker case is handled.
     *
     * IT DELIBERATELY DOES NOT ASK WHETHER THIS SERVICE EVER SAW WORK. It
     * did at first, so that a freshly started engine with an empty queue
     * could not be torn down on its first reading - and that guard is
     * per-INSTANCE, so the moment the service was recreated for any
     * reason it read false forever and the engine ran on with nothing to
     * do, which is what happened on the emulator after a picker-induced
     * restart. The question it was standing in for is answered properly
     * by [foreground]: an idle engine with the app not in use should stop,
     * whether or not this particular service instance watched it work,
     * and the activity starts it again the moment somebody comes back.
     */
    private fun checkIdle(s: PlaybackSnapshot) {
        if (!s.queueIdle) {
            idleStreak = 0
            return
        }
        idleStreak++
        if (idleStreak < IDLE_POLLS_TO_STOP || foreground.value) return
        if (stopRequested) return
        stopRequested = true
        post("nzbfast", "Downloads finished.", null)
        // Not `stopSelf`: see [lastStartId]. The poll loop is NOT ended
        // here either - if the stop is refused because the activity has
        // just asked for the engine again, this service goes on running
        // and has to go on reporting.
        stopSelfResult(lastStartId)
    }

    // ---- metered networks ----

    /**
     * Pause-on-metered, as a setting rather than as a policy.
     *
     * Registered once, and it reads [Settings.pauseOnMetered] at the
     * moment the network changes rather than at registration, so turning
     * the setting on does not need the callback rebuilding. What it
     * pauses is the DAEMON's global pause, which is the same switch the
     * Pause all button uses - so [pausedForMetered] exists to make sure an
     * unmetered network resumes only a pause this rule applied, and never
     * one the user asked for.
     *
     * THAT LAST CLAUSE NEEDED A SECOND HALF, added 28 Aug 2026. The
     * latch says which pauses this rule gives BACK; on its own it said
     * nothing about which it was allowed to TAKE, so a queue the user
     * had paused was adopted by the next step onto cellular and resumed
     * by the next step off it. The decision is [meteredAction] now, in
     * one place for this callback and [applyMeteredPolicy] both, and it
     * refuses the pause edge over an already-paused queue.
     */
    private fun watchMetered() {
        if (meteredCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        // The DEFAULT network, not every network matching a request: a
        // phone routinely holds a Wi-Fi and a cellular network at once,
        // and a callback for each would hand this two contradictory
        // answers about whether "the network" is metered. The default is
        // the one the engine's sockets are actually on.
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(net: Network, caps: NetworkCapabilities) {
                val metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                scope.launch {
                    // Read at the moment the network changes, never
                    // captured: this callback outlives the engine
                    // generation that was running when it was registered,
                    // and the client it addressed went with that one.
                    val client = current ?: return@launch
                    // THE DECISION IS [meteredAction] AND NOT AN `if`
                    // CHAIN HERE. It used to be one, and so did
                    // [applyMeteredPolicy]'s - two hand-copied
                    // spellings of one rule, both missing the
                    // already-paused guard in the same way. Do not
                    // inline it back.
                    applyMeteredAction(
                        client,
                        meteredAction(
                            settingOn = Settings.pauseOnMetered(this@EngineService),
                            metered = metered,
                            pausedForMetered = pausedForMetered,
                            enginePaused = enginePaused,
                        ),
                    )
                }
            }
        }
        runCatching {
            cm.registerDefaultNetworkCallback(cb)
            meteredCallback = cb
        }
    }

    /**
     * Apply the metered policy against the CURRENT network, on a setting
     * change rather than a network change - see [meteredPolicyEpoch].
     *
     * LITERALLY the same rule as the callback, because both now call
     * [meteredAction]: on plus metered pauses, and a standing
     * [pausedForMetered] pause is resumed when the setting goes off or
     * the network is not metered. A pause the user asked for is never
     * touched - which this comment claimed before 28 Aug 2026 and this
     * function did not do: with no already-paused guard on the pause
     * edge, turning the setting OFF while still on cellular resumed a
     * user-paused download over metered data. That was the expensive
     * half of the bug, because the resume arm here fires on a setting
     * change without waiting for the network to move.
     */
    private fun applyMeteredPolicy() {
        val client = current ?: return
        applyMeteredAction(
            client,
            meteredAction(
                settingOn = Settings.pauseOnMetered(this),
                metered = DeviceProfile.isMetered(this),
                pausedForMetered = pausedForMetered,
                enginePaused = enginePaused,
            ),
        )
    }

    /**
     * Carry out what [meteredAction] decided. The latch and the cached
     * [enginePaused] move together with the request, so the next
     * decision - which may arrive before the next poll - sees what this
     * one did rather than what the engine last said.
     *
     * Blocking, on purpose: [NzbfastClient.pauseAll] is a plain HTTP
     * call and both callers are already on the IO dispatcher.
     */
    private fun applyMeteredAction(client: NzbfastClient, action: MeteredAction) {
        when (action) {
            MeteredAction.PAUSE -> {
                pausedForMetered = true
                // The persisted twin moves with the latch, in both
                // arms and in [render]'s clear: the daemon keeps its
                // pause across a service restart, so the ownership
                // marker has to survive with it - see
                // [Settings.meteredHold].
                Settings.setMeteredHold(this, true)
                enginePaused = true
                runCatching { client.pauseAll() }
                post("nzbfast", METERED_TEXT, null)
            }
            MeteredAction.RESUME -> {
                pausedForMetered = false
                Settings.setMeteredHold(this, false)
                enginePaused = false
                runCatching { client.resumeAll() }
            }
            MeteredAction.NONE -> Unit
        }
    }

    // ---- export (AN3) ----

    /**
     * Copy newly finished payloads into the user's chosen folder.
     *
     * Here rather than in the activity because a download that finishes
     * with the app closed is the normal case, and an export that only
     * happens when somebody is looking is not an export. The daemon does
     * not carry the on-disk path on the playback contract, so the path
     * comes from `mode=history` (contract row 3), fetched only when there
     * is actually something new to copy.
     */
    private fun exportFinished(client: NzbfastClient, s: PlaybackSnapshot) {
        val tree = Settings.exportTree(this) ?: return
        val fresh = s.history.filter {
            it.status == "Completed" && !Settings.isExported(this, it.nzoId)
        }
        if (fresh.isEmpty()) return
        val paths = runCatching { client.history() }.getOrNull() ?: return
        for (job: PlaybackJob in fresh) {
            val row = paths.firstOrNull { it.nzoId == job.nzoId } ?: continue
            val src = row.storage
            if (src.isEmpty()) continue
            val r = Exporter.export(this, tree, File(src), job.name, job.nzoId)
            if (r.error == null) {
                // Marked on success only, so a folder that was
                // unavailable this poll is retried on the next one.
                Settings.markExported(this, job.nzoId)
            }
        }
    }

    // ---- wakelock ----

    /**
     * Hold the CPU awake while there is work.
     *
     * A foreground service is exempt from being KILLED, not from the
     * device suspending: with the screen off and no wakelock the CPU stops
     * and the sockets go quiet, so the download stalls under a
     * notification still claiming progress. Held only while the queue has
     * something in it, and dropped the moment it does not, which is what
     * keeps this from being a battery bug of its own.
     */
    private fun holdWake() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(PowerManager::class.java) ?: return
        val wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "nzbfast:download")
        wl.setReferenceCounted(false)
        runCatching { wl.acquire(WAKE_CAP_MS) }
        wakeLock = wl
    }

    private fun releaseWake() {
        val wl = wakeLock ?: return
        runCatching { if (wl.isHeld) wl.release() }
        wakeLock = null
    }

    /**
     * A timeout on the wakelock, not because one is expected to be needed
     * but because a leaked wakelock is a flat battery and this is the one
     * bug in this file the user would never diagnose. Twelve hours is far
     * past any real job and far short of overnight-to-noon.
     */
    private val WAKE_CAP_MS = 12L * 60 * 60 * 1000

    // ---- engine process ----

    private fun startEngine() {
        if (engine?.isAlive == true) return
        try {
            val base = filesDir
            val dl = DeviceProfile.downloadDir(this).apply { mkdirs() }
            val watch = File(base, "watch").apply { mkdirs() }
            val cfg = File(base, "config").apply { mkdirs() }
            val bin = applicationInfo.nativeLibraryDir + "/libnzbfast.so"
            val pb = ProcessBuilder(
                bin,
                "--config", File(cfg, "config.json").absolutePath,
                // TODO 281 AN4. A top-level flag, so it goes BEFORE the
                // subcommand. The engine's own default is a quarter of
                // physical RAM, which is a desktop rule - see
                // DeviceProfile.memLimitArg for what it costs on a phone.
                "--mem-limit", DeviceProfile.memLimitArg(this),
                "serve",
                "--bind", "127.0.0.1",
                // 0 = let the OS pick. The engine used to bind a fixed
                // 6791, and every app on a phone shares ONE loopback
                // namespace, so a port a sibling app can predict is a
                // port it can pre-bind before us (Codex sweep 12 Aug F4).
                // Identity is still proved by the runtime.json token, not
                // by the port - see EngineIdentity - but a port nobody can
                // name in advance is one nobody can lie in wait on.
                //
                // Where the answer comes back: the daemon reports the port
                // it actually bound in runtime.json, and Store.load reads
                // it from there. Nothing in this app holds a port constant.
                "--port", "0",
                "--apikey", apiKey(this),
                "--out", dl.absolutePath,
                "--watch", watch.absolutePath,
            )
            // The launcher owns the port, so a `port` in settings.json must
            // not overrule the `--port 0` above. Without this a value saved
            // from the daemon's own embedded dashboard would pin the
            // listener back to one fixed port, and the randomisation would
            // stop happening with nothing to show it had.
            pb.environment()["NZBFAST_PORT_LOCKED"] = "1"
            // TODO 281 AN4, the thermal half: the engine's CPU-bound pools
            // size themselves from `available_parallelism`, which counts a
            // phone's little cores as if they were big ones. See
            // DeviceProfile.cpuWorkers.
            pb.environment()["NZBFAST_CPU_WORKERS"] = DeviceProfile.cpuWorkers().toString()
            // TODO 281 AN3. ANDROID HAS NO SYSTEM TRASH - `smart.rs`'s
            // recoverable-delete route is a `cfg` arm that refuses on this
            // platform by construction - and the engine's default is to
            // send deletes there. So a "delete the files too" left the
            // payload exactly where it was and logged a warning telling
            // the user to turn off a setting this app does not show.
            // Measured on the emulator, 26 Aug 2026: 40 MB survived a
            // delete that reported success. The launcher is the right
            // place to say this, for the same reason it names the memory
            // budget: it is a fact about the device.
            pb.environment()["NZBFAST_NO_TRASH"] = "1"
            pb.environment()["HOME"] = base.absolutePath
            pb.environment()["TMPDIR"] = cacheDir.absolutePath
            pb.redirectErrorStream(true)
            pb.redirectOutput(File(base, "daemon.log"))
            val p = pb.start()
            engine = p
            watchEngine(p)
        } catch (e: Exception) {
            stopSelf()
        }
    }

    /**
     * Notice the engine going away.
     *
     * NOTHING DID. The child [Process] was held and never waited on, so an
     * engine that crashed, was killed for memory, or exited on an unusable
     * config left this service still saying "engine running on this
     * device" and the UI still polling - with the install's full API key
     * on every request - a 127.0.0.1 port nothing of ours holds any more.
     * See [engineExits] for what that costs and who fixes it.
     *
     * A thread on `waitFor` rather than `Process.onExit`, which is API 33
     * and this app ships to 26; and rather than polling `isAlive`, which
     * would report the death only when something next looked. One thread
     * per engine generation, and it exits with that generation.
     *
     * GENERATION-SAFE, the same way the Mac wrapper's termination handler
     * is: the report is made only while [engine] is still the process this
     * watcher was started for. A corpse whose replacement is already
     * running must not take the live engine's connection down with it.
     *
     * It does NOT `stopSelf`, and that is a decision rather than an
     * omission: the UI answers the report by asking for the engine again,
     * `startForegroundService` lands as [onStartCommand] on a service that
     * is already up, and [startEngine] then starts a fresh generation with
     * no stop to race. Stopping here would put a `stopSelf` and that start
     * request in flight against each other for nothing.
     */
    private fun watchEngine(p: Process) {
        val watcher = Runnable {
            // Null only for an interrupt, which is not an exit: the thread
            // is being asked to go, and the engine it was watching is
            // somebody else's business by then.
            val code = try {
                p.waitFor()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                null
            }
            if (code != null && !stopping && engine === p) {
                engine = null
                // Retire the keyed client NOW, not on the poll loop's
                // next pass: the port this generation bound is free the
                // moment the process is gone, and both the sleeping poll
                // (the token) and the metered callback (the null) must
                // refuse it before anything rebinds - see [liveGen].
                liveGen.incrementAndGet()
                current = null
                releaseWake()
                post("nzbfast", "The engine stopped (exit $code)", null)
                exits.update { it + 1 }
            }
        }
        Thread(watcher, "nzbfast-engine-watch").start()
    }

    override fun onDestroy() {
        stopping = true
        // Same retirement as [watchEngine]'s exit branch: the engine is
        // about to be destroyed, so nothing may send its key again.
        liveGen.incrementAndGet()
        current = null
        releaseWake()
        meteredCallback?.let { cb ->
            runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) }
        }
        meteredCallback = null
        scope.cancel()
        engine?.destroy()
        engine = null
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
