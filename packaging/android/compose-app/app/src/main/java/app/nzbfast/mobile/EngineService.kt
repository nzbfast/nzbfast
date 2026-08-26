package app.nzbfast.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Foreground service hosting the on-device engine. The binary ships as
 * libnzbfast.so in jniLibs; with legacy packaging the installer puts a
 * real file in nativeLibraryDir, and exec from there is the
 * post-API-29-legal way to run a bundled binary. Same mechanism as the
 * proven packaging/android/app test APK.
 *
 * The daemon binds 127.0.0.1 only, on a port the OS chooses. Downloads
 * land in filesDir/downloads until the export story exists.
 */
class EngineService : Service() {

    companion object {
        private const val CHANNEL = "engine"
        private const val NOTE_ID = 1

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

    override fun onCreate() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Engine", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        stopping = false
        val n = notification("engine running on this device")
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTE_ID, n)
        }
        startEngine()
        return START_STICKY
    }

    /** The one foreground notification, built twice: once when the engine
     *  starts and once by [watchEngine] when it stops, because "engine
     *  running on this device" is the only surface a user who is not in
     *  the app can see and it must not go on saying that. */
    private fun notification(text: String): Notification =
        Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("nzbfast")
            .setContentText(text)
            .setOngoing(true)
            .build()

    private fun startEngine() {
        if (engine?.isAlive == true) return
        try {
            val base = filesDir
            val dl = File(base, "downloads").apply { mkdirs() }
            val watch = File(base, "watch").apply { mkdirs() }
            val cfg = File(base, "config").apply { mkdirs() }
            val bin = applicationInfo.nativeLibraryDir + "/libnzbfast.so"
            val pb = ProcessBuilder(
                bin,
                "--config", File(cfg, "config.json").absolutePath,
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
                getSystemService(NotificationManager::class.java)
                    .notify(NOTE_ID, notification("engine stopped (exit $code)"))
                exits.update { it + 1 }
            }
        }
        Thread(watcher, "nzbfast-engine-watch").start()
    }

    override fun onDestroy() {
        stopping = true
        engine?.destroy()
        engine = null
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
