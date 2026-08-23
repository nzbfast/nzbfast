package app.nzbfast.mobile

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import app.nzbfast.mobile.api.NzbfastClient
import app.nzbfast.mobile.api.PlaybackJob
import app.nzbfast.mobile.api.PlaybackSnapshot
import app.nzbfast.mobile.ui.AddScreen
import app.nzbfast.mobile.ui.ConnectScreen
import app.nzbfast.mobile.ui.HomeScreen
import app.nzbfast.mobile.ui.NzbfastTheme
import app.nzbfast.mobile.ui.PlayerScreen
import app.nzbfast.mobile.ui.ServerSetupScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Which screen is on top. A hand-rolled stack: four screens do not
 *  earn a navigation library. */
sealed class Screen {
    data object Connect : Screen()
    data object ServerSetup : Screen()
    data object Home : Screen()
    data object Add : Screen()
    data class Player(val nzoId: String, val url: String, val title: String) : Screen()
}

/**
 * Something an OUTSIDE app asked us to download, staged until the user
 * says yes.
 *
 * MainActivity is exported for ACTION_SEND and ACTION_VIEW, and intent
 * filters constrain implicit launches only: any app on the device can
 * start an exported component explicitly. Submitting on arrival therefore
 * let a malicious foreground app make the victim's daemon - possibly a
 * remote one, holding provider credentials - enqueue downloads of the
 * attacker's choosing, without knowing the API key and without the share
 * chooser ever appearing. We are the deputy; the confirmation is what
 * stops us being a confused one (Codex sweep 12 Aug F10).
 *
 * The in-app paths (file picker, pasted link) are NOT staged: those are
 * already an explicit action by the person holding the phone.
 */
sealed class PendingImport {
    abstract val label: String

    data class File(val uri: Uri, val name: String) : PendingImport() {
        override val label get() = name
    }

    data class Link(val link: String) : PendingImport() {
        override val label get() = link
    }
}

class MainActivity : ComponentActivity() {

    private var screen by mutableStateOf<Screen>(Screen.Connect)
    private var connection by mutableStateOf<Connection?>(null)
    private var busy by mutableStateOf(false)
    private var note by mutableStateOf<String?>(null)

    /** An external share/link waiting for the user to confirm it. See
     *  [PendingImport]: nothing is uploaded or enqueued until they do. */
    private var pendingImport by mutableStateOf<PendingImport?>(null)

    /** The one poll: mode=playback carries queue, history, per-file
     *  readiness and the byte-serving telemetry in a single response. */
    private var snapshot by mutableStateOf<PlaybackSnapshot?>(null)

    /** Rolling throughput samples (MB/s), one per poll, for the Home
     *  chart. ~90 samples at the 2 s cadence = the last three minutes. */
    private var speedHistory by mutableStateOf(listOf<Double>())

    private var pollJob: Job? = null

    private val client: NzbfastClient?
        get() = connection?.let { NzbfastClient(it.baseUrl, it.apiKey) }

    private val pickNzb =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) addFromUri(uri)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        when (Store.savedMode(this)) {
            Mode.DEVICE -> {
                // A saved ON-DEVICE connection must clear the same identity
                // bar a fresh one does. Setting `connection` here and polling
                // immediately is what sent the stored full key to whatever
                // owned the port on every app start, not just the first (see
                // EngineIdentity). The engine is asked to start, the screen
                // goes to Home, and the credential waits for the proof.
                //
                // The mode is read here but the ENDPOINT is not: the engine
                // takes an OS-chosen port, so where to send the key is not
                // known until the proof comes back with it.
                startForegroundService(Intent(this, EngineService::class.java))
                screen = Screen.Home
                busy = true
                lifecycleScope.launch {
                    val proven = withContext(Dispatchers.IO) {
                        EngineIdentity.awaitVerified(this@MainActivity)
                    }
                    busy = false
                    if (proven == null) {
                        note = "The engine did not start, or something else is using " +
                            "its port. Check daemon.log in app storage."
                        screen = Screen.Connect
                        return@launch
                    }
                    note = null
                    connection = Store.deviceConnection(this@MainActivity, proven)
                    startPolling()
                }
            }
            Mode.SERVER -> {
                val saved = Store.load(this)
                if (saved != null) {
                    connection = saved
                    screen = Screen.Home
                    startPolling()
                }
            }
            null -> {}
        }
        handleIntent(intent)

        setContent {
            NzbfastTheme {
                AppScaffold()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    /** True while the activity is in a PiP window: the player hides its
     *  chrome (controller, overlays) - the window is thumbnail-sized and
     *  the OS draws its own controls over it. */
    private var inPip by mutableStateOf(false)

    /** Home button while the test preview is up: keep the picture going
     *  in a PiP window instead of stopping. Only the player earns it -
     *  minimizing a queue screen should just minimize. */
    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        if (screen is Screen.Player) {
            enterPictureInPictureMode(
                android.app.PictureInPictureParams.Builder().build()
            )
        }
    }

    override fun onPictureInPictureModeChanged(
        isInPictureInPictureMode: Boolean,
        newConfig: android.content.res.Configuration,
    ) {
        super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig)
        inPip = isInPictureInPictureMode
    }

    override fun onDestroy() {
        pollJob?.cancel()
        super.onDestroy()
    }

    /**
     * "Another app wants nzbfast to download this" - shown before any
     * upload or enqueue, naming what it is and which daemon would get it.
     *
     * Cancel is the destructive-free default and dismissing counts as
     * cancel, so a launch the user did not intend costs nothing.
     */
    @Composable
    private fun ImportConfirmation() {
        val p = pendingImport ?: return
        val target = connection?.let {
            if (it.mode == Mode.DEVICE) "this phone" else it.baseUrl
        }
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { pendingImport = null },
            title = { Text("Add this to nzbfast?") },
            text = {
                Text(
                    buildString {
                        append("Another app asked nzbfast to download:\n\n")
                        append(p.label)
                        append("\n\n")
                        when (target) {
                            null -> append("You are not connected yet, so nothing can be added.")
                            else -> append("It would be sent to $target.")
                        }
                    }
                )
            },
            confirmButton = {
                TextButton(
                    onClick = ::confirmImport,
                    enabled = target != null,
                ) { Text("Add") }
            },
            dismissButton = {
                TextButton(onClick = { pendingImport = null }) { Text("Cancel") }
            },
        )
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun AppScaffold() {
        val s = screen
        BackHandler(enabled = s is Screen.Add || s is Screen.Player) {
            screen = Screen.Home
        }
        ImportConfirmation()
        when (s) {
            is Screen.Player -> PlayerScreen(
                streamUrl = s.url,
                title = s.title,
                job = { snapshot?.let { snap ->
                    (snap.queue + snap.history).firstOrNull { it.nzoId == s.nzoId }
                } },
                telemetry = { snapshot?.stream },
                inPip = { inPip },
            )
            else -> Scaffold(
                topBar = {
                    if (s is Screen.Home) {
                        TopAppBar(
                            title = { Text("nzbfast") },
                            actions = {
                                val paused = snapshot?.paused == true
                                TextButton(onClick = { togglePauseAll(paused) }) {
                                    Text(if (paused) "Resume all" else "Pause all")
                                }
                            },
                        )
                    }
                },
                floatingActionButton = {
                    if (s is Screen.Home) {
                        FloatingActionButton(onClick = { screen = Screen.Add }) {
                            Text("+")
                        }
                    }
                },
            ) { pad ->
                val mod = Modifier.padding(pad)
                when (s) {
                    is Screen.Connect -> androidx.compose.foundation.layout.Box(mod) {
                        ConnectScreen(
                            busy = busy,
                            error = note,
                            onUseDevice = ::useDevice,
                            onUseServer = ::useServer,
                        )
                    }
                    is Screen.ServerSetup -> androidx.compose.foundation.layout.Box(mod) {
                        ServerSetupScreen(
                            busy = busy,
                            status = note,
                            onTest = ::testNewsServer,
                            onSave = ::saveNewsServer,
                        )
                    }
                    is Screen.Home -> androidx.compose.foundation.layout.Box(mod) {
                        HomeScreen(
                            snapshot = snapshot,
                            speedHistory = speedHistory,
                            statusLine = note,
                            onPlay = ::play,
                            onPauseJob = { io { client?.pauseJob(it) } },
                            onResumeJob = { io { client?.resumeJob(it) } },
                            onDeleteJob = { io { client?.deleteJob(it, deleteFiles = false) } },
                            onDeleteHistory = {
                                io { client?.deleteHistory(it, deleteFiles = false) }
                            },
                        )
                    }
                    is Screen.Add -> androidx.compose.foundation.layout.Box(mod) {
                        AddScreen(
                            busy = busy,
                            status = note,
                            onPickFile = {
                                pickNzb.launch(arrayOf("*/*"))
                            },
                            onSubmitLink = ::addLink,
                        )
                    }
                    is Screen.Player -> {}
                }
            }
        }
    }

    // ---- connect flows ----

    private fun useDevice() {
        busy = true
        note = null
        startForegroundService(Intent(this, EngineService::class.java))
        lifecycleScope.launch {
            // Identity BEFORE the credential. `local.version()` used to be
            // the readiness probe, and it carried the persistent full API
            // key to whatever held the port - see EngineIdentity. Nothing
            // keyed happens until the listener has proven it is our engine.
            val proven = withContext(Dispatchers.IO) {
                EngineIdentity.awaitVerified(this@MainActivity)
            }
            busy = false
            if (proven == null) {
                note = "The engine did not start, or something else is using its port. " +
                    "Check daemon.log in app storage."
                return@launch
            }
            Store.saveDevice(this@MainActivity)
            // From the PROVEN record, not from a re-read: this is the
            // listener that just answered the challenge, and the port it
            // answered on is the only one the key may go to.
            connection = Store.deviceConnection(this@MainActivity, proven)
            val configured = withContext(Dispatchers.IO) {
                runCatching { client!!.serversConfigured() }.getOrDefault(false)
            }
            if (configured) {
                note = null
                screen = Screen.Home
                startPolling()
            } else {
                note = null
                screen = Screen.ServerSetup
            }
        }
    }

    private fun useServer(url: String, key: String) {
        busy = true
        note = null
        val base = if (url.startsWith("http")) url else "http://$url"
        lifecycleScope.launch {
            val probe = NzbfastClient(base.trimEnd('/'), key)
            // Validate with the call the app lives on: mode=playback
            // needs the full key and proves the daemon speaks contract v1.
            val err = withContext(Dispatchers.IO) {
                runCatching { probe.playback(limit = 1) }.exceptionOrNull()
            }
            busy = false
            if (err != null) {
                note = "Could not connect: ${err.message}"
            } else {
                Store.saveServer(this@MainActivity, base, key)
                connection = Store.load(this@MainActivity)
                note = null
                screen = Screen.Home
                startPolling()
            }
        }
    }

    private fun testNewsServer(host: String, port: Int, tls: Boolean, user: String, pass: String) {
        busy = true
        note = null
        lifecycleScope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching { client!!.serverTest(host, port, tls, user, pass) }
                    .getOrElse { app.nzbfast.mobile.api.ServerTestResult(false, it.message ?: "failed") }
            }
            busy = false
            note = if (r.ok) "Connected: ${r.detail}" else "Failed: ${r.detail}"
        }
    }

    private fun saveNewsServer(host: String, port: Int, tls: Boolean, user: String, pass: String) {
        busy = true
        note = null
        lifecycleScope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching { client!!.serverSave(host, port, tls, user, pass) }
                    .getOrDefault(false)
            }
            busy = false
            if (ok) {
                note = null
                screen = Screen.Home
                startPolling()
            } else {
                note = "Saving the server failed."
            }
        }
    }

    // ---- add flows ----

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri: Uri? = if (android.os.Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                // STAGED, not submitted - see PendingImport.
                when {
                    uri != null -> pendingImport = PendingImport.File(
                        uri,
                        queryDisplayName(uri) ?: "shared.nzb",
                    )
                    text != null && text.contains("nzblnk:") ->
                        pendingImport = PendingImport.Link(text.trim())
                }
            }
            Intent.ACTION_VIEW -> {
                val data = intent.data ?: return
                if (data.scheme == "nzblnk") {
                    pendingImport = PendingImport.Link(data.toString())
                }
            }
        }
    }

    /** The user said yes to a staged external import. */
    private fun confirmImport() {
        val p = pendingImport ?: return
        pendingImport = null
        when (p) {
            is PendingImport.File -> addFromUri(p.uri)
            is PendingImport.Link -> addLink(p.link)
        }
    }

    private fun addFromUri(uri: Uri) {
        if (connection == null) {
            note = "Connect first, then add NZBs."
            return
        }
        busy = true
        note = null
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val name = queryDisplayName(uri) ?: "shared.nzb"
                    // readSharedNzb, not readBytes: the stream behind a
                    // content URI is served by whichever app shared it,
                    // which is free to make it arbitrarily long and to
                    // lie about its length. The daemon's own 256 MiB
                    // addfile cap is far too late to protect the phone.
                    val stream = contentResolver.openInputStream(uri)
                        ?: error("could not read the file")
                    val bytes = client!!.readSharedNzb(stream, name)
                    client!!.addFile(name, bytes)
                }
            }
            busy = false
            result.fold(
                onSuccess = { r ->
                    note = if (r.ok) "Added." else "Add failed: ${r.error ?: "unknown error"}"
                    if (r.ok) screen = Screen.Home
                },
                onFailure = { note = "Add failed: ${it.message}" },
            )
        }
    }

    private fun addLink(link: String) {
        if (connection == null) {
            note = "Connect first, then add links."
            return
        }
        busy = true
        note = null
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { client!!.addNzbLnk(link) }
            }
            busy = false
            result.fold(
                onSuccess = { r ->
                    note = if (r.ok) "Added." else "Add failed: ${r.error ?: "unknown error"}"
                    if (r.ok) screen = Screen.Home
                },
                onFailure = { note = "Add failed: ${it.message}" },
            )
        }
    }

    private fun queryDisplayName(uri: Uri): String? =
        contentResolver.query(uri, null, null, null, null)?.use { c ->
            val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (i >= 0 && c.moveToFirst()) c.getString(i) else null
        }

    // ---- play ----

    private fun play(job: PlaybackJob) {
        val cl = client ?: return
        busy = true
        lifecycleScope.launch {
            // Row 16 already hands over the tokenized play URL; /m3u is
            // only the fallback for a snapshot that lacked one.
            val url = withContext(Dispatchers.IO) {
                job.stream.ifEmpty { cl.streamUrl(job.nzoId) }
            }
            // mode=playback is read-only by design; the probe is what
            // promotes a live job's file index, so fire it once for the
            // one job the user opened (contract row 13).
            if (job.playback.source == "live") {
                io { cl.probe(job.nzoId) }
            }
            busy = false
            screen = Screen.Player(job.nzoId, url, job.name)
        }
    }

    private fun togglePauseAll(paused: Boolean) {
        io { if (paused) client?.resumeAll() else client?.pauseAll() }
    }

    // ---- polling ----

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = lifecycleScope.launch {
            while (isActive) {
                val cl = client
                // One poll for everything: readiness rides the job rows
                // (no per-job probes) and the telemetry feeds the player
                // overlay, so keep polling while the player is up.
                if (cl != null && (screen is Screen.Home || screen is Screen.Player)) {
                    val snap = withContext(Dispatchers.IO) {
                        runCatching { cl.playback() }.getOrNull()
                    }
                    if (snap != null) {
                        snapshot = snap
                        speedHistory = (speedHistory + snap.speedBps / 1e6).takeLast(90)
                        if (note?.startsWith("Could not reach") == true) note = null
                    } else {
                        note = "Could not reach the server."
                    }
                }
                delay(2_000)
            }
        }
    }

    private fun io(block: () -> Unit) {
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching(block)
        }
    }
}
