package app.nzbfast.mobile

import android.app.PictureInPictureParams
import android.content.Intent
import android.graphics.Rect
import android.net.Uri
import android.os.Build
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
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import app.nzbfast.mobile.api.NzbSize
import app.nzbfast.mobile.api.NzbfastClient
import app.nzbfast.mobile.api.PlaybackJob
import app.nzbfast.mobile.api.PlaybackSnapshot
import app.nzbfast.mobile.ui.AddScreen
import app.nzbfast.mobile.ui.ConnectScreen
import app.nzbfast.mobile.ui.HomeScreen
import app.nzbfast.mobile.ui.NzbfastTheme
import app.nzbfast.mobile.ui.PlayerScreen
import app.nzbfast.mobile.ui.ServerSetupScreen
import app.nzbfast.mobile.ui.SettingsScreen
import app.nzbfast.mobile.ui.UpdateBanner
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.drop
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
    data object Settings : Screen()
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

    /**
     * The newest nzbfast this install has been told about, when that is
     * newer than the app itself; null otherwise. Loaded from prefs at
     * onCreate so a cold start draws the notice without waiting for a
     * network round trip, and refreshed by [maybeCheckForUpdate].
     */
    private var updateVersion by mutableStateOf<String?>(null)

    /** The version whose BANNER the user has waved away. The Settings
     *  card ignores this - see [UpdateNotice.dismiss]. */
    private var updateDismissed by mutableStateOf<String?>(null)

    /**
     * An update check already on the wire.
     *
     * The once-a-day gate alone does NOT make this one call: the stored
     * deadline only moves when the answer comes back, and the two call
     * sites both fire during the same launch - onCreate reaches
     * [startPolling] and onStart follows it, microseconds apart, so both
     * read a deadline neither has written yet. Measured on the emulator,
     * 4 Sep 2026: two `mode=update_check` lines in the proxy log for one
     * cold start. Set synchronously before the coroutine is launched,
     * which is what makes it a latch rather than a second race.
     */
    private var updateCheckInFlight = false

    /**
     * Free bytes where downloads actually land on THIS phone (TODO 281
     * AN3). Sampled at onStart and after every add rather than polled:
     * `StatFs` is a syscall against the filesystem the app is writing to,
     * and a figure that is a few seconds old is not what makes a disk
     * fill up.
     *
     * Zero in server mode, where the volume that matters is the daemon's
     * and `diskspace_gb` on the contract is the answer.
     */
    private var freeBytes by mutableLongStateOf(0L)

    /** The export folder's display name, or null for keep-in-app. */
    private var exportFolder by mutableStateOf<String?>(null)

    /**
     * Whether this activity is between onStart and onStop.
     *
     * Gates the poll. `lifecycleScope` lives until onDestroy, so without
     * this the activity kept polling every two seconds behind a screen
     * nobody was looking at - and, since TODO 281 AN2, would have fought
     * the service over it: the service stops the engine when the queue
     * drains off screen, and a background poll would see that as the
     * engine dying and start it again.
     */
    private var visible = false

    /** The in-flight on-device startup, so two ways in cannot race one
     *  another - see [startDeviceEngine]. */
    private var deviceStartJob: Job? = null

    private val client: NzbfastClient?
        get() = connection?.let { NzbfastClient(it.baseUrl, it.apiKey) }

    /**
     * True while a picker WE launched is on top.
     *
     * A picker is another app's activity, so ours stops - and the engine
     * service reads "not on screen" as permission to shut an idle engine
     * down. Choosing the very first NZB is precisely the moment the queue
     * IS idle, so without this the engine went away while the user was
     * still browsing for the file they were about to add. Measured on the
     * emulator, 26 Aug 2026.
     */
    private var awaitingPicker = false

    private val pickNzb =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            awaitingPicker = false
            if (uri != null) addFromUri(uri)
        }

    /**
     * The SAF folder picker behind AN3's export.
     *
     * `OpenDocumentTree` is the only way to be given write access to a
     * place outside app-private storage without asking for a
     * storage-wide permission, which is the permission Play reviews
     * hardest and which this app has no business holding: it needs one
     * folder, chosen by the person who owns it.
     */
    private val pickExportTree =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            awaitingPicker = false
            if (uri != null) {
                Settings.setExportTree(this, uri)
                exportFolder = treeLabel(uri)
                note = "Finished downloads will be copied to that folder."
            }
        }

    /**
     * The Android 13 notification permission.
     *
     * A foreground service still RUNS without it - the grant governs
     * whether its notification is shown - so the failure it prevents is
     * silent rather than loud: downloads work, and the one surface that
     * reports them to somebody who has left the app is invisible. Asked
     * for once, when on-device mode is chosen, and never insisted on.
     */
    private val askNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

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
                startDeviceEngine(toHome = true)
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
        exportFolder = Settings.exportTree(this)?.let(::treeLabel)
        updateVersion = UpdateNotice.available(this)
        updateDismissed = UpdateNotice.dismissed(this)
        watchEngineExits()
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

    /**
     * On screen. Three things follow from that and each is one half of a
     * pair with [onStop].
     *
     * The service is asked for again because it may have stopped ITSELF:
     * since TODO 281 AN2 a drained queue with the app off screen ends the
     * engine, and coming back is the moment to have one again - asking
     * here rather than letting the first failed poll discover it means the
     * engine is usually up before Home has finished drawing.
     * `startForegroundService` on a service that is already running is
     * just another onStartCommand, so this is idempotent.
     */
    override fun onStart() {
        super.onStart()
        visible = true
        EngineService.setForeground(true)
        refreshFreeSpace()
        if (Store.savedMode(this) == Mode.DEVICE && connection != null) {
            startForegroundService(Intent(this, EngineService::class.java))
        }
        maybeCheckForUpdate()
    }

    override fun onStop() {
        visible = false
        // Still "in use" while a picker we launched is up - see
        // [awaitingPicker]. Every other way out of this activity is a real
        // departure, and an idle engine should not outlive one.
        EngineService.setForeground(awaitingPicker)
        super.onStop()
    }

    /**
     * Re-read free space on the volume downloads actually land on.
     *
     * Keyed on the LIVE connection rather than on the saved mode, which
     * is what it read at first and was wrong: on a first run the mode is
     * saved part-way through `useDevice`, so a reading taken at onStart -
     * before any of that - answered zero and the Add screen then said
     * free space was not known on a phone that had 8.6 GB of it. Called
     * at onStart, on every path that establishes a device connection, and
     * whenever a screen that shows the figure is opened.
     */
    private fun refreshFreeSpace() {
        freeBytes = if (connection?.mode == Mode.DEVICE) {
            DeviceProfile.freeBytes(DeviceProfile.downloadDir(this))
        } else {
            0L
        }
    }

    /**
     * A folder name a person can recognise, out of a tree URI.
     *
     * The document id is the readable part ("primary:Download"); the rest
     * of the URI is a provider authority and percent-encoding. Falling
     * back to the whole URI is ugly rather than wrong, and only a provider
     * that mints opaque ids gets there.
     */
    private fun treeLabel(uri: Uri): String {
        val id = runCatching { android.provider.DocumentsContract.getTreeDocumentId(uri) }
            .getOrNull() ?: return uri.toString()
        return id.substringAfter(':').ifEmpty { id }
    }

    /** True while the activity is in a PiP window: the player hides its
     *  chrome (controller, overlays) - the window is thumbnail-sized and
     *  the OS draws its own controls over it. */
    private var inPip by mutableStateOf(false)

    /** The video's current on-screen bounds, reported by [PlayerScreen] via
     *  [Modifier.onGloballyPositioned] whenever they change. Feeds
     *  [updatePipParams]'s sourceRectHint. */
    private var videoRect by mutableStateOf<Rect?>(null)

    /**
     * Keeps this activity's PictureInPictureParams current with the system.
     * Android 12+ (API 31) reads setAutoEnterEnabled/setSourceRectHint to
     * animate the transition into PiP itself - from the actual on-screen
     * video position - rather than the plain fade you get from calling
     * enterPictureInPictureMode() by hand in onUserLeaveHint (lint's
     * PictureInPictureIssue). Below API 31 neither setter exists, so
     * onUserLeaveHint's manual call remains the only way in.
     */
    private fun updatePipParams() {
        if (Build.VERSION.SDK_INT < 31) return
        val builder = PictureInPictureParams.Builder()
            .setAutoEnterEnabled(screen is Screen.Player)
        videoRect?.let { builder.setSourceRectHint(it) }
        setPictureInPictureParams(builder.build())
    }

    /** Home button while the test preview is up: keep the picture going
     *  in a PiP window instead of stopping. Only the player earns it -
     *  minimizing a queue screen should just minimize.
     *
     *  On API 31+ this is a no-op in practice: setAutoEnterEnabled (see
     *  [updatePipParams]) already has the system do this itself, with a
     *  smoother transition than a manual call can produce. The call here
     *  is the fallback for API 26-30, which has no auto-enter. */
    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        if (Build.VERSION.SDK_INT < 31 && screen is Screen.Player) {
            enterPictureInPictureMode(PictureInPictureParams.Builder().build())
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
        deviceStartJob?.cancel()
        super.onDestroy()
    }

    /**
     * The whole on-device startup: ask the service for an engine, wait for
     * a listener that PROVES it is ours, and only then build the keyed
     * connection.
     *
     * One function because there are now three ways in - a saved on-device
     * mode at launch, the engine generation ending ([watchEngineExits]),
     * and a poll that stopped reaching the engine we proved
     * ([startPolling]) - and every one of them owes the same two things
     * first: drop the credential, and stop polling with it. A [Connection]
     * names a PORT, the port outlives the process that bound it, and any
     * app on the phone may take it the moment it is free, so a connection
     * kept across a generation addresses the full API key to a stranger
     * (Codex sweep 26 Aug, P1-2). [EngineIdentity.awaitVerified] is what
     * earns it back, and it sends no key to do so.
     */
    private fun startDeviceEngine(message: String? = null, toHome: Boolean = false) {
        pollJob?.cancel()
        pollJob = null
        deviceStartJob?.cancel()
        connection = null
        note = message
        if (toHome) {
            snapshot = null
            screen = Screen.Home
        }
        ensureNotificationPermission()
        startForegroundService(Intent(this, EngineService::class.java))
        busy = true
        deviceStartJob = lifecycleScope.launch {
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
            refreshFreeSpace()
            startPolling()
        }
    }

    /**
     * Re-enter the proof path when an on-device engine generation ends.
     *
     * See [EngineService.engineExits]: the service now waits on its child
     * and says so, and this is the half that acts on it. Only the DEVICE
     * mode is ours to restart - a SERVER connection points at a daemon
     * this app never started and cannot prove that way, and its own
     * unreachability is already reported as a note.
     */
    private fun watchEngineExits() {
        lifecycleScope.launch {
            // `drop(1)`: a StateFlow replays its current value to every new
            // collector, and that value is a count of exits that happened
            // before this activity existed.
            EngineService.engineExits.drop(1).collect {
                if (Store.savedMode(this@MainActivity) == Mode.DEVICE) {
                    startDeviceEngine(
                        message = "The engine stopped. Starting it again…",
                        toHome = true,
                    )
                }
            }
        }
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
        BackHandler(
            enabled = s is Screen.Add || s is Screen.Player || s is Screen.Settings,
        ) {
            screen = Screen.Home
        }
        SideEffect { updatePipParams() }
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
                onVideoRectChanged = { videoRect = it },
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
                                TextButton(onClick = {
                                    refreshFreeSpace()
                                    screen = Screen.Settings
                                }) {
                                    Text("Settings")
                                }
                            },
                        )
                    }
                },
                floatingActionButton = {
                    if (s is Screen.Home) {
                        FloatingActionButton(onClick = {
                            refreshFreeSpace()
                            screen = Screen.Add
                        }) {
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
                            suggestedConnections = DeviceProfile.connectionsForLine(this@MainActivity),
                            lineNote = lineNote(),
                            onTest = ::testNewsServer,
                            onSave = ::saveNewsServer,
                        )
                    }
                    is Screen.Home -> androidx.compose.foundation.layout.Column(mod) {
                        val v = updateVersion
                        if (v != null && v != updateDismissed) {
                            UpdateBanner(
                                version = v,
                                currentVersion = appVersion(),
                                onOpenReleases = ::openReleasesPage,
                                onDismiss = {
                                    UpdateNotice.dismiss(this@MainActivity, v)
                                    updateDismissed = v
                                },
                            )
                        }
                        androidx.compose.foundation.layout.Box(Modifier.weight(1f)) {
                            HomeScreen(
                                snapshot = snapshot,
                                speedHistory = speedHistory,
                                statusLine = note,
                                freeBytesLocal = freeBytes,
                                // Export copies from a LOCAL path, so it is
                                // on-device mode only: a remote daemon's
                                // `storage` names a directory on that machine,
                                // and a phone opening it would find nothing or,
                                // worse, something else.
                                canExport = connection?.mode == Mode.DEVICE && exportFolder != null,
                                onPlay = ::play,
                                onPauseJob = { id -> mutate("pause that download") { client?.pauseJob(id) == true } },
                                onResumeJob = { id -> mutate("resume that download") { client?.resumeJob(id) == true } },
                                onDeleteJob = { id, files ->
                                    mutate("remove that download") {
                                        client?.deleteJob(id, deleteFiles = files) == true
                                    }
                                },
                                onDeleteHistory = { id, files ->
                                    mutate("remove that entry") {
                                        client?.deleteHistory(id, deleteFiles = files) == true
                                    }
                                },
                                onExport = ::exportJob,
                            )
                        }
                    }
                    is Screen.Add -> androidx.compose.foundation.layout.Box(mod) {
                        AddScreen(
                            busy = busy,
                            status = note,
                            freeText = freeSpaceLine(),
                            onPickFile = {
                                awaitingPicker = true
                                pickNzb.launch(arrayOf("*/*"))
                            },
                            onSubmitLink = ::addLink,
                        )
                    }
                    is Screen.Settings -> androidx.compose.foundation.layout.Box(mod) {
                        SettingsScreen(
                            sourceLabel = connection?.let {
                                if (it.mode == Mode.DEVICE) "This phone" else it.baseUrl
                            } ?: "Not connected",
                            appVersion = appVersion(),
                            updateVersion = updateVersion,
                            exportFolder = exportFolder,
                            pauseOnMetered = Settings.pauseOnMetered(this@MainActivity),
                            freeText = freeSpaceLine(),
                            profileLines = profileLines(),
                            onPickExportFolder = {
                                awaitingPicker = true
                                pickExportTree.launch(null)
                            },
                            onClearExportFolder = {
                                Settings.setExportTree(this@MainActivity, null)
                                exportFolder = null
                            },
                            onPauseOnMetered = {
                                Settings.setPauseOnMetered(this@MainActivity, it)
                                // Apply against the network the phone is on
                                // NOW: the service's callback only fires on a
                                // capability CHANGE, so without this the new
                                // setting waits for the network to move.
                                EngineService.notifyMeteredPolicyChanged()
                                // Re-read into a state the recomposition can
                                // see: the switch is drawn from the prefs and
                                // nothing else would tell Compose they moved.
                                note = if (it) {
                                    "Downloads will hold on a metered network."
                                } else {
                                    "Downloads will run on any network."
                                }
                            },
                            onOpenReleases = ::openReleasesPage,
                            onDisconnect = ::disconnect,
                        )
                    }
                    is Screen.Player -> {}
                }
            }
        }
    }

    // ---- update notice ----

    /**
     * This app's own version, as Android knows it. Read from the package
     * rather than from BuildConfig so no gradle feature has to be turned
     * on for it; the versionName is the crate's version (app/build.gradle.kts
     * reads it out of Cargo.toml), so it is the same string the engine
     * compares against.
     */
    private fun appVersion(): String =
        runCatching { packageManager.getPackageInfo(packageName, 0).versionName }
            .getOrNull() ?: ""

    /**
     * Ask the daemon whether a newer nzbfast exists, at most once a day.
     *
     * THE CADENCE, and why it is not a timer. The app checks when it
     * comes to the FOREGROUND and the day's check has not happened yet:
     * a release comes out a few times a year, so anything faster is a
     * poll loop over a fact that does not move, and anything on a
     * schedule of its own would have to wake a phone up to learn nothing.
     * Foreground is also the only moment the answer can be acted on -
     * there is no install path, so the whole value of the check is a card
     * in front of somebody who is looking at the screen.
     *
     * The gate is a stored deadline rather than a "last checked" stamp
     * so that the failure backoff is one number in one place; see
     * [updateCheckDue] for the clock-moved-backwards arm.
     *
     * NOTIFY ONLY. This reads a version string and puts it in a card.
     */
    private fun maybeCheckForUpdate() {
        val cl = client ?: return
        val now = System.currentTimeMillis()
        if (updateCheckInFlight || !UpdateNotice.due(this, now)) return
        updateCheckInFlight = true
        lifecycleScope.launch {
            val status = withContext(Dispatchers.IO) {
                runCatching { cl.updateCheck() }.getOrNull()
            }
            val at = System.currentTimeMillis()
            updateCheckInFlight = false
            if (status == null) {
                // Offline, an engine still coming up, a daemon too old to
                // know the mode, or a refused manifest. None of those is
                // "up to date", so nothing latched changes and the retry
                // is the short one.
                UpdateNotice.recordFailed(this@MainActivity, at)
                return@launch
            }
            UpdateNotice.recordChecked(this@MainActivity, at)
            // Compared against OUR version, not the daemon's. In device
            // mode they are the same number; in server mode the daemon
            // may be older than this app, and its verdict about itself
            // would be a false alarm here. `current` is the fallback for
            // a package with no readable versionName, where the daemon's
            // opinion is better than none.
            val local = appVersion().ifEmpty { status.current }
            val v = status.available?.takeIf { updateIsNewer(it, local) }
            UpdateNotice.setAvailable(this@MainActivity, v)
            updateVersion = v
        }
    }

    /**
     * Open the releases page in a browser. The ONE outward action this
     * feature has: no download, no installer intent, and no
     * REQUEST_INSTALL_PACKAGES permission behind it.
     */
    private fun openReleasesPage() {
        val i = Intent(Intent.ACTION_VIEW, Uri.parse(RELEASES_URL))
        runCatching { startActivity(i) }
            .onFailure { note = "No app on this phone can open $RELEASES_URL" }
    }

    // ---- settings surface helpers ----

    private fun freeSpaceLine(): String = when {
        connection?.mode != Mode.DEVICE ->
            "%.1f GB free where the server saves".format(snapshot?.diskFreeGb ?: 0.0)
        freeBytes > 0 -> "${DeviceProfile.humanBytes(freeBytes)} free on this phone"
        else -> "Free space on this phone is not known"
    }

    private fun lineNote(): String {
        val mbit = DeviceProfile.downstreamMbit(this)
        val n = DeviceProfile.connectionsForLine(this)
        return if (mbit > 0) {
            "$n connections, sized for the $mbit Mbit/s this network reports. " +
                "Your provider's own limit still applies."
        } else {
            "$n connections. This network does not report a speed, so this is " +
                "the low end. Your provider's own limit still applies."
        }
    }

    /**
     * What the phone told the engine about itself (TODO 281 AN4), read
     * back from the same functions that produced the arguments, so the
     * readout cannot drift from what was actually passed.
     */
    private fun profileLines(): List<String> = listOf(
        "Memory budget: ${DeviceProfile.memLimitArg(this)} " +
            "(of ${DeviceProfile.humanBytes(DeviceProfile.totalRamBytes(this))} on this device)",
        "Decode and repair workers: ${DeviceProfile.cpuWorkers()} " +
            "(of ${Runtime.getRuntime().availableProcessors()} cores)",
        lineNote(),
    )

    private fun disconnect() {
        pollJob?.cancel()
        pollJob = null
        deviceStartJob?.cancel()
        if (Store.savedMode(this) == Mode.DEVICE) {
            stopService(Intent(this, EngineService::class.java))
        }
        Store.clear(this)
        connection = null
        snapshot = null
        // The 90-sample throughput window is about ONE engine. Left
        // behind, the next connection's samples appended to the previous
        // one's and were charted against the new link's peak for about
        // three minutes - iOS clears both together (`AppState`), and this
        // side cleared only the snapshot.
        speedHistory = emptyList()
        note = null
        screen = Screen.Connect
    }

    /**
     * Copy one finished job into the chosen folder, on demand.
     *
     * The path comes from `mode=history` because the playback contract
     * does not carry one - see the `storage` field on HistorySlot for why
     * it does not and why this is the one caller that needs it.
     */
    private fun exportJob(job: PlaybackJob) {
        val tree = Settings.exportTree(this) ?: return
        val cl = client ?: return
        busy = true
        note = null
        lifecycleScope.launch {
            val msg = withContext(Dispatchers.IO) {
                val row = runCatching { cl.history() }.getOrNull()
                    ?.firstOrNull { it.nzoId == job.nzoId }
                when {
                    row == null || row.storage.isEmpty() ->
                        "Could not find that download on this phone any more."
                    else -> {
                        val r = Exporter.export(
                            this@MainActivity,
                            tree,
                            File(row.storage),
                            job.name,
                            job.nzoId,
                        )
                        if (r.error != null) {
                            "Could not save it: ${r.error}"
                        } else {
                            Settings.markExported(this@MainActivity, job.nzoId)
                            if (r.copied == 0) {
                                "Already saved to your folder."
                            } else {
                                "Saved ${r.copied} file(s) to your folder."
                            }
                        }
                    }
                }
            }
            busy = false
            note = msg
        }
    }

    // ---- connect flows ----

    /**
     * Ask for the notification permission if this Android has one and it
     * has not been answered yet.
     *
     * Called from the two places the engine is started, rather than at
     * launch: a permission prompt on first open, before the user has said
     * they want anything to run on the phone at all, is a prompt with no
     * context - and in server mode there is no service and nothing to
     * notify about, so it would never be asked for at all.
     */
    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return
        val granted = checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
        if (!granted) askNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun useDevice() {
        busy = true
        note = null
        ensureNotificationPermission()
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
            refreshFreeSpace()
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
                // Adopting a DIFFERENT remote engine is a change of
                // identity exactly as a disconnect is - same reason, and
                // this arm needs it said again because it never goes
                // through `disconnect`.
                speedHistory = emptyList()
                note = null
                screen = Screen.Home
                startPolling()
            }
        }
    }

    private fun testNewsServer(
        host: String,
        port: Int,
        tls: Boolean,
        user: String,
        pass: String,
        conns: Int,
    ) {
        busy = true
        note = null
        lifecycleScope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching { client!!.serverTest(host, port, tls, user, pass, conns) }
                    .getOrElse { app.nzbfast.mobile.api.ServerTestResult(false, it.message ?: "failed") }
            }
            busy = false
            note = if (r.ok) "Connected: ${r.detail}" else "Failed: ${r.detail}"
        }
    }

    private fun saveNewsServer(
        host: String,
        port: Int,
        tls: Boolean,
        user: String,
        pass: String,
        conns: Int,
    ) {
        busy = true
        note = null
        lifecycleScope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching { client!!.serverSave(host, port, tls, user, pass, conns) }
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
                    uri != null -> {
                        // Staged with a GENERIC label, and the real one
                        // resolved afterwards OFF the main thread.
                        // `queryDisplayName` is a query against a
                        // provider owned by whichever app did the
                        // sharing, and this activity is exported - so an
                        // inaccessible, throwing or merely slow provider
                        // crashed or froze the confirmation screen
                        // before it had appeared, on a share the user
                        // had not approved yet. Nothing needs the name
                        // in the first frame: it is a label on a sheet
                        // that is still asking.
                        pendingImport = PendingImport.File(uri, "shared.nzb")
                        lifecycleScope.launch {
                            val name = withContext(Dispatchers.IO) {
                                runCatching { queryDisplayName(uri) }.getOrNull()
                            }
                            val staged = pendingImport
                            if (name != null
                                && staged is PendingImport.File
                                && staged.uri == uri
                            ) {
                                pendingImport = PendingImport.File(uri, name)
                            }
                        }
                    }
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
                    val room = roomFor(bytes)
                    if (room is Room.No) error(room.why)
                    AddOutcome(client!!.addFile(name, bytes), (room as? Room.Tight)?.why)
                }
            }
            busy = false
            refreshFreeSpace()
            result.fold(
                onSuccess = { o ->
                    val r = o.result
                    note = when {
                        !r.ok -> "Add failed: ${r.error ?: "unknown error"}"
                        o.warning != null -> "Added. ${o.warning}"
                        else -> "Added."
                    }
                    if (r.ok) screen = Screen.Home
                },
                onFailure = { note = "Add failed: ${it.message}" },
            )
        }
    }

    private data class AddOutcome(
        val result: app.nzbfast.mobile.api.AddResult,
        val warning: String?,
    )

    /** The verdict of the pre-enqueue disk check - see [roomFor]. */
    private sealed class Room {
        data object Yes : Room()
        data class Tight(val why: String) : Room()
        data class No(val why: String) : Room()
    }

    /**
     * TODO 281 AN3's free-space truth, applied to the file in hand.
     *
     * Only in ON-DEVICE mode: in server mode the filesystem that matters
     * belongs to the daemon and this phone's `StatFs` describes an
     * unrelated volume, so the check would be an authoritative-sounding
     * answer to the wrong question. The daemon's own min-free hold covers
     * that side and always did.
     *
     * Two tiers, because the two mistakes are not the same size. Not
     * enough room for the PAYLOAD is a certain failure some hours in, and
     * telling somebody that up front is the whole point - so it refuses.
     * Not enough room for the payload plus the space an extract needs
     * beside it is a MAYBE, since a post that is not an archive needs no
     * such room, and refusing on a maybe would be the app substituting a
     * guess for the daemon's real guards. So that one is said out loud
     * and the add goes ahead.
     */
    private fun roomFor(nzb: ByteArray): Room {
        if (connection?.mode != Mode.DEVICE) return Room.Yes
        val payload = NzbSize.estimatePayloadBytes(nzb)
        if (payload <= 0L) return Room.Yes
        val free = DeviceProfile.freeBytes(DeviceProfile.downloadDir(this))
        if (free <= 0L) return Room.Yes
        val human = DeviceProfile.humanBytes(payload)
        if (free < payload) {
            return Room.No(
                "that download is about $human and this phone has " +
                    "${DeviceProfile.humanBytes(free)} free"
            )
        }
        if (free < NzbSize.estimatePeakBytes(nzb)) {
            return Room.Tight(
                "It is about $human, and unpacking it may need about that much " +
                    "again. There is ${DeviceProfile.humanBytes(free)} free."
            )
        }
        return Room.Yes
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

    /**
     * A provider query, which is a call into ANOTHER app's process:
     * slow at best, and free to throw. Never call it on the main
     * thread, and never before the user has approved the import - see
     * the ACTION_SEND arm of `handleIntent`.
     */
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
                job.stream.ifEmpty { cl.streamUrl(job.nzoId) ?: "" }
            }
            // No scoped URL and no /m3u answer: say so rather than
            // falling back to one carrying the master API key.
            if (url.isEmpty()) {
                busy = false
                note = "Could not open this job for playback."
                return@launch
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
        val what = if (paused) "resume downloading" else "pause downloading"
        mutate(what) { (if (paused) client?.resumeAll() else client?.pauseAll()) == true }
    }

    // ---- polling ----

    private fun startPolling() {
        // Here as well as in onStart, and not instead of it: on a cold
        // start there is no connection to ask yet - device mode is still
        // proving the engine, server mode has not been loaded - so onStart
        // alone would skip the check on exactly the launch that opens the
        // app. Both sites go through the once-a-day gate, so the pair
        // costs at most one call.
        maybeCheckForUpdate()
        pollJob?.cancel()
        pollJob = lifecycleScope.launch {
            // Has this poll job ever got an answer? See the failure arm.
            var reached = false
            while (isActive) {
                val cl = client
                // One poll for everything: readiness rides the job rows
                // (no per-job probes) and the telemetry feeds the player
                // overlay, so keep polling while the player is up.
                //
                // `visible` is the third condition and the newest: see the
                // field for why an off-screen activity must not poll.
                if (visible && cl != null && (screen is Screen.Home || screen is Screen.Player)) {
                    val snap = withContext(Dispatchers.IO) {
                        runCatching { cl.playback() }.getOrNull()
                    }
                    if (snap != null) {
                        reached = true
                        snapshot = snap
                        speedHistory = (speedHistory + snap.speedBps / 1e6).takeLast(90)
                        // A poll that reached the engine clears the
                        // status line, whichever of the two put a
                        // sentence there - the reach failure below, or a
                        // refused mutation ([mutate]). A note nothing
                        // clears is a stale sentence about a moment that
                        // has passed.
                        if (note?.startsWith("Could not reach") == true ||
                            note?.startsWith("The server refused") == true
                        ) {
                            note = null
                        }
                    } else if (reached && connection?.mode == Mode.DEVICE) {
                        // A call that stopped reaching the engine we proved.
                        // Both ways that happens say the same thing: a
                        // transport failure means nothing of ours is on that
                        // port any more, and an authentication failure means
                        // something is and it is not ours. Either way the
                        // credential is now addressed to a stranger, so drop
                        // it and prove the listener again rather than keep
                        // sending the key at it every two seconds.
                        //
                        // `reached` bounds this to ONE re-prove per streak of
                        // working polls. A daemon that answers the keyless
                        // challenge and then refuses the keyed call - a key
                        // this install no longer shares with it - would
                        // otherwise re-prove, fail, and re-prove forever.
                        startDeviceEngine(message = "Reconnecting to the engine…")
                        return@launch
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

    /**
     * A mutation whose REFUSAL the person can see.
     *
     * [io] is right for fire-and-forget work with nothing to report, and
     * wrong for every queue/history/global write on Home: those return a
     * meaningful Boolean (`NzbfastClient.pauseJob` and its siblings) and
     * it was dropped on the floor along with any exception, so a pause
     * the daemon refused, a delete against a stale api key and a global
     * resume against an engine that had gone all looked exactly like
     * success - the confirmation closed and nothing changed.
     *
     * `false` is a refusal and a throw is a transport/auth failure, and
     * the two get different sentences because they send the reader
     * somewhere different. Cleared by the poll loop's own note handling
     * the moment it reaches the engine again.
     */
    private fun mutate(what: String, block: () -> Boolean) {
        lifecycleScope.launch(Dispatchers.IO) {
            val outcome = runCatching(block)
            val problem = when {
                outcome.isFailure -> "Could not reach the server."
                outcome.getOrDefault(false) -> null
                else -> "The server refused to $what."
            }
            if (problem != null) {
                withContext(Dispatchers.Main) { note = problem }
            }
        }
    }
}
