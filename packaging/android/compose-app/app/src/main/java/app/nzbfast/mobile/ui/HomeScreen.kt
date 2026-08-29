package app.nzbfast.mobile.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.nzbfast.mobile.api.PlaybackJob
import app.nzbfast.mobile.api.PlaybackSnapshot

/**
 * TODO 281 AN1: Home is the DOWNLOADER.
 *
 * What changed, and why each one is a change rather than a preference:
 *
 *   - The headline is the queue's own state - what is running, how fast,
 *     how much is left - not the Play button. This shell was built in the
 *     playback-first era and its queue row led with "Play test preview",
 *     which is a demo affordance sitting where the product is. Play is
 *     still on every row that can serve one; it is just not the point of
 *     the screen.
 *   - Pause, resume and delete are BUTTONS. They were swipe-only, which
 *     is a gesture with no discoverable name and, for delete, an
 *     irreversible one a pocket can perform. Swipe survives for
 *     pause/resume, where the worst case is a tap to undo it.
 *   - Delete asks first, and asks the question that actually matters on a
 *     phone: whether the bytes go too. A queue row's partials are worth
 *     nothing and default to going; a finished payload does not, and
 *     defaults to staying.
 *   - History says why a job failed, in the daemon's own words.
 */
@Composable
fun HomeScreen(
    snapshot: PlaybackSnapshot?,
    speedHistory: List<Double>,
    statusLine: String?,
    freeBytesLocal: Long,
    canExport: Boolean,
    onPlay: (PlaybackJob) -> Unit,
    onPauseJob: (String) -> Unit,
    onResumeJob: (String) -> Unit,
    onDeleteJob: (String, Boolean) -> Unit,
    onDeleteHistory: (String, Boolean) -> Unit,
    onExport: (PlaybackJob) -> Unit,
) {
    // Which row is asking to be deleted, and from which list. Held here
    // rather than per row so the dialog survives the list recomposing
    // under it when the next poll lands.
    var confirming by remember { mutableStateOf<DeleteRequest?>(null) }

    confirming?.let { req ->
        DeleteDialog(
            request = req,
            onDismiss = { confirming = null },
            onConfirm = { withFiles ->
                confirming = null
                if (req.fromHistory) onDeleteHistory(req.nzoId, withFiles)
                else onDeleteJob(req.nzoId, withFiles)
            },
        )
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
    ) {
        if (snapshot == null) {
            item { Text("Connecting...", style = MaterialTheme.typography.bodyLarge) }
        } else {
            item {
                StatusCard(
                    snapshot = snapshot,
                    speedHistory = speedHistory,
                    freeBytesLocal = freeBytesLocal,
                )
            }
            if (snapshot.queue.isEmpty()) {
                item {
                    Text(
                        if (snapshot.history.isEmpty()) {
                            "Nothing here yet. Tap + to add an NZB."
                        } else {
                            "Nothing downloading."
                        },
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
            items(snapshot.queue, key = { it.nzoId }) { job ->
                SwipeRow(
                    onSwipeRight = {
                        if (job.status == "Paused") onResumeJob(job.nzoId) else onPauseJob(job.nzoId)
                    },
                    rightLabel = if (job.status == "Paused") "Resume" else "Pause",
                ) {
                    QueueRow(
                        job = job,
                        onPlay = { onPlay(job) },
                        onPause = { onPauseJob(job.nzoId) },
                        onResume = { onResumeJob(job.nzoId) },
                        onDelete = {
                            confirming = DeleteRequest(job.nzoId, job.name, fromHistory = false)
                        },
                    )
                }
            }
            if (snapshot.history.isNotEmpty()) {
                item {
                    Spacer(Modifier.height(8.dp))
                    Text("History", style = MaterialTheme.typography.titleMedium)
                }
                items(snapshot.history, key = { "h-" + it.nzoId }) { job ->
                    HistoryRow(
                        job = job,
                        canExport = canExport,
                        onPlay = { onPlay(job) },
                        onExport = { onExport(job) },
                        onDelete = {
                            confirming = DeleteRequest(job.nzoId, job.name, fromHistory = true)
                        },
                    )
                }
            }
        }
        if (statusLine != null) {
            item {
                Text(
                    statusLine,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
    }
}

private data class DeleteRequest(
    val nzoId: String,
    val name: String,
    val fromHistory: Boolean,
)

/**
 * The one destructive confirmation in the app.
 *
 * The checkbox default differs by list and that is the whole point of
 * asking: a queue row's bytes are partial articles that are worth nothing
 * once the job is gone, so they default to going with it, while a history
 * row's bytes are the finished download and default to staying. Getting
 * that backwards in either direction is either a silent disk leak on a
 * phone or a deleted film.
 */
@Composable
private fun DeleteDialog(
    request: DeleteRequest,
    onDismiss: () -> Unit,
    onConfirm: (Boolean) -> Unit,
) {
    var withFiles by remember(request.nzoId) { mutableStateOf(!request.fromHistory) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (request.fromHistory) "Remove from history?" else "Cancel this download?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(request.name, maxLines = 3, overflow = TextOverflow.Ellipsis)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = withFiles, onCheckedChange = { withFiles = it })
                    Text(
                        if (request.fromHistory) {
                            "Delete the downloaded files too"
                        } else {
                            "Delete the part-downloaded files too"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(withFiles) }) {
                Text(if (request.fromHistory) "Remove" else "Cancel download")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Keep") } },
    )
}

/**
 * What the whole install is doing, above the list: the aggregate the
 * notification shows, on screen.
 *
 * The percentage is weighted by BYTES and not by averaging the per-job
 * percentages, for the reason EngineService.render gives: a 40 GB job at
 * 10% beside a 200 MB job at 90% is not halfway done.
 */
@Composable
private fun StatusCard(
    snapshot: PlaybackSnapshot,
    speedHistory: List<Double>,
    freeBytesLocal: Long,
) {
    val active = snapshot.queue
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val total = active.sumOf { it.mb }
            val left = active.sumOf { it.mbLeft }
            val pct = if (total > 0.0) ((total - left) / total * 100.0) else 0.0
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    when {
                        snapshot.paused -> "Paused"
                        active.isEmpty() -> "Idle"
                        else -> "%.1f MB/s".format(snapshot.speedBps / 1e6)
                    },
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    freeText(snapshot, freeBytesLocal),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (active.isNotEmpty()) {
                LinearProgressIndicator(
                    progress = { (pct / 100.0).toFloat().coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth(),
                )
                val eta = active.firstOrNull { it.status == "Downloading" }?.timeLeft.orEmpty()
                Text(
                    buildString {
                        append("%d %s".format(active.size, if (active.size == 1) "job" else "jobs"))
                        append("  ")
                        append("%.0f%%".format(pct))
                        if (left > 0.0) {
                            append("  ")
                            append("%.0f MB to go".format(left))
                        }
                        if (!snapshot.paused && eta.isNotEmpty() && eta != "0:00:00") {
                            append("  ")
                            append("$eta left")
                        }
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            // Two samples minimum: with fewer the canvas cannot draw a
            // line and the card is an empty stub for the first polls.
            if (active.isNotEmpty() && speedHistory.size >= 2) {
                ThroughputChart(
                    samples = speedHistory,
                    linkPeakMBps = snapshot.linkPeakBps / 1e6,
                    linkPeakSrc = snapshot.linkPeakSrc,
                )
            }
        }
    }
}

/**
 * Free space, from the phone's own filesystem where that is known.
 *
 * `diskspace_gb` on the contract is the DAEMON's answer about its own out
 * directory, which is right for a server across the room and is the same
 * volume this app measures when the engine is on this phone. The local
 * StatFs reading wins when there is one, because it is the filesystem
 * that will actually refuse the write (DeviceProfile.freeBytes).
 */
private fun freeText(snapshot: PlaybackSnapshot, freeBytesLocal: Long): String {
    val gb = if (freeBytesLocal > 0) freeBytesLocal / 1e9 else snapshot.diskFreeGb
    return "%.1f GB free".format(gb)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SwipeRow(
    onSwipeRight: () -> Unit,
    rightLabel: String,
    content: @Composable () -> Unit,
) {
    val right = rememberUpdatedState(onSwipeRight)
    // confirmValueChange fires the action and refuses the dismiss, so the
    // row snaps back and the next poll shows the new state. The LazyColumn
    // keys rows by nzo_id, so each row owns its own state.
    //
    // ONE DIRECTION ONLY since TODO 281 AN1: the left swipe used to
    // delete, immediately and with no confirmation, which is a gesture a
    // pocket can perform on an irreversible action. Delete is a button
    // with a dialog now; pause and resume keep the gesture because the
    // worst a stray one costs is a tap.
    val state = rememberSwipeToDismissBoxState(
        confirmValueChange = { v ->
            if (v == SwipeToDismissBoxValue.StartToEnd) right.value()
            false
        },
    )
    SwipeToDismissBox(
        state = state,
        enableDismissFromStartToEnd = true,
        enableDismissFromEndToStart = false,
        backgroundContent = {
            Row(
                Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) { Text(rightLabel) }
        },
        content = { content() },
    )
}

/**
 * Rolling throughput chart, anchored the way the web dashboard's is
 * (§125): a known link peak is 100%, drawn as a dashed rule with ~4% of
 * air above it, so working well reads as a band riding the rule and a blip
 * past the peak pokes above it without rescaling the history. No known
 * peak (link_peak 0) = scale to the window.
 */
@Composable
private fun ThroughputChart(
    samples: List<Double>,
    linkPeakMBps: Double,
    linkPeakSrc: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        if (linkPeakMBps > 0.0) {
            val cur = samples.lastOrNull() ?: 0.0
            val pct = (cur / linkPeakMBps * 100.0).coerceAtLeast(0.0)
            Text(
                "%.0f%% of %.1f MB/s".format(pct, linkPeakMBps) +
                    if (linkPeakSrc == "line") " line speed" else " peak",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        val accent = MaterialTheme.colorScheme.primary
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(48.dp),
        ) {
            if (samples.size < 2) return@Canvas
            // The anchor pins the scale's lower bound; the window max can
            // still push past it, so an over-peak blip clips the rule
            // instead of squashing everything below it.
            val floor = if (linkPeakMBps > 0.0) linkPeakMBps * 1.04 else 0.0
            val max = maxOf(samples.max(), floor, 0.001)
            val stepX = size.width / (samples.size - 1).toFloat()
            val pad = 2f
            fun y(v: Double): Float =
                size.height - pad - ((v / max) * (size.height - pad * 2)).toFloat()
            val line = Path()
            samples.forEachIndexed { i, v ->
                if (i == 0) line.moveTo(0f, y(v)) else line.lineTo(i * stepX, y(v))
            }
            val area = Path().apply {
                addPath(line)
                lineTo(size.width, size.height)
                lineTo(0f, size.height)
                close()
            }
            drawPath(area, accent.copy(alpha = 0.18f))
            drawPath(line, accent, style = Stroke(width = 2.dp.toPx()))
            if (linkPeakMBps > 0.0) {
                val py = y(linkPeakMBps)
                drawLine(
                    color = accent.copy(alpha = 0.55f),
                    start = Offset(0f, py),
                    end = Offset(size.width, py),
                    strokeWidth = 1.dp.toPx(),
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(12f, 8f)),
                )
            }
        }
    }
}

@Composable
private fun QueueRow(
    job: PlaybackJob,
    onPlay: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                job.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            LinearProgressIndicator(
                progress = { (job.percentage / 100f).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                buildString {
                    append(job.status)
                    append("  ")
                    append("%.0f%%".format(job.percentage))
                    if (job.status == "Downloading" && job.timeLeft.isNotEmpty() &&
                        job.timeLeft != "0:00:00"
                    ) {
                        append("  ")
                        append("${job.timeLeft} left")
                    }
                    if (job.mbLeft > 0.0) {
                        append("  ")
                        append("%.0f MB to go".format(job.mbLeft))
                    }
                    // The activity token names the phase a tail is in -
                    // repairing, extracting, moving - which is the part of
                    // a download that otherwise looks like a stall.
                    if (job.activity.isNotEmpty() && job.activity != "fetching") {
                        append("  ")
                        append(job.activity)
                    }
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (job.status == "Paused") {
                    TextButton(onClick = onResume) { Text("Resume") }
                } else {
                    TextButton(onClick = onPause) { Text("Pause") }
                }
                TextButton(onClick = onDelete) { Text("Cancel") }
                Spacer(Modifier.weight(1f))
                // playback.ready on the row replaces the per-job probe:
                // reason "live" (or "disk") means /stream serves it now.
                if (job.playback.ready) {
                    FilledTonalButton(onClick = onPlay) { Text("Play") }
                }
            }
        }
    }
}

@Composable
private fun HistoryRow(
    job: PlaybackJob,
    canExport: Boolean,
    onPlay: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                job.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            val failed = job.status == "Failed"
            Text(
                historyDetail(job),
                style = MaterialTheme.typography.bodySmall,
                color = if (failed) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = onDelete) { Text("Remove") }
                Spacer(Modifier.weight(1f))
                if (canExport && job.status == "Completed") {
                    TextButton(onClick = onExport) { Text("Save to folder") }
                }
                // reason "disk" = the file is really still there; a row
                // whose media has been cleaned away ("no_media") gets no
                // Play, and one being relocated ("moving") is asked to
                // wait rather than written off.
                if (job.playback.ready) {
                    FilledTonalButton(onClick = onPlay) { Text("Play") }
                }
            }
        }
    }
}

/**
 * The history subtitle, which is where a failure has to say what went
 * wrong.
 *
 * `fail_message` is the daemon's own sentence and is passed through
 * unedited: the alternative is a phone-side translation table that goes
 * stale the first time a new refusal is written, and a wrong explanation
 * of a failure is worse than a blunt one.
 */
private fun historyDetail(job: PlaybackJob): String = when {
    job.status == "Failed" -> job.failMessage.ifEmpty { "Failed" }
    // The move window: the payload is whole and in flight to its final
    // folder, which used to read as "gone" before the contract grew a
    // token for it.
    job.playback.reason == "moving" -> "Moving to its folder"
    job.status == "Completed" && job.bytes > 0 -> "%.0f MB".format(job.bytes / 1e6)
    else -> job.status
}
