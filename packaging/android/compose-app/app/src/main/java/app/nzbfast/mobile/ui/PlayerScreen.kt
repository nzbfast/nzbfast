package app.nzbfast.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.common.MediaItem
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.PlayerView
import app.nzbfast.mobile.api.PlaybackJob
import app.nzbfast.mobile.api.StreamTelemetry

/**
 * The test preview player: ExoPlayer on the daemon's /stream URL.
 * ExoPlayer plays Matroska natively with hardware decode, which is
 * the whole point of going native on Android. Transport controls come
 * from the Media3 PlayerView; the screen stays on while this screen
 * is visible.
 *
 * The buffer/health overlay reads the mode=playback poll that keeps
 * running behind the player: `stream` telemetry (blocked_reads,
 * zero_filled_bytes - process-wide cumulative counters, so the overlay
 * shows the movement since the player opened) plus the job's own
 * coverage for live jobs.
 *
 * ExoPlayer and PlayerView are both media3 `@UnstableApi`: the library
 * ships them outside its stable surface, so every call here needs an
 * explicit opt-in or `lintDebug` fails (TODO 158 item 5). We take it
 * once for the whole composable rather than per call site - the screen
 * exists to drive that player, so there is no non-media3 half of it to
 * protect. `androidx.annotation.OptIn`, spelled out, because the
 * unqualified name is Kotlin's own and they are not interchangeable.
 */
@androidx.annotation.OptIn(UnstableApi::class)
@Composable
fun PlayerScreen(
    streamUrl: String,
    title: String,
    job: () -> PlaybackJob?,
    telemetry: () -> StreamTelemetry?,
    inPip: () -> Boolean = { false },
    // The video's on-screen bounds, reported whenever they change, so the
    // caller can keep PictureInPictureParams.setSourceRectHint current -
    // that is what lets Android 12+ animate the transition into PiP from
    // the actual video position instead of a plain fade (PictureInPictureIssue).
    onVideoRectChanged: (android.graphics.Rect) -> Unit = {},
) {
    val context = LocalContext.current
    val view = LocalView.current

    val player = remember(streamUrl) {
        ExoPlayer.Builder(context).build().apply {
            setMediaItem(MediaItem.fromUri(streamUrl))
            playWhenReady = true
            prepare()
        }
    }

    DisposableEffect(player) {
        view.keepScreenOn = true
        onDispose {
            view.keepScreenOn = false
            player.release()
        }
    }

    // Seek discipline: a live job whose tail has not landed answers
    // playback.seekable=false - scrubbing into unfetched bytes would
    // stall the player against a hole (or read zeros mid-recovery).
    // Finished jobs and ready tails seek freely.
    val seekAllowed = job()?.playback?.let { it.source != "live" || it.seekable } ?: true
    val pip = inPip()

    Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
        Box(modifier = Modifier.fillMaxSize()) {
            AndroidView(
                factory = { ctx ->
                    PlayerView(ctx).apply {
                        this.player = player
                        setShowNextButton(false)
                        setShowPreviousButton(false)
                    }
                },
                update = { pv ->
                    // The OS draws its own chrome over a PiP window;
                    // ours would just shrink into noise.
                    pv.useController = !pip
                    pv.setShowFastForwardButton(seekAllowed)
                    pv.setShowRewindButton(seekAllowed)
                    // DefaultTimeBar honors View enablement for touch:
                    // the bar still draws position, it just refuses the
                    // scrub until the tail is ready.
                    pv.findViewById<androidx.media3.ui.DefaultTimeBar>(
                        androidx.media3.ui.R.id.exo_progress
                    )?.isEnabled = seekAllowed
                },
                modifier = Modifier.fillMaxSize().onGloballyPositioned { coords ->
                    // Skip while already in the PiP window itself - those
                    // bounds are the shrunk window, not a rect a future
                    // transition into PiP should aim for.
                    if (pip) return@onGloballyPositioned
                    val bounds = coords.boundsInWindow()
                    onVideoRectChanged(
                        android.graphics.Rect(
                            bounds.left.toInt(),
                            bounds.top.toInt(),
                            bounds.right.toInt(),
                            bounds.bottom.toInt(),
                        )
                    )
                },
            )
            if (!pip) {
                Text(
                    text = "Test preview  ·  $title",
                    style = MaterialTheme.typography.labelMedium,
                    color = Color.White,
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 8.dp)
                        .background(Color(0x80000000))
                        .padding(horizontal = 8.dp, vertical = 2.dp),
                )
                HealthOverlay(
                    job = job(),
                    telemetry = telemetry(),
                    modifier = Modifier
                        .align(Alignment.TopStart)
                        .padding(start = 8.dp, top = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun HealthOverlay(
    job: PlaybackJob?,
    telemetry: StreamTelemetry?,
    modifier: Modifier = Modifier,
) {
    // The counters are cumulative since daemon start; anchor at the
    // first sample so the overlay reports this session's movement.
    var baseline by remember { mutableStateOf<StreamTelemetry?>(null) }
    LaunchedEffect(telemetry) {
        if (baseline == null && telemetry != null) baseline = telemetry
    }
    val tele = telemetry ?: return
    val base = baseline ?: tele

    val waits = (tele.blockedReads - base.blockedReads).coerceAtLeast(0)
    val zeroed = (tele.zeroFilledBytes - base.zeroFilledBytes).coerceAtLeast(0)

    Column(
        modifier = modifier
            .background(Color(0x80000000))
            .padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(
            text = buildString {
                append("Buffer waits ")
                append(waits)
                if (zeroed > 0) {
                    append("  ·  gaps ")
                    append(formatBytes(zeroed))
                }
            },
            style = MaterialTheme.typography.labelSmall,
            color = if (zeroed > 0) Color(0xFFFFC24B) else Color.White,
        )
        if (job != null && job.playback.source == "live") {
            Text(
                text = buildString {
                    append("Fetched ")
                    append("%.0f%%".format(job.percentage))
                    append("  ·  ")
                    append(if (job.playback.seekable) "seek ready" else "seek not ready yet")
                },
                style = MaterialTheme.typography.labelSmall,
                color = Color.White,
            )
        }
    }
}

private fun formatBytes(b: Long): String = when {
    b >= 1_000_000 -> "%.1f MB".format(b / 1e6)
    b >= 1_000 -> "%.0f KB".format(b / 1e3)
    else -> "$b B"
}
