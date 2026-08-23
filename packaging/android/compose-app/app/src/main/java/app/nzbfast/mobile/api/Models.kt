package app.nzbfast.mobile.api

import org.json.JSONObject

/**
 * Thin models over the daemon's SABnzbd-compat JSON. Parsers are pure
 * String -> model functions so the JVM snapshot tests exercise exactly
 * the code the app runs. Only fields the app reads are modeled; the
 * full field inventory lives in CONTRACT.md next to this app.
 */

data class QueueSlot(
    val nzoId: String,
    val name: String,
    val status: String,
    val percentage: Float,
    val mb: Double,
    val mbLeft: Double,
    val timeLeft: String,
    val activity: String,
)

data class QueueSnapshot(
    val paused: Boolean,
    val status: String,
    val kbPerSec: Double,
    val slots: List<QueueSlot>,
)

data class HistorySlot(
    val nzoId: String,
    val name: String,
    val status: String,
    val size: String,
    val failMessage: String,
    val completedAt: Long,
    /** The daemon judged this row to hold media: the latched `media`
     * chip when present, else the stored path's own extension (rows
     * recorded before the chip existed). Gates the Play action -
     * ISOs, software and archive-only jobs get none. */
    val playable: Boolean,
)

data class AddResult(
    val ok: Boolean,
    val nzoIds: List<String>,
    val error: String?,
)

/** /preview/probe: the daemon's own playability verdict for one job. */
data class ProbeResult(
    val file: String?,
    val mediaReady: Boolean,
    val pending: Boolean,
)

/**
 * Playback contract v1 (`mode=playback`): per-file readiness for one
 * job. `reason` is a closed token set - live, disk, pending,
 * not_fetched, not_started, moving, no_media, failed, unknown - so the
 * UI can branch on it without reading prose. `moving` is a wait (the
 * payload is being relocated to its final folder), `no_media` is final;
 * both carry ready=false, which is what the rows below branch on.
 */
data class Playback(
    val ready: Boolean,
    val reason: String,
    val file: String?,
    val size: Long,
    val source: String,
    val seekable: Boolean,
    val headBytes: Long,
    val pct: Double,
)

data class PlaybackJob(
    val nzoId: String,
    val name: String,
    val status: String,
    val percentage: Float,
    val mb: Double,
    val mbLeft: Double,
    val timeLeft: String,
    val activity: String,
    val failMessage: String,
    /** History rows: finished size in bytes (queue rows report mb/mbleft). */
    val bytes: Long,
    /** History rows: unix seconds of completion. */
    val completedAt: Long,
    val playback: Playback,
    /** Play URL carrying the job's scoped token, never the API key. */
    val stream: String,
)

/** Byte-serving telemetry behind the player's health overlay. */
data class StreamTelemetry(
    val readers: Int,
    val blockedReads: Long,
    val zeroFilledBytes: Long,
    val runwayMb: Long,
    val runwayWaitMs: Long,
)

/** The whole of `mode=playback`: the one call this app polls. */
data class PlaybackSnapshot(
    val contract: Int,
    val paused: Boolean,
    val speedBps: Double,
    // §125 anchor: the link's learned peak (bps) and where it came
    // from ("measured" | "line" | ""). 0 = no anchor known, and the
    // chart scales to its window instead.
    val linkPeakBps: Double,
    val linkPeakSrc: String,
    val diskFreeGb: Double,
    val warnings: Int,
    val queue: List<PlaybackJob>,
    val history: List<PlaybackJob>,
    val stream: StreamTelemetry,
)

data class ServerTestResult(
    val ok: Boolean,
    val detail: String,
)

object Parse {

    fun version(body: String): String =
        JSONObject(body).optString("version", "")

    fun queue(body: String): QueueSnapshot {
        val q = JSONObject(body).getJSONObject("queue")
        val slots = q.optJSONArray("slots")
        val out = ArrayList<QueueSlot>(slots?.length() ?: 0)
        if (slots != null) {
            for (i in 0 until slots.length()) {
                val s = slots.getJSONObject(i)
                out.add(
                    QueueSlot(
                        nzoId = s.optString("nzo_id"),
                        name = s.optString("filename"),
                        status = s.optString("status"),
                        percentage = s.optString("percentage", "0")
                            .toFloatOrNull() ?: 0f,
                        mb = s.optString("mb", "0").toDoubleOrNull() ?: 0.0,
                        mbLeft = s.optString("mbleft", "0").toDoubleOrNull() ?: 0.0,
                        timeLeft = s.optString("timeleft", ""),
                        activity = s.optString("activity", ""),
                    )
                )
            }
        }
        return QueueSnapshot(
            paused = q.optBoolean("paused", false),
            status = q.optString("status", ""),
            kbPerSec = q.optString("kbpersec", "0").toDoubleOrNull() ?: 0.0,
            slots = out,
        )
    }

    fun history(body: String): List<HistorySlot> {
        val h = JSONObject(body).getJSONObject("history")
        val slots = h.optJSONArray("slots") ?: return emptyList()
        val out = ArrayList<HistorySlot>(slots.length())
        for (i in 0 until slots.length()) {
            val s = slots.getJSONObject(i)
            out.add(
                HistorySlot(
                    nzoId = s.optString("nzo_id"),
                    name = s.optString("name"),
                    status = s.optString("status"),
                    size = s.optString("size"),
                    failMessage = s.optString("fail_message"),
                    completedAt = s.optLong("completed", 0),
                    playable = looksPlayable(s),
                )
            )
        }
        return out
    }

    /** Play gating (Codex sweep 5 Aug L3): the `media` chip the daemon
     * latched during the download says whether the bytes are media; a
     * row recorded before the chip existed falls back to the stored
     * path's extension (mirrors the daemon's MEDIA_EXTS list). */
    private val MEDIA_EXTS = listOf(".mkv", ".mp4", ".avi", ".m4v", ".ts", ".wmv")

    private fun looksPlayable(s: JSONObject): Boolean {
        val m = s.optJSONObject("media")
        if (m != null && (!m.isNull("res") || !m.isNull("vcodec") || !m.isNull("audio"))) {
            return true
        }
        for (key in listOf("storage", "name")) {
            val p = s.optString(key).lowercase()
            if (MEDIA_EXTS.any { p.endsWith(it) }) return true
        }
        return false
    }

    fun addResult(body: String): AddResult {
        val j = JSONObject(body)
        val ok = j.optBoolean("status", false)
        val ids = ArrayList<String>()
        j.optJSONArray("nzo_ids")?.let { a ->
            for (i in 0 until a.length()) ids.add(a.getString(i))
        }
        return AddResult(ok, ids, j.optString("error", "").ifEmpty { null })
    }

    fun probe(body: String): ProbeResult {
        val j = JSONObject(body)
        val media = j.optJSONObject("media")
        return ProbeResult(
            file = j.optString("file", "").ifEmpty { null },
            mediaReady = media != null,
            pending = j.optBoolean("pending", false),
        )
    }

    /**
     * `mode=playback` - the one call a phone polls: server state, both
     * job lists with per-file playback readiness, and the byte-serving
     * telemetry. Replaces queue + history + a probe per job.
     */
    fun playback(body: String): PlaybackSnapshot {
        val j = JSONObject(body)
        // A pre-contract daemon answers HTTP 200 with
        // {"status":false,"error":"unimplemented mode playback"} - parsing
        // that as an empty snapshot made setup save the connection and
        // left Home silently blank. Refuse anything that is not a
        // status:true contract-v1 body; the thrown message surfaces
        // through the existing runCatching paths in setup and polling.
        if (!j.optBoolean("status", false)) {
            throw Exception(
                j.optString("error").ifEmpty { "the daemon refused the playback call" },
            )
        }
        if (j.optInt("contract", 0) < 1) {
            throw Exception("this daemon does not support the mobile app - upgrade nzbfast")
        }
        val s = j.optJSONObject("stream")
        return PlaybackSnapshot(
            contract = j.optInt("contract", 0),
            paused = j.optBoolean("paused", false),
            speedBps = j.optDouble("speed_bps", 0.0),
            linkPeakBps = j.optDouble("link_peak", 0.0),
            linkPeakSrc = j.optString("link_peak_src", ""),
            diskFreeGb = j.optDouble("diskspace_gb", 0.0),
            warnings = j.optInt("warnings", 0),
            queue = playbackJobs(j.optJSONArray("queue")),
            history = playbackJobs(j.optJSONArray("history")),
            stream = StreamTelemetry(
                readers = s?.optInt("readers", 0) ?: 0,
                blockedReads = s?.optLong("blocked_reads", 0) ?: 0,
                zeroFilledBytes = s?.optLong("zero_filled_bytes", 0) ?: 0,
                runwayMb = s?.optLong("runway_mb", 0) ?: 0,
                runwayWaitMs = s?.optLong("runway_wait_ms", 0) ?: 0,
            ),
        )
    }

    private fun playbackJobs(arr: org.json.JSONArray?): List<PlaybackJob> {
        if (arr == null) return emptyList()
        val out = ArrayList<PlaybackJob>(arr.length())
        for (i in 0 until arr.length()) {
            val j = arr.getJSONObject(i)
            val p = j.optJSONObject("playback")
            val cov = p?.optJSONObject("coverage")
            out.add(
                PlaybackJob(
                    nzoId = j.optString("nzo_id"),
                    name = j.optString("name"),
                    status = j.optString("status"),
                    // Numbers, not quoted strings: that is the whole
                    // point of the mobile shapes over the SAB ones.
                    percentage = j.optDouble("percentage", 0.0).toFloat(),
                    mb = j.optDouble("mb", 0.0),
                    mbLeft = j.optDouble("mbleft", 0.0),
                    timeLeft = j.optString("timeleft", ""),
                    activity = j.optString("activity", ""),
                    failMessage = j.optString("fail_message", ""),
                    bytes = j.optLong("bytes", 0),
                    completedAt = j.optLong("completed", 0),
                    playback = Playback(
                        ready = p?.optBoolean("ready", false) ?: false,
                        reason = p?.optString("reason", "unknown") ?: "unknown",
                        file = p?.optString("file", "")?.ifEmpty { null },
                        size = p?.optLong("size", 0) ?: 0,
                        source = p?.optString("source", "none") ?: "none",
                        seekable = p?.optBoolean("seekable", false) ?: false,
                        headBytes = cov?.optLong("head_bytes", 0) ?: 0,
                        pct = cov?.optDouble("pct", 0.0) ?: 0.0,
                    ),
                    stream = j.optString("stream", ""),
                )
            )
        }
        return out
    }

    /**
     * `mode=stream_token`: the scoped per-job secret for a URL handed
     * outside the app (an external player, a share sheet). Null when
     * the daemon does not know the job.
     */
    fun streamToken(body: String): String? {
        val j = JSONObject(body)
        if (!j.optBoolean("status", false)) return null
        return j.optString("stream", "").ifEmpty { null }
    }

    fun serversConfigured(getConfigBody: String): Boolean =
        JSONObject(getConfigBody)
            .optJSONObject("config")
            ?.optJSONObject("nzbfast")
            ?.optBoolean("servers_configured", false)
            ?: false

    fun serverTest(body: String): ServerTestResult {
        val j = JSONObject(body)
        return if (j.optBoolean("status", false)) {
            ServerTestResult(true, j.optString("greeting", "connected"))
        } else {
            ServerTestResult(false, j.optString("error", "connection failed"))
        }
    }

    fun statusOk(body: String): Boolean =
        JSONObject(body).optBoolean("status", false)

    /**
     * /m3u body: "#EXTM3U\nhttp://host/stream/<id>?t=<token>". The
     * URL line carries the per-job stream token, which keeps the API
     * key out of long-lived player URLs.
     */
    fun m3uUrl(body: String): String? =
        body.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() && !it.startsWith("#") }
}
