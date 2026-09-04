package app.nzbfast.mobile.api

import org.json.JSONObject

/**
 * Hand-rolled client for the daemon endpoints this app uses. The full
 * request/response inventory is CONTRACT.md next to the app; keep the
 * two in sync when this grows.
 *
 * Auth: the API key rides the X-Api-Key header for /api calls (query
 * fallback exists server-side but headers keep keys out of logs).
 * Never send a `t` query param to /api - that path belongs to the
 * newznab facade.
 */
class NzbfastClient(private val baseUrl: String, private val apiKey: String) {

    private fun api(query: String): String =
        Http.get("$baseUrl/api?$query", apiKey = apiKey)

    fun version(): String = Parse.version(api("mode=version"))

    fun queue(): QueueSnapshot = Parse.queue(api("mode=queue"))

    fun history(): List<HistorySlot> = Parse.history(api("mode=history"))

    /**
     * Playback contract v1: the one call this app polls on Home and in
     * the player - server state, both job lists with per-file
     * readiness, and the byte-serving telemetry, in one response.
     */
    fun playback(limit: Int = 60): PlaybackSnapshot =
        Parse.playback(api("mode=playback&limit=$limit"))

    fun addFile(fileName: String, bytes: ByteArray, category: String? = null): AddResult {
        val fields = buildMap {
            put("apikey", apiKey)
            category?.let { put("cat", it) }
        }
        val body = Http.postMultipart(
            "$baseUrl/api?mode=addfile",
            fields,
            fileField = "nzbfile",
            fileName = fileName,
            fileBytes = bytes,
        )
        return Parse.addResult(body)
    }

    /**
     * Read a shared NZB with a client-side size bound - see
     * [Http.NZB_SIZE_LIMIT]. Throws [Http.TooLargeError] past it.
     *
     * Here rather than at the call site so every intake path gets the
     * bound, and so the UI has one exception class to report.
     */
    fun readSharedNzb(stream: java.io.InputStream, name: String): ByteArray =
        Http.readBounded(stream, name)

    fun addNzbLnk(link: String): AddResult =
        Parse.addResult(api("mode=addnzblnk&link=${Http.encode(link)}"))

    fun pauseJob(nzoId: String): Boolean =
        Parse.statusOk(api("mode=queue&name=pause&value=${Http.encode(nzoId)}"))

    fun resumeJob(nzoId: String): Boolean =
        Parse.statusOk(api("mode=queue&name=resume&value=${Http.encode(nzoId)}"))

    fun deleteJob(nzoId: String, deleteFiles: Boolean): Boolean =
        Parse.statusOk(
            api(
                "mode=queue&name=delete&value=${Http.encode(nzoId)}" +
                    if (deleteFiles) "&del_files=1" else ""
            )
        )

    fun deleteHistory(nzoId: String, deleteFiles: Boolean): Boolean =
        Parse.statusOk(
            api(
                "mode=history&name=delete&value=${Http.encode(nzoId)}" +
                    if (deleteFiles) "&del_files=1" else ""
            )
        )

    fun pauseAll(): Boolean = Parse.statusOk(api("mode=pause"))

    fun resumeAll(): Boolean = Parse.statusOk(api("mode=resume"))

    fun serversConfigured(): Boolean = Parse.serversConfigured(api("mode=get_config"))

    /**
     * Force an update check now. NOTIFY ONLY: the daemon fetches its
     * signed release manifest and reports a version, and nothing on
     * either side downloads or installs anything. Null when the check
     * did not answer - see [Parse.updateCheck].
     *
     * Called at most once a day from the foreground, never polled: this
     * is the one call in the client that makes the daemon reach out to
     * the internet, and the answer changes a few times a year.
     */
    fun updateCheck(): UpdateStatus? = Parse.updateCheck(api("mode=update_check"))

    /** Probe playability; 404 while nothing is downloadable yet. */
    fun probe(nzoId: String): ProbeResult? = try {
        Parse.probe(Http.get("$baseUrl/preview/probe/${Http.encode(nzoId)}", apiKey = apiKey))
    } catch (e: Http.HttpError) {
        null
    }

    /**
     * URL the player should open for a job, or null when one cannot be
     * minted. The /m3u body embeds the per-job stream token, so the
     * long-lived player URL never carries the API key.
     *
     * THERE IS NO APIKEY FALLBACK, and the fallback that used to be
     * here is why this returns null. It built
     * `/stream/<id>?apikey=<the full master key>` whenever /m3u errored
     * or came back malformed, and handed that to ExoPlayer - where
     * logcat, the media session, PiP metadata and any intermediary's
     * access log can retain it. That key is the credential that also
     * writes provider passwords through mode=server_save.
     *
     * The iOS twin never had one: `ApiClient.playURL(for:)` throws, and
     * its own comment records the lesson ("the long-lived full
     * credential rode a query string past every reverse proxy and URL
     * diagnostic", Codex sweep 12 Aug). Android reintroduced on the
     * fallback path what iOS had removed on the mint path.
     */
    fun streamUrl(nzoId: String): String? {
        val id = Http.encode(nzoId)
        return try {
            Parse.m3uUrl(Http.get("$baseUrl/m3u/$id", apiKey = apiKey))
        } catch (e: Exception) {
            null
        }
    }

    /** First-run news-server save. index -1 appends. */
    fun serverSave(
        host: String,
        port: Int,
        tls: Boolean,
        username: String,
        password: String,
        connections: Int = 8,
    ): Boolean {
        val body = serverJson(host, port, tls, username, password, connections)
        return Parse.statusOk(postJson("mode=server_save", body))
    }

    fun serverTest(
        host: String,
        port: Int,
        tls: Boolean,
        username: String,
        password: String,
        connections: Int = 8,
    ): ServerTestResult {
        val body = serverJson(host, port, tls, username, password, connections)
        return Parse.serverTest(postJson("mode=server_test", body))
    }

    private fun serverJson(
        host: String,
        port: Int,
        tls: Boolean,
        username: String,
        password: String,
        connections: Int,
    ): String {
        val server = JSONObject()
            .put("host", host)
            .put("port", port)
            .put("tls", tls)
            .put("username", username)
            .put("password", password)
            .put("connections", connections)
        return JSONObject().put("index", -1).put("server", server).toString()
    }

    private fun postJson(query: String, jsonBody: String): String =
        Http.postJson("$baseUrl/api?$query", jsonBody, apiKey = apiKey)
}
