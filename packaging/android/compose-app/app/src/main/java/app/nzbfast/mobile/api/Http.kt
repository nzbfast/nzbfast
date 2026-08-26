package app.nzbfast.mobile.api

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Minimal HTTP plumbing for the hand-rolled daemon client. The app
 * deliberately has no HTTP library dependency: the daemon API is a
 * handful of GETs plus one multipart POST, and HttpURLConnection
 * covers both on every supported API level.
 */
internal object Http {

    /**
     * `body` is the response body, not just the excerpt in the message:
     * the daemon's keyless 403 refusal carries the launcher handshake proof
     * in its JSON, and [app.nzbfast.mobile.EngineIdentity] has to read it
     * off a non-2xx reply.
     */
    class HttpError(val code: Int, val body: String) :
        Exception("HTTP $code: ${body.take(200)}")

    class TooLargeError(val name: String) :
        Exception("$name is too big to be an NZB")

    /**
     * Ceiling on an NZB this app will read into memory.
     *
     * The biggest real NZB is a few tens of megabytes - roughly a
     * kilobyte per segment, so a 100 GB post lands near 30 MB. This sits
     * comfortably past that and far below what a phone can be made to
     * swallow.
     *
     * The bound has to be HERE. The daemon caps `addfile` at 256 MiB,
     * which protects the daemon and arrives long after the phone has
     * already allocated the whole stream plus a payload-sized multipart
     * copy of it - and a content URI handed over by a share intent is
     * served by whatever app sent it, which is free to return an
     * arbitrarily long stream and to lie about its length (Codex sweep
     * 12 Aug F14).
     */
    const val NZB_SIZE_LIMIT: Int = 64 shl 20

    fun encode(v: String): String = URLEncoder.encode(v, "UTF-8")

    /**
     * Read at most [NZB_SIZE_LIMIT] bytes, throwing [TooLargeError] the
     * moment the stream proves longer. Counted as it is read: declared
     * content-provider metadata is never the bound, because a hostile
     * provider controls it.
     */
    fun readBounded(s: InputStream, name: String): ByteArray {
        val buf = ByteArrayOutputStream()
        val chunk = ByteArray(64 * 1024)
        var total = 0L
        s.use {
            while (true) {
                val n = it.read(chunk)
                if (n <= 0) break
                total += n
                if (total > NZB_SIZE_LIMIT) throw TooLargeError(name)
                buf.write(chunk, 0, n)
            }
        }
        return buf.toByteArray()
    }

    fun get(url: String, apiKey: String? = null, timeoutMs: Int = 10_000): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        if (!apiKey.isNullOrEmpty()) c.setRequestProperty("X-Api-Key", apiKey)
        try {
            val code = c.responseCode
            val body = readAll(if (code in 200..299) c.inputStream else c.errorStream)
            if (code !in 200..299) throw HttpError(code, body)
            return body
        } finally {
            c.disconnect()
        }
    }

    /** One multipart/form-data POST: form fields plus a single file part. */
    fun postMultipart(
        url: String,
        fields: Map<String, String>,
        fileField: String,
        fileName: String,
        fileBytes: ByteArray,
        timeoutMs: Int = 30_000,
    ): String {
        val boundary = "nzbfast-${System.nanoTime()}"
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        c.requestMethod = "POST"
        c.doOutput = true
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        try {
            c.outputStream.use { out ->
                val w = out.bufferedWriter(Charsets.UTF_8)
                for ((k, v) in fields) {
                    w.write("--$boundary\r\n")
                    w.write("Content-Disposition: form-data; name=\"$k\"\r\n\r\n")
                    w.write("$v\r\n")
                }
                w.write("--$boundary\r\n")
                w.write(
                    "Content-Disposition: form-data; name=\"$fileField\"; " +
                        "filename=\"${fileName.replace("\"", "_")}\"\r\n"
                )
                w.write("Content-Type: application/x-nzb\r\n\r\n")
                w.flush()
                out.write(fileBytes)
                out.flush()
                w.write("\r\n--$boundary--\r\n")
                w.flush()
            }
            val code = c.responseCode
            val body = readAll(if (code in 200..299) c.inputStream else c.errorStream)
            if (code !in 200..299) throw HttpError(code, body)
            return body
        } finally {
            c.disconnect()
        }
    }

    /** JSON POST used by server_save / server_test. */
    fun postJson(url: String, body: String, apiKey: String? = null, timeoutMs: Int = 20_000): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        if (!apiKey.isNullOrEmpty()) c.setRequestProperty("X-Api-Key", apiKey)
        c.requestMethod = "POST"
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        try {
            c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = c.responseCode
            val text = readAll(if (code in 200..299) c.inputStream else c.errorStream)
            if (code !in 200..299) throw HttpError(code, text)
            return text
        } finally {
            c.disconnect()
        }
    }

    /**
     * The ceiling on a RESPONSE body held in memory.
     *
     * `copyTo` had none: a misconfigured or hostile endpoint - or an
     * endlessly chunked answer from something else that grabbed the
     * port on a LAN the app talks to in cleartext - could grow this
     * until Android killed the process. Every endpoint this client
     * calls answers with a JSON document; the largest of them by far is
     * a full mode=queue plus history snapshot, which is measured in
     * hundreds of kilobytes even on a very deep queue, so 32 MiB is
     * three orders of magnitude of headroom and still bounded.
     */
    private const val RESPONSE_LIMIT = 32L * 1024 * 1024

    private fun readAll(s: InputStream?): String {
        if (s == null) return ""
        val buf = ByteArrayOutputStream()
        val chunk = ByteArray(64 * 1024)
        var total = 0L
        s.use {
            while (true) {
                val n = it.read(chunk)
                if (n <= 0) break
                total += n
                // Truncate rather than throw: this is also the ERROR
                // path (`c.errorStream`), and an oversized error body
                // must still produce the HttpError its caller is
                // waiting on, with a bounded excerpt in it.
                if (total > RESPONSE_LIMIT) break
                buf.write(chunk, 0, n)
            }
        }
        return buf.toString("UTF-8")
    }
}
