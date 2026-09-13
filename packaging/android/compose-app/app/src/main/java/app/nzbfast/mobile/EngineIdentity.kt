package app.nzbfast.mobile

import android.content.Context
import app.nzbfast.mobile.api.Http
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.delay
import org.json.JSONObject

/**
 * Proving that the thing answering the loopback port is OUR engine, before
 * a single byte of the API key is sent to it.
 *
 * The app used to treat "ProcessBuilder.start() did not throw" as proof
 * that the daemon owned 127.0.0.1 on a fixed port, then send the persistent
 * per-install full key in `X-Api-Key` to whoever held it and accept
 * any non-empty version reply. Android apps share one loopback namespace,
 * so another INTERNET-capable app could pre-bind the port, record the key
 * and answer `{"version":"x"}`; the real daemon exited on EADDRINUSE while
 * the UI attached to the impostor. That captured key is a FULL key - it
 * controls the real daemon on the next start and reads back stored
 * provider credentials through `mode=server_secret` (review sweep 12 Aug
 * F4).
 *
 * The daemon already publishes what is needed: `runtime.json`, written
 * beside its config on every start, carrying the port and a per-start
 * secret token, and `mode=version&hs=<nonce>` answers
 * `hs_proof = sha256(token:nonce)`. That reply needs no key, so the
 * challenge can go to a stranger safely - and a stranger cannot answer it,
 * because `runtime.json` lives in app-private storage that no other app
 * can read. Same handshake the Mac wrapper and the Windows tray use.
 */
object EngineIdentity {

    data class Runtime(val port: Int, val tls: Boolean, val token: String)

    /** Where the daemon's config lives - see [EngineService.startEngine]. */
    fun runtimeFile(ctx: Context): File = File(File(ctx.filesDir, "config"), "runtime.json")

    fun readRuntime(ctx: Context): Runtime? {
        val f = runtimeFile(ctx)
        if (!f.isFile) return null
        return try {
            val o = JSONObject(f.readText())
            val token = o.optString("token", "")
            val port = o.optInt("port", 0)
            if (token.isEmpty() || port !in 1..65535) return null
            Runtime(port, o.optBoolean("tls", false), token)
        } catch (_: Exception) {
            null
        }
    }

    private fun nonce(): String {
        val b = ByteArray(16)
        SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    private fun expectedProof(token: String, nonce: String): String {
        val d = MessageDigest.getInstance("SHA-256")
        d.update(token.toByteArray(Charsets.UTF_8))
        d.update(':'.code.toByte())
        d.update(nonce.toByteArray(Charsets.UTF_8))
        return d.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * One challenge. True only when the listener returned the proof for
     * OUR token and OUR nonce.
     *
     * No API key is sent, and none is needed: the daemon answers a KEYLESS
     * `mode=version` (the `version_probe` exemption the container
     * healthcheck and the desktop wrappers use), and its keyless refusal
     * carries `hs_proof` too, so both replies work. That exemption also
     * means these probes are not counted as auth failures, so retrying is
     * free. Sending the key here is the whole bug - so it is not sent.
     */
    private fun challenge(rt: Runtime): Boolean {
        val n = nonce()
        val scheme = if (rt.tls) "https" else "http"
        val body = try {
            Http.get("$scheme://127.0.0.1:${rt.port}/api?mode=version&hs=$n", timeoutMs = 3_000)
        } catch (e: Http.HttpError) {
            // A keyed daemon answers the keyless probe with 403 and the
            // proof in the body - that IS the success path here.
            e.body
        } catch (_: Exception) {
            // Nothing listening yet, or a connection reset. Not a failure
            // of identity, just not an answer - the caller retries.
            return false
        }
        val got = try {
            JSONObject(body).optString("hs_proof", "")
        } catch (_: Exception) {
            ""
        }
        if (got.isEmpty()) return false
        // Constant-time-ish: these are hex digests of equal length, and the
        // comparison is against a value we already hold, so the only thing
        // a timing signal could leak is the proof itself.
        return MessageDigest.isEqual(
            got.toByteArray(Charsets.UTF_8),
            expectedProof(rt.token, n).toByteArray(Charsets.UTF_8),
        )
    }

    /**
     * Wait for a listener that PROVES it is our engine, and return what
     * runtime.json says about it. Null means it never did - the caller must
     * not fall back to sending the key anyway.
     *
     * `runtime.json` is re-read every attempt on purpose: it is rewritten
     * on each daemon start, so a stale file from an earlier run is replaced
     * while this loop runs rather than being trusted or specially detected.
     */
    suspend fun awaitVerified(ctx: Context, tries: Int = 60, gapMs: Long = 500): Runtime? {
        repeat(tries) {
            val rt = readRuntime(ctx)
            // There is no expected port to compare against any more, and
            // that is the point: the engine is started with `--port 0` so
            // the OS picks, and this file is the only thing that knows the
            // answer (EngineService). What `rt.port == PORT` used to guard
            // was "the record describes the listener the UI will actually
            // talk to" - and that still holds, more tightly than before,
            // because the caller now takes its endpoint from the Runtime
            // RETURNED here instead of deriving one separately (Store).
            //
            // A stale record is still rejected, by the challenge instead of
            // by the port: the token is minted per daemon start, so an old
            // file names a port with nothing of ours behind it, and whatever
            // does answer there cannot produce the proof.
            //
            // `tls` is still checked - we pass no TLS flag, so a record
            // claiming https is not describing our engine.
            if (rt != null && !rt.tls && challenge(rt)) {
                return rt
            }
            delay(gapMs)
        }
        return null
    }
}
