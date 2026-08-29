package app.nzbfast.mobile.api

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Snapshot tests: the parsers run against responses recorded from a
 * real daemon (chaos_serve-backed; see CONTRACT.md for the recording
 * recipe). If the daemon's shapes drift, these fail before the app
 * does.
 *
 * The recordings are NOT all one vintage, and CONTRACT.md's drift
 * audit says which is which. The three queue and history ones were
 * re-recorded from 1.2.3 on 25 Aug 2026, when they were found still
 * carrying four seen-sets the payload had retired. The rest are 1.0.16
 * and stay that way while they answer with the same keys and types a
 * current daemon does - which for the four `playback_*` ones is
 * load-bearing rather than laziness, because the absence of
 * `link_peak` is exactly what one of the tests below is about.
 */
class ParseSnapshotTest {

    private fun snap(name: String): String =
        javaClass.classLoader!!.getResourceAsStream("snapshots/$name")!!
            .readBytes().toString(Charsets.UTF_8)

    @Test
    fun version() {
        assertEquals("4.5.0", Parse.version(snap("version.json")))
    }

    @Test
    fun queueDownloading() {
        val q = Parse.queue(snap("queue_downloading.json"))
        assertFalse(q.paused)
        assertEquals("Downloading", q.status)
        assertEquals(1, q.slots.size)
        val s = q.slots[0]
        assertEquals("SABnzbd_nzo_nzbfast1", s.nzoId)
        assertEquals("chaos-video", s.name)
        assertEquals("Downloading", s.status)
        assertEquals(7f, s.percentage, 0.01f)
        assertEquals(91.53, s.mb, 0.01)
        assertEquals(84.25, s.mbLeft, 0.01)
        assertEquals("fetching", s.activity)
    }

    @Test
    fun queueEmpty() {
        val q = Parse.queue(snap("queue_empty.json"))
        assertTrue(q.slots.isEmpty())
    }

    @Test
    fun historyCompleted() {
        val h = Parse.history(snap("history_completed.json"))
        assertEquals(1, h.size)
        assertEquals("chaos-video", h[0].name)
        assertEquals("Completed", h[0].status)
        assertEquals("91.5 MB", h[0].size)
        assertTrue(h[0].completedAt > 0)
        // The recorded row carries the §76 media chip (720p H.264), so
        // it earns the Play action.
        assertTrue(h[0].playable)
    }

    /** Codex sweep 5 Aug L3: Play used to render for EVERY Completed
     * row - ISOs, software, archive-only jobs got a dead button. No
     * media chip and no media extension means no Play. */
    @Test
    fun historyNonMediaGetsNoPlay() {
        val body = """{"history":{"noofslots":1,"slots":[{"nzo_id":"x",""" +
            """"name":"Some.App.v2","status":"Completed","size":"1 GB",""" +
            """"fail_message":"","completed":1,"media":null,""" +
            """"storage":"/out/Some.App.v2"}]}}"""
        val h = Parse.history(body)
        assertFalse(h[0].playable)
    }

    @Test
    fun addFileOk() {
        val r = Parse.addResult(snap("addfile.json"))
        assertTrue(r.ok)
        assertEquals(listOf("SABnzbd_nzo_nzbfast1"), r.nzoIds)
        assertNull(r.error)
    }

    @Test
    fun addNzbLnkBad() {
        val r = Parse.addResult(snap("addnzblnk_bad.json"))
        assertFalse(r.ok)
        assertTrue(r.nzoIds.isEmpty())
        assertEquals("that is not an nzblnk link", r.error)
    }

    @Test
    fun probeLiveIsPlayable() {
        val p = Parse.probe(snap("probe_live.json"))
        // Mid-download with the container parsed: media != null is the
        // Play affordance signal, exactly what the dashboard keys on.
        assertTrue(p.mediaReady)
        assertFalse(p.pending)
        assertEquals("Chaos.Test.Pattern.2026.720p.WEB.x264-BENCH.mkv", p.file)
    }

    @Test
    fun probeDiskIsPlayable() {
        val p = Parse.probe(snap("probe_disk.json"))
        assertTrue(p.mediaReady)
    }

    @Test
    fun serversConfigured() {
        assertTrue(Parse.serversConfigured(snap("get_config.json")))
    }

    @Test
    fun serverTestGreeting() {
        val r = Parse.serverTest(snap("server_test.json"))
        assertTrue(r.ok)
        assertEquals("200 mock ready", r.detail)
    }

    @Test
    fun serverSaveOk() {
        assertTrue(Parse.statusOk(snap("server_save.json")))
    }

    @Test
    fun globalPauseResume() {
        assertTrue(Parse.statusOk(snap("pause_all.json")))
        assertTrue(Parse.statusOk(snap("resume_all.json")))
        assertFalse(Parse.statusOk(snap("job_pause_missing.json")))
    }

    @Test
    fun wrongKeyIsStatusFalse() {
        assertFalse(Parse.statusOk(snap("auth_wrong_key.json")))
    }

    @Test
    fun m3uCarriesTokenUrl() {
        val url = Parse.m3uUrl(snap("m3u.txt"))
        assertNotNull(url)
        assertTrue(url!!.contains("/stream/SABnzbd_nzo_nzbfast1?t="))
        assertFalse(url.contains("apikey"))
    }

    // --- playback contract v1 (mode=playback, mode=stream_token) ---

    /** Early in a download: bytes are moving, nothing is playable yet. */
    @Test
    fun playbackPendingIsHonestlyNotReady() {
        val p = Parse.playback(snap("playback_pending.json"))
        assertEquals(1, p.contract)
        assertFalse(p.paused)
        assertEquals(1, p.queue.size)
        assertTrue(p.history.isEmpty())
        val j = p.queue[0]
        assertEquals("Downloading", j.status)
        assertFalse(j.playback.ready)
        assertEquals("pending", j.playback.reason)
        assertNull(j.playback.file)
    }

    /** Mid-download, container parsed: this is the Play affordance. */
    @Test
    fun playbackLiveIsPlayableWhileDownloading() {
        val p = Parse.playback(snap("playback_live.json"))
        val j = p.queue[0]
        assertTrue(j.playback.ready)
        assertEquals("live", j.playback.reason)
        assertEquals("live", j.playback.source)
        assertEquals("movie.mkv", j.playback.file)
        // tail_ok too, so scrubbing will work.
        assertTrue(j.playback.seekable)
        // Numbers arrive as numbers - no string parsing on this call.
        assertEquals(56f, j.percentage, 0.01f)
        assertEquals(2.86, j.mb, 0.01)
        // The play URL carries the job's scoped token, never the key.
        assertTrue(j.stream.contains("?t="))
        assertFalse(j.stream.contains("apikey"))
    }

    /**
     * §125 anchor fields are a contract ADDITION: a pre-addition daemon
     * (these 1.0.16 recordings) answers without them and the chart must
     * fall back to scale-to-window, so absence parses as 0 / "".
     */
    @Test
    fun playbackWithoutLinkPeakMeansNoAnchor() {
        val p = Parse.playback(snap("playback_live.json"))
        assertEquals(0.0, p.linkPeakBps, 0.0)
        assertEquals("", p.linkPeakSrc)
    }

    /** And a daemon that knows its link carries bps + source. */
    @Test
    fun playbackLinkPeakParses() {
        val body = snap("playback_live.json").replace(
            "\"paused\": false,",
            "\"paused\": false, \"link_peak\": 118500000.0, \"link_peak_src\": \"measured\",",
        )
        val p = Parse.playback(body)
        assertEquals(118500000.0, p.linkPeakBps, 0.0)
        assertEquals("measured", p.linkPeakSrc)
    }

    /**
     * Mid-download of a file too big to land whole: playable now, but
     * the tail (where the seek index lives) has not arrived - ready
     * WITHOUT seekable. Recorded behind chaos-serve --line so the
     * coverage is genuinely partial, unlike playback_live.json whose
     * small file landed whole.
     */
    @Test
    fun playbackLivePartialIsReadyButNotSeekable() {
        val p = Parse.playback(snap("playback_live_partial.json"))
        val j = p.queue[0]
        assertTrue(j.playback.ready)
        assertEquals("live", j.playback.reason)
        assertEquals("movie.mkv", j.playback.file)
        // The distinction this fixture exists for: ready and seekable
        // are different answers mid-download.
        assertFalse(j.playback.seekable)
        assertEquals(33.8, j.playback.pct, 0.01)
        assertTrue(j.playback.headBytes in 1 until j.playback.size)
    }

    /** Finished: the answer moves to disk and stays ready. */
    @Test
    fun playbackDoneReadsFromDisk() {
        val p = Parse.playback(snap("playback_done.json"))
        assertTrue(p.queue.isEmpty())
        val j = p.history[0]
        assertEquals("Completed", j.status)
        assertTrue(j.playback.ready)
        assertEquals("disk", j.playback.reason)
        assertTrue(j.playback.size > 0)
        assertEquals(100.0, j.playback.pct, 0.01)
        assertEquals(2994402L, j.bytes)
        assertTrue(j.completedAt > 0)
        // The overlay's telemetry rides the same response.
        assertEquals(3000L, p.stream.runwayWaitMs)
        assertEquals(0L, p.stream.zeroFilledBytes)
    }

    /**
     * TODO 281 AN2's drain latch, from BOTH sides, and the absent case is
     * the one that matters.
     *
     * The foreground service stops the engine on this key, so what a
     * daemon that predates the addition means by not sending it has to be
     * "I cannot tell" and not "there is nothing left to do". The four
     * `playback_*` fixtures are all pre-addition recordings, which makes
     * them the real negative case rather than a constructed one - the same
     * argument as `playbackWithoutLinkPeakMeansNoAnchor` above, and the
     * same reason CONTRACT.md says not to re-record them.
     */
    @Test
    fun playbackWithoutQueueIdleIsNotIdle() {
        assertFalse(Parse.playback(snap("playback_live.json")).queueIdle)
        assertFalse(Parse.playback(snap("playback_done.json")).queueIdle)
    }

    @Test
    fun playbackQueueIdleParses() {
        val body = snap("playback_done.json").replace(
            "\"paused\": false,",
            "\"paused\": false, \"queue_idle\": true,",
        )
        assertTrue(Parse.playback(body).queueIdle)
    }

    /**
     * The export path needs the on-disk directory, and only `mode=history`
     * carries one - see the `storage` field on HistorySlot.
     */
    @Test
    fun historyCarriesTheOnDiskPath() {
        val h = Parse.history(snap("history_completed.json"))
        assertTrue(h[0].storage.isNotEmpty())
        assertTrue(h[0].storage.startsWith("/"))
    }

    @Test
    fun streamTokenMintsAScopedUrl() {
        val url = Parse.streamToken(snap("stream_token.json"))
        assertNotNull(url)
        assertTrue(url!!.contains("/stream/SABnzbd_nzo_nzbfast1?t="))
        assertFalse(url.contains("apikey"))
        // A job the daemon does not have gets no token at all.
        assertNull(Parse.streamToken(snap("stream_token_unknown.json")))
    }
}
