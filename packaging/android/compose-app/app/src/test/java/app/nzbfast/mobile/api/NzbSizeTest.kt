package app.nzbfast.mobile.api

import app.nzbfast.mobile.DeviceProfile
import app.nzbfast.mobile.Exporter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TODO 281 AN3/AN4: the three pure functions behind the storage and
 * device-profile work, exercised on the JVM.
 *
 * Everything else in those files needs a `Context` or a document
 * provider and belongs on the emulator. These three do not, and they are
 * the ones where being wrong is silent: a size estimate that reads low
 * lets a download start that cannot finish, and a name the provider
 * rewrites makes the already-exported check miss its own output forever.
 */
class NzbSizeTest {

    private fun nzb(vararg segmentBytes: Long): ByteArray {
        val sb = StringBuilder("<?xml version=\"1.0\"?><nzb><file subject=\"x\"><segments>")
        segmentBytes.forEachIndexed { i, b ->
            sb.append("<segment bytes=\"$b\" number=\"${i + 1}\">id$i@example</segment>")
        }
        sb.append("</segments></file></nzb>")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    @Test
    fun sumsEverySegment() {
        assertEquals(6_000L, NzbSize.declaredEncodedBytes(nzb(1_000, 2_000, 3_000)))
    }

    @Test
    fun anNzbWithNoSegmentsDeclaresNothing() {
        assertEquals(0L, NzbSize.declaredEncodedBytes("<nzb></nzb>".toByteArray()))
        assertEquals(0L, NzbSize.declaredEncodedBytes(ByteArray(0)))
    }

    /**
     * The payload is UNDER the declared figure, never over: the declared
     * bytes are what crosses the wire, yEnc included, and this number is
     * compared against free space.
     */
    @Test
    fun payloadIsBelowTheDeclaredWireBytes() {
        val b = nzb(103_000)
        val declared = NzbSize.declaredEncodedBytes(b)
        val payload = NzbSize.estimatePayloadBytes(b)
        assertTrue(payload < declared)
        assertTrue(payload > declared * 9 / 10)
        // The peak the pre-enqueue warning compares against leaves room
        // for an extract beside the payload.
        assertEquals(payload * 2, NzbSize.estimatePeakBytes(b))
    }

    /**
     * A run of digits long enough to overflow a Long must not wrap into a
     * small number: that would report a colossal post as one that fits,
     * which is the exact direction this check exists to refuse.
     */
    @Test
    fun anAbsurdSegmentSizeSaturatesRatherThanWrapping() {
        val b = "<segment bytes=\"99999999999999999999999999\">x</segment>".toByteArray()
        assertTrue(NzbSize.declaredEncodedBytes(b) >= 0L)
    }

    /**
     * The AGGREGATE saturates too: ten valid 18-digit declarations sum
     * past Long.MAX_VALUE, and a wrapped total is negative, which the
     * pre-enqueue check reads as "fits". Overflow must mean too large.
     */
    @Test
    fun manyHugeSegmentsSaturateTheTotal() {
        val b = nzb(*LongArray(10) { 999_999_999_999_999_999L })
        assertEquals(Long.MAX_VALUE, NzbSize.declaredEncodedBytes(b))
        assertTrue(NzbSize.estimatePayloadBytes(b) > 0L)
        assertTrue(NzbSize.estimatePeakBytes(b) > 0L)
    }

    /** A 19-digit value is too large, never zero. */
    @Test
    fun aNineteenDigitValueSaturatesRatherThanVanishing() {
        val b = "<segment bytes=\"9999999999999999999\">x</segment>".toByteArray()
        assertEquals(Long.MAX_VALUE, NzbSize.declaredEncodedBytes(b))
    }

    /** The doubled peak clamps rather than wrapping negative. */
    @Test
    fun theDoubledPeakClampsAtMax() {
        val b = nzb(*LongArray(8) { 999_999_999_999_999_999L })
        assertTrue(NzbSize.estimatePayloadBytes(b) > Long.MAX_VALUE / 2)
        assertEquals(Long.MAX_VALUE, NzbSize.estimatePeakBytes(b))
    }

    /**
     * A display name a document provider will accept, and - the part that
     * matters - one it will not REWRITE. A separator in a display name is
     * read differently by different providers, and the export's
     * already-copied check compares names.
     */
    @Test
    fun exportNamesAreSafeForADocumentProvider() {
        assertEquals("a_b", Exporter.safeName("a/b"))
        assertEquals("a_b", Exporter.safeName("a:b"))
        assertEquals("download", Exporter.safeName(""))
        assertEquals("download", Exporter.safeName("   "))
        // A trailing dot is a name several filesystems silently drop.
        assertEquals("movie", Exporter.safeName("movie."))
        assertTrue(Exporter.safeName("x".repeat(500)).length <= 200)
        // An ordinary name is left exactly alone, extension included.
        assertEquals("Some.Film.2026.mkv", Exporter.safeName("Some.Film.2026.mkv"))
    }

    /**
     * The worker cap with no sysfs to read, which is what a JVM host is
     * and what a kernel without cpufreq exposed looks like: still a real
     * number, still at least two, never more than the machine has.
     */
    @Test
    fun cpuWorkersFallsBackToSomethingSane() {
        val all = Runtime.getRuntime().availableProcessors()
        val n = DeviceProfile.cpuWorkers()
        assertTrue(n >= 2)
        assertTrue(n <= all.coerceAtLeast(2))
    }

    @Test
    fun humanBytesReadsAsSizesPeopleUse() {
        assertEquals("1.5 GB", DeviceProfile.humanBytes(1_500_000_000L))
        assertEquals("12 MB", DeviceProfile.humanBytes(12_000_000L))
        assertFalse(DeviceProfile.humanBytes(0L).contains("GB"))
    }
}
