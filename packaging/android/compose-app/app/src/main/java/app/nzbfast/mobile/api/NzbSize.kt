package app.nzbfast.mobile.api

/**
 * How big an NZB is about to be, read out of the NZB itself.
 *
 * TODO 281 AN3's free-space truth: a phone has one small filesystem and no
 * dialog to offer when it fills, so the honest moment to say "this will
 * not fit" is BEFORE the add, while the file is already in hand and the
 * answer costs a scan. The desktop equivalent is the min-free hold, which
 * catches the same thing later and on a machine that can usually afford
 * the wait.
 *
 * ADVISORY, and the caller must treat it that way. It is a sum of the
 * `bytes` attributes the poster wrote, so a poster who wrote them wrongly
 * is believed, and the on-disk figure it implies is an estimate for the
 * reasons in [estimateBytes]. Nothing here refuses an add; the daemon's
 * own guards still do that with real numbers.
 */
object NzbSize {

    /**
     * Total ENCODED bytes an NZB declares: the sum of every
     * `<segment bytes="...">`.
     *
     * Scanned rather than parsed. The alternative is an XML parse of a
     * file that arrived from another app, which is a parser reachable
     * from a share intent for the sake of one integer, and this scan
     * reads no structure at all: `bytes` is an attribute of `<segment>`
     * and of nothing else in the NZB grammar, so the literal is
     * unambiguous. A file that somehow contains it elsewhere makes an
     * advisory number too big, which errs toward warning.
     *
     * Bytes rather than a decoded string: the caller's input is capped at
     * [Http.NZB_SIZE_LIMIT], and decoding tens of megabytes to UTF-16 to
     * look for seven ASCII characters is the one avoidable allocation on
     * this path.
     */
    fun declaredEncodedBytes(nzb: ByteArray): Long {
        val needle = "bytes=\"".toByteArray(Charsets.US_ASCII)
        var total = 0L
        var i = 0
        val n = nzb.size
        outer@ while (i + needle.size < n) {
            for (k in needle.indices) {
                if (nzb[i + k] != needle[k]) {
                    i++
                    continue@outer
                }
            }
            var j = i + needle.size
            var v = 0L
            var digits = 0
            while (j < n && nzb[j] >= '0'.code.toByte() && nzb[j] <= '9'.code.toByte()) {
                // Saturate rather than overflow: a crafted run of digits
                // must not wrap this into a small number, which would
                // report a huge post as one that fits.
                if (v < Long.MAX_VALUE / 16) v = v * 10 + (nzb[j] - '0'.code.toByte())
                digits++
                j++
            }
            if (digits > 18) {
                // A 19-digit declaration is past what a Long can hold.
                // Overflow must mean too large, never zero: a crafted
                // value must not slip past the free-space refusal by
                // being unrepresentable.
                total = Long.MAX_VALUE
            } else if (digits >= 1) {
                // Saturating add: the per-value guard above does not
                // protect the aggregate, and ten huge-but-legal values
                // must not wrap the sum negative, which the caller would
                // read as "fits".
                total = if (Long.MAX_VALUE - v < total) Long.MAX_VALUE else total + v
            }
            i = j
        }
        return total
    }

    /**
     * Bytes this job is expected to occupy once it has landed.
     *
     * The declared figure is what crosses the WIRE, and yEnc costs about
     * 3% over the payload plus the article headers, so the payload is a
     * little under it. Divided by 1.03 rather than assumed equal, because
     * this number is compared against free space and the direction of the
     * error should be toward saying there is room only when there is.
     */
    fun estimatePayloadBytes(nzb: ByteArray): Long =
        (declaredEncodedBytes(nzb) / 1.03).toLong()

    /**
     * Free bytes wanted before starting, which is more than the payload.
     *
     * A posted set is usually an archive: the payload lands, and then the
     * extractor writes the contents beside it before anything is removed,
     * so the high-water mark is roughly twice the payload. This is the
     * number the pre-enqueue warning compares against - and it is a
     * WARNING, because a plain video posted without an archive around it
     * needs only the payload and refusing that would be wrong.
     */
    fun estimatePeakBytes(nzb: ByteArray): Long {
        val payload = estimatePayloadBytes(nzb)
        // Clamped rather than multiplied blind: a saturated payload times
        // two wraps negative, and a negative peak reads as "fits".
        return if (payload > Long.MAX_VALUE / 2) Long.MAX_VALUE else payload * 2
    }
}
