package app.nzbfast.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import app.nzbfast.mobile.api.Parse

/**
 * The two rules behind the update notice, plus the parser that feeds
 * them. All three are pure, which is why they are written as free
 * functions and not as methods on an Android object.
 *
 * [updateIsNewer] is a hand port of `version_newer` in
 * crates/nzbfast-daemon/src/update.rs, so the rows below are the rows
 * that file's behaviour actually turns on: the `v` prefix, the `-`
 * split that makes a prerelease tag compare EQUAL rather than lower, a
 * short version against a long one, and junk fragments reading as 0. A
 * port that drifts on any of those makes the app disagree with the
 * daemon about what "newer" means, and the disagreement would show up
 * as a banner that will not go away.
 */
class UpdateNoticeTest {

    @Test
    fun a_higher_version_is_newer() {
        assertTrue(updateIsNewer("1.4.1", "1.4.0"))
        assertTrue(updateIsNewer("1.5.0", "1.4.9"))
        assertTrue(updateIsNewer("2.0.0", "1.99.99"))
    }

    @Test
    fun the_same_version_is_not_newer() {
        assertFalse(updateIsNewer("1.4.0", "1.4.0"))
    }

    @Test
    fun an_older_version_is_not_newer() {
        assertFalse(updateIsNewer("1.3.9", "1.4.0"))
        // The server-mode case this compare exists for: a current APK
        // against an older daemon, whose own verdict says "1.3.2 is
        // out". Newer than the DAEMON, not newer than us, no banner.
        assertFalse(updateIsNewer("1.3.2", "1.4.0"))
    }

    @Test
    fun a_leading_v_is_ignored() {
        assertTrue(updateIsNewer("v1.4.1", "1.4.0"))
        assertFalse(updateIsNewer("v1.4.0", "V1.4.0"))
    }

    @Test
    fun a_prerelease_tag_compares_equal_to_the_release() {
        // `-` splits like `.`, so "1.4.0-beta" is [1,4,0,0] against
        // [1,4,0] - equal, not lower. Copied deliberately: the daemon
        // does this, and the two must agree.
        assertFalse(updateIsNewer("1.4.0-beta", "1.4.0"))
        assertFalse(updateIsNewer("1.4.0", "1.4.0-beta"))
        assertTrue(updateIsNewer("1.4.1-beta", "1.4.0"))
    }

    @Test
    fun missing_and_junk_fragments_read_as_zero() {
        assertFalse(updateIsNewer("1.4", "1.4.0"))
        assertTrue(updateIsNewer("1.4.1", "1.4"))
        assertFalse(updateIsNewer("", "1.4.0"))
        assertFalse(updateIsNewer("nightly", "1.4.0"))
    }

    @Test
    fun a_check_is_due_at_or_past_the_deadline() {
        val now = 1_000_000L
        assertTrue(updateCheckDue(now, 0L))
        assertTrue(updateCheckDue(now, now))
        assertTrue(updateCheckDue(now, now - 1))
        assertFalse(updateCheckDue(now, now + 1))
        assertFalse(updateCheckDue(now, now + UPDATE_CHECK_INTERVAL_MS))
    }

    @Test
    fun a_deadline_further_out_than_the_interval_is_junk_and_due() {
        // The clock-moved-backwards arm: a phone whose date was set
        // forward, checked, and then corrected holds a deadline no
        // interval we write could have produced. Without this it never
        // checks again for the life of the install.
        val now = 1_000_000L
        assertTrue(updateCheckDue(now, now + UPDATE_CHECK_INTERVAL_MS + 1))
        assertTrue(updateCheckDue(now, now + 400L * 24 * 60 * 60 * 1000))
    }

    @Test
    fun the_retry_after_a_failure_is_shorter_than_the_interval() {
        // Both are used as `now + interval`, so a retry that was not
        // shorter would make a failed check cost a whole day.
        assertTrue(UPDATE_RETRY_INTERVAL_MS < UPDATE_CHECK_INTERVAL_MS)
    }

    @Test
    fun the_update_check_payload_parses() {
        val s = Parse.updateCheck(
            """{"status":true,"current":"1.4.0","available":"1.4.1",""" +
                """"manifest":{"version":"1.4.1","serial":27}}"""
        )
        assertEquals("1.4.0", s!!.current)
        assertEquals("1.4.1", s.available)
    }

    @Test
    fun up_to_date_parses_as_no_version_available() {
        // The arm answers `available: null` (serde's None) rather than
        // omitting the key, and both have to read the same way.
        val nulled = Parse.updateCheck("""{"status":true,"current":"1.4.0","available":null}""")
        assertNull(nulled!!.available)
        val missing = Parse.updateCheck("""{"status":true,"current":"1.4.0"}""")
        assertNull(missing!!.available)
    }

    @Test
    fun a_refused_or_unreachable_check_is_null_not_up_to_date() {
        assertNull(Parse.updateCheck("""{"status":false,"error":"update check: dns error"}"""))
    }

    @Test
    fun the_releases_url_is_the_page_and_not_a_download() {
        // The link must stay a human-readable page. A direct asset URL
        // here would be the first half of the install path this feature
        // deliberately does not have.
        assertEquals("https://github.com/nzbfast/nzbfast/releases", RELEASES_URL)
    }
}
