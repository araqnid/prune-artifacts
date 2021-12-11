package pruneArtifacts

import org.araqnid.kotlin.assertthat.assertThat
import org.araqnid.kotlin.assertthat.equalTo
import kotlin.test.Test
import kotlin.test.assertFails

class InputsTest {
    @Test
    fun parse_megabytes_as_size() {
        assertThat(parseSize("1Mb"), equalTo(1048576L))
        assertThat(parseSize("1M"), equalTo(1048576L))
    }

    @Test
    fun parse_kilobytes_as_size() {
        assertThat(parseSize("1Kb"), equalTo(1024L))
        assertThat(parseSize("1K"), equalTo(1024L))
    }

    @Test
    fun parse_bytes_as_size() {
        assertThat(parseSize("1b"), equalTo(1L))
        assertThat(parseSize("1"), equalTo(1L))
    }

    @Test
    fun parse_empty_string_as_size_fails() {
        assertFails {
            parseSize("")
        }
    }

    @Test
    fun parse_days_as_age() {
        assertThat(parseAge("1D"), equalTo(24 * 3600 * 1000L))
        assertThat(parseAge("1 d"), equalTo(24 * 3600 * 1000L))
        assertThat(parseAge("1 day"), equalTo(24 * 3600 * 1000L))
        assertThat(parseAge("2d"), equalTo(2 * 24 * 3600 * 1000L))
        assertThat(parseAge("2 d"), equalTo(2 * 24 * 3600 * 1000L))
        assertThat(parseAge("2 days"), equalTo(2 * 24 * 3600 * 1000L))
    }

    @Test
    fun parse_hours_as_age() {
        assertThat(parseAge("1H"), equalTo(3600 * 1000L))
        assertThat(parseAge("1 H"), equalTo(3600 * 1000L))
        assertThat(parseAge("1 hour"), equalTo(3600 * 1000L))
        assertThat(parseAge("1 hr"), equalTo(3600 * 1000L))
        assertThat(parseAge("2h"), equalTo(2 * 3600 * 1000L))
        assertThat(parseAge("2 h"), equalTo(2 * 3600 * 1000L))
        assertThat(parseAge("2hrs"), equalTo(2 * 3600 * 1000L))
    }

    @Test
    fun parse_empty_string_as_age_fails() {
        assertFails {
            parseAge("")
        }
    }
}
