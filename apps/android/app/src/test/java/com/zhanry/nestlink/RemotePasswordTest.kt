package com.zhanry.nestlink

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RemotePasswordTest {
    @Test fun passwordLimitsCountUtf8Bytes() {
        assertTrue(remotePasswordLengthIsValid("a".repeat(12)))
        assertTrue(remotePasswordLengthIsValid("密".repeat(4)))
        assertFalse(remotePasswordLengthIsValid("a".repeat(11)))
        assertTrue(remotePasswordLengthIsValid("密".repeat(4) + "a"))
        assertFalse(remotePasswordLengthIsValid("a".repeat(1_025)))
        assertTrue(remotePasswordLengthIsValid("🔐".repeat(256)))
        assertFalse(remotePasswordLengthIsValid("🔐".repeat(257)))
    }

    @Test fun expiryIsBoundedToTheSupportedDurationsAndCheckedForOverflow() {
        assertEquals(86_400_000L + 10L, remotePasswordExpiry(10L, 1))
        assertEquals(30L * 86_400_000L + 10L, remotePasswordExpiry(10L, 30))
        assertNull(remotePasswordExpiry(10L, 31))
        assertNull(remotePasswordExpiry(Long.MAX_VALUE, 1))
        assertNull(remotePasswordExpiry(-1L, 1))
    }

    @Test fun passwordScopeParsingAndSettingsNeverIncludeTheSecret() {
        val scope = parseRemotePasswordView(
            """{"revision":4,"permissions":[1,2],"paths":[1,2],"expires_at_unix_ms":3000000000000,"active":true}""",
        )
        assertEquals(listOf(1, 2), scope.permissions)
        assertEquals(listOf(1, 2), scope.paths)
        assertTrue(scope.active)

        val settings = remotePasswordSettingsJson(4, listOf(1, 2), listOf(1), 86_400_000L)
        val json = JSONObject(settings)
        assertEquals(4L, json.getLong("expected_revision"))
        assertEquals(listOf(1, 2), json.getJSONArray("permissions").let { values -> List(values.length()) { values.getInt(it) } })
        assertFalse(settings.contains("one-time-secret"))
    }

    @Test fun activeScopeRequiresViewAndAtLeastOnePath() {
        assertFalse(
            runCatching {
                parseRemotePasswordView(
                    """{"revision":1,"permissions":[2],"paths":[1],"expires_at_unix_ms":100,"active":true}""",
                )
            }.isSuccess,
        )
        assertFalse(
            runCatching {
                parseRemotePasswordView(
                    """{"revision":1,"permissions":[1],"paths":[],"expires_at_unix_ms":100,"active":true}""",
                )
            }.isSuccess,
        )
    }
}
