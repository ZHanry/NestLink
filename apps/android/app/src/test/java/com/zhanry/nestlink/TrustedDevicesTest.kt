package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedDevicesTest {
    @Test fun parsesTheHostOwnedTrustRevisionPermissionsAndExpiry() {
        val trusted = parseTrustedDevices(
            """{"host_device_id":"host_01","devices":[{"controller_device_id":"client_01","host_key_sha256":"${"a".repeat(64)}","controller_key_sha256":"${"b".repeat(64)}","permissions":[1,2,6],"paths":[1,2],"revision":7,"expires_at_unix_ms":1800000000000,"active":true}]}""",
        )
        assertEquals("host_01", trusted.hostDeviceId)
        assertEquals(1, trusted.devices.size)
        assertEquals("client_01", trusted.devices.single().controllerDeviceId)
        assertEquals(listOf(1, 2, 6), trusted.devices.single().permissions)
        assertEquals(listOf(1, 2), trusted.devices.single().paths)
        assertEquals(7L, trusted.devices.single().revision)
        assertEquals(1_800_000_000_000L, trusted.devices.single().expiresAtUnixMs)
        assertTrue(trusted.devices.single().active)
    }

    @Test fun rejectsDuplicateControllersAndInvalidPermissionOrPathValues() {
        val base = """{"host_device_id":"host_01","devices":[%s]}"""
        val valid = """{"controller_device_id":"client_01","host_key_sha256":"${"a".repeat(64)}","controller_key_sha256":"${"b".repeat(64)}","permissions":[1],"paths":[1],"revision":1,"expires_at_unix_ms":1800000000000,"active":true}"""
        assertFalse(runCatching { parseTrustedDevices(base.format("$valid,$valid")) }.isSuccess)
        assertFalse(runCatching { parseTrustedDevices(base.format(valid.replace("\"permissions\":[1]", "\"permissions\":[99]"))) }.isSuccess)
        assertFalse(runCatching { parseTrustedDevices(base.format(valid.replace("\"paths\":[1]", "\"paths\":[0]"))) }.isSuccess)
    }
}
