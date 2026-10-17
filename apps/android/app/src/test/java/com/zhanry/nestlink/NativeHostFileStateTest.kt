package com.zhanry.nestlink

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class NativeHostFileStateTest {
    private val envelope = """{"identity":{"binding":{"request_id":"host-session","connection_generation":9},"core_generation":12},"read":true,"write":true,"host":true}"""
    private val status = """{"identity":{"binding":{"request_id":"host-session","connection_generation":9},"core_generation":12},"receive_approved":false,"reserved_bytes":3,"artifacts":[{"id":"received-1","kind":"receive","display_name":"note.txt","phase":"received","size":3,"published":true,"verified":true,"owner_stopped":true,"cleanup_pending":false,"error":"completion delivery unknown","cleanup_error":null}],"exports":[]}"""

    @Test
    fun hostRoleAndSessionProofAreRequiredBeforePublishingLocalFileState() {
        val host = requireNotNull(parseNativeFileSessionIdentity(envelope))
        assertTrue(host.isHost)
        val controller = requireNotNull(parseNativeFileSessionIdentity(envelope.replace("\"host\":true", "\"host\":false")))
        assertTrue(runCatching { parseNativeHostFiles(status, controller) }.isFailure)
        assertTrue(runCatching { parseNativeHostFiles(status.replace("\"core_generation\":12", "\"core_generation\":13"), host) }.isFailure)
    }

    @Test
    fun unknownCompletionPreservesVerifiedPublicationAndLocalReceiveRemainsOff() {
        val host = requireNotNull(parseNativeFileSessionIdentity(envelope))
        val parsed = parseNativeHostFiles(status, host)
        assertFalse(parsed.receiveApproved)
        assertEquals(3L, parsed.reservedBytes)
        val artifact = parsed.artifacts.single()
        assertTrue(artifact.published)
        assertEquals("completion delivery unknown", artifact.error)
        assertTrue(artifact.canExport())
    }

    @Test
    fun terminalPhaseCannotEnableExportWithoutRealOwnerAndCleanupReceipts() {
        val host = requireNotNull(parseNativeFileSessionIdentity(envelope))
        assertFalse(parseNativeHostFiles(status.replace("\"owner_stopped\":true", "\"owner_stopped\":false"), host).artifacts.single().canExport())
        assertFalse(parseNativeHostFiles(status.replace("\"owner_stopped\":true,", ""), host).artifacts.single().canExport())
        assertFalse(parseNativeHostFiles(status.replace("\"cleanup_pending\":false", "\"cleanup_pending\":true"), host).artifacts.single().canExport())
        assertFalse(parseNativeHostFiles(status.replace("\"verified\":true", "\"verified\":false"), host).artifacts.single().canExport())
    }
}
