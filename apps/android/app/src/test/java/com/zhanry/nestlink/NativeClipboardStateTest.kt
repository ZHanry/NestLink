package com.zhanry.nestlink

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeClipboardStateTest {
    private val status = """{"binding":{"request_id":"clipboard-session","connection_generation":9,"core_generation":12},"endpoint":"controller","permitted_read":true,"permitted_write":true}"""

    @Test
    fun remotePermitsDoNotEnableEitherLocalDirection() {
        val row = requireNotNull(parseNativeClipboardStatus(status))
        assertFalse(row.localRead)
        assertFalse(row.localWrite)
        assertFalse(row.ready)
        assertFalse(row.canAct(false))
        assertFalse(row.canAct(true))
    }

    @Test
    fun controllerReadsLocalForRemoteWriteAndWritesLocalForRemoteRead() {
        val readRemote = requireNotNull(parseNativeClipboardStatus(status.replace("\"permitted_write\":true", "\"permitted_write\":false")))
        assertFalse(readRemote.allowedLocalRead)
        assertTrue(readRemote.allowedLocalWrite)
        val ready = readRemote.copy(localWrite = true, ready = true)
        assertTrue(ready.canAct(false))
        assertFalse(ready.canAct(true))
        assertFalse(ready.copy(restartRequired = true).canAct(false))
    }

    @Test
    fun hostDirectionUsesHostPermitAndHasNoControllerAction() {
        val host = requireNotNull(parseNativeClipboardStatus(status.replace("controller", "host").replace("\"permitted_write\":true", "\"permitted_write\":false")))
        assertTrue(host.allowedLocalRead)
        assertFalse(host.allowedLocalWrite)
        assertFalse(host.copy(ready = true, localRead = true).canAct(false))
        assertFalse(host.copy(ready = true, localRead = true).canAct(true))
    }

    @Test
    fun originalConnectionAndCoreGenerationCannotBeReusedAcrossSessions() {
        val row = requireNotNull(parseNativeClipboardStatus(status))
        assertNotEquals(row.binding, row.binding.copy(connectionGeneration = 10))
        assertNotEquals(row.binding, row.binding.copy(coreGeneration = 13))
        assertTrue(runCatching { parseNativeClipboardStatus(status.replace("\"core_generation\":12", "\"core_generation\":0")) }.isFailure)
        assertTrue(runCatching { parseNativeClipboardStatus(status.replace("\"core_generation\":12", "\"other_generation\":12")) }.isFailure)
        assertTrue(runCatching { parseNativeClipboardStatus(status.replace("controller", "unknown")) }.isFailure)
    }

    @Test
    fun clipboardForegroundGateRequiresBothResumeAndActualWindowFocus() {
        val gate = NativeClipboardForeground()
        assertFalse(gate.available())
        gate.resumed(true)
        assertFalse(gate.available())
        gate.focused(true)
        assertTrue(gate.available())
        gate.resumed(false)
        assertFalse(gate.available())
        gate.resumed(true)
        gate.focused(false)
        assertFalse(gate.available())
    }

    @Test
    fun localConsentCannotCreateNewDirectionsOrRestoreRevokedOnes() {
        val off = NativeClipboardLocalConsent()
        off.reduce(true, true)
        assertFalse(off.allows(true))
        assertFalse(off.allows(false))
        val selected = NativeClipboardLocalConsent(read = true, write = true)
        selected.reduce(false, true)
        assertFalse(selected.allows(true))
        assertTrue(selected.allows(false))
        selected.reduce(true, true)
        assertFalse(selected.allows(true))
        selected.close()
        assertFalse(selected.isActive())
        assertFalse(selected.allows(false))
    }

    @Test
    fun multilingualAndSupplementaryTextUsesUtf8ByteBudgetBeforeAllocation() {
        val text = "中文🙂".repeat(6_553) + "012345"
        val bytes = encodeNativeClipboardText(text)
        assertEquals(NATIVE_CLIPBOARD_TEXT_BYTES, bytes.size)
        assertEquals(text, decodeNativeClipboardText(bytes))
        assertArrayEquals(ByteArray(0), encodeNativeClipboardText(""))
        assertTrue(runCatching { encodeNativeClipboardText(text + "a") }.isFailure)
    }

    @Test
    fun textRejectsNulUnpairedSurrogatesMalformedUtf8AndOversizedReplies() {
        assertTrue(runCatching { encodeNativeClipboardText("a\u0000b") }.isFailure)
        assertTrue(runCatching { encodeNativeClipboardText("\uD800") }.isFailure)
        assertTrue(runCatching { encodeNativeClipboardText("\uDC00") }.isFailure)
        assertTrue(runCatching { decodeNativeClipboardText(byteArrayOf(0xC0.toByte(), 0x80.toByte())) }.isFailure)
        assertTrue(runCatching { decodeNativeClipboardText(byteArrayOf(0)) }.isFailure)
        assertTrue(runCatching { decodeNativeClipboardText(ByteArray(NATIVE_CLIPBOARD_TEXT_BYTES + 1) { 1 }) }.isFailure)
    }
}
