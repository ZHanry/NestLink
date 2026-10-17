package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserHostCaptureLifecycleTest {
    @Test
    fun browserBindingRequiresFullProofIdentityAndCannotAliasNativeSession() {
        val browser = binding()
        val parsed = HostCaptureBinding.browserHost(browser)
        val native = HostCaptureBinding.nativeSession(
            """{"request_id":"req-1","connection_generation":7}""",
        )
        assertFalse(parsed.sameOwner(native))
        assertThrows(IllegalArgumentException::class.java) {
            HostCaptureBinding.browserHost("""{"request_id":"req-1","connection_generation":7}""")
        }

        val changedPermit = HostCaptureBinding.browserHost(binding(permitByte = 10))
        assertFalse(parsed.sameOwner(changedPermit))
        val changedRequest = HostCaptureBinding.browserHost(binding(request = "req-2"))
        assertFalse(parsed.sameOwner(changedRequest))
        val changedGeneration = HostCaptureBinding.browserHost(binding(generation = 8))
        assertFalse(parsed.sameOwner(changedGeneration))
    }

    @Test
    fun projectionAndRawQueueStayClosedUntilExactPostProofActivation() {
        val expected = binding()
        val queue = AndroidBrowserRawFrameQueue()
        var projectionActivations = 0
        var ownerStops = 0
        var audioEnabled = false
        var inputEnabled = false
        val endpoint = AndroidBrowserRawCaptureEndpoint(
            bindingJson = expected,
            boundRequestId = "req-1",
            boundGeneration = 7,
            queue = queue,
            activateOwner = { binding, audio, input ->
                if (binding != expected) false
                else {
                    projectionActivations++
                    audioEnabled = audio
                    inputEnabled = input
                    true
                }
            },
            stopOwner = { binding -> binding == expected && ++ownerStops > 0 },
            displaySize = { 1080 to 1920 },
            audioOwner = { null },
            stopInputOwner = { it == expected },
        )

        assertNull(endpoint.pollRawFrame())
        val beforeProof = byteArrayOf(1, 2, 3, 4)
        assertFalse(queue.offer(1, 1, 10L, beforeProof))
        assertEquals(listOf<Byte>(0, 0, 0, 0), beforeProof.toList())
        assertEquals(0, projectionActivations)

        assertFalse(endpoint.activateAfterProof(binding(permitByte = 10), audio = true, input = true))
        assertEquals(0, projectionActivations)
        assertTrue(endpoint.activateAfterProof(expected, audio = true, input = false))
        assertEquals(1, projectionActivations)
        assertTrue(audioEnabled)
        assertFalse(inputEnabled)
        assertEquals(1080, endpoint.displayWidth())
        assertEquals(1920, endpoint.displayHeight())

        assertTrue(queue.offer(1, 1, 20L, byteArrayOf(1, 2, 3, 4)))
        val replaced = queuedFrame(queue)
        assertTrue(queue.offer(1, 1, 30L, byteArrayOf(5, 6, 7, 8)))
        assertZeroed(frameBytes(replaced))
        val newest = endpoint.pollRawFrame()!!
        assertThrows(IllegalStateException::class.java) { replaced.copyPixels() }
        assertEquals(listOf<Byte>(5, 6, 7, 8), newest.copyPixels().toList())
        newest.clear()
        assertThrows(IllegalStateException::class.java) { newest.copyPixels() }
    }

    @Test
    fun staleResetCannotStopReplacementAndExactResetClearsPendingPixels() {
        val expected = binding()
        val queue = AndroidBrowserRawFrameQueue()
        var ownerStops = 0
        val endpoint = AndroidBrowserRawCaptureEndpoint(
            bindingJson = expected,
            boundRequestId = "req-1",
            boundGeneration = 7,
            queue = queue,
            activateOwner = { binding, _, _ -> binding == expected },
            stopOwner = { binding -> binding == expected && ++ownerStops > 0 },
            displaySize = { 1080 to 1920 },
            audioOwner = { null },
            stopInputOwner = { it == expected },
        )
        assertTrue(endpoint.activateAfterProof(expected, audio = false, input = false))
        assertTrue(queue.offer(1, 1, 10L, byteArrayOf(1, 2, 3, 4)))
        val pending = queuedFrame(queue)

        assertFalse(endpoint.stopAndAwait(binding(request = "new-request")))
        assertEquals(0, ownerStops)
        assertEquals(1, endpoint.pollRawFrame()?.width())
        assertTrue(queue.offer(1, 1, 20L, byteArrayOf(5, 6, 7, 8)))
        val pendingOnStop = queuedFrame(queue)
        assertTrue(endpoint.stopAndAwait(expected))
        assertEquals(1, ownerStops)
        assertFalse(endpoint.isActive())
        assertNull(endpoint.pollRawFrame())
        assertZeroed(frameBytes(pendingOnStop))
        assertFalse(pending === pendingOnStop)
    }

    private fun binding(
        request: String = "req-1",
        generation: Long = 7,
        permitByte: Int = 9,
    ): String {
        fun digest(value: Int) = (0 until 32).joinToString(prefix = "[", postfix = "]") {
            if (it == 0) value.toString() else "0"
        }
        return """{"request_id":"$request","session_id":"sess-1","controller_device_id":"controller","host_device_id":"host","controller_key_sha256":${digest(1)},"host_key_sha256":${digest(2)},"permit_sha256":${digest(permitByte)},"connection_generation":$generation}"""
    }

    private fun queuedFrame(queue: AndroidBrowserRawFrameQueue): AndroidBrowserRawFrame {
        val field = AndroidBrowserRawFrameQueue::class.java.getDeclaredField("latest")
        field.isAccessible = true
        return field.get(queue) as AndroidBrowserRawFrame
    }

    private fun frameBytes(frame: AndroidBrowserRawFrame): ByteArray {
        val field = AndroidBrowserRawFrame::class.java.getDeclaredField("bytes")
        field.isAccessible = true
        return field.get(frame) as ByteArray
    }

    private fun assertZeroed(bytes: ByteArray) = assertTrue(bytes.all { it == 0.toByte() })
}
