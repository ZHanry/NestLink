package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.ArrayDeque

class NativeAudioEndpointTest {
    @Test
    fun playbackUsesOneSoftwareChunkAndKeepsMissingHardwareLatencyUnknown() {
        val queue = BoundedAudioPcmQueue(packetBytes = 4, capacity = 1)
        assertTrue(queue.offer(byteArrayOf(1, 2, 3, 4)))
        assertTrue(queue.offer(byteArrayOf(5, 6, 7, 8)))
        assertEquals(1, queue.size())
        assertEquals(1L, queue.droppedPackets())
        assertEquals(byteArrayOf(5, 6, 7, 8).toList(), queue.poll()?.toList())
        assertEquals(listOf(-1L, -1L, -1L), FakeEndpoint().playbackTiming().toList())
    }

    @Test
    fun playbackHeadWrapIsMeasuredWithoutInventingZeroForInconsistentSnapshots() {
        assertEquals(48L, nativeAudioHardwareQueuedFrames(0x1_0000_0020L, 0xffff_fff0L.toInt()))
        assertEquals(16L, nativeAudioHardwareQueuedFrames(0x1_0000_0020L, 0x10))
        assertEquals(0L, nativeAudioHardwareQueuedFrames(0, 0))
        assertEquals(-1L, nativeAudioHardwareQueuedFrames(50, 100))
        assertEquals(-1L, nativeAudioHardwareQueuedFrames(2881, 0))
    }

    @Test
    fun pcmBudgetAndQueueKeepAtMostFiveTwentyMillisecondPacketsDroppingOldest() {
        assertEquals(3_840, NATIVE_AUDIO_PCM_BYTES)
        assertEquals(3_856, NATIVE_AUDIO_CAPTURE_PACKET_BYTES)
        val queue = BoundedAudioPcmQueue(packetBytes = 4)
        for (value in 1..6) assertTrue(queue.offer(ByteArray(4) { value.toByte() }))

        assertEquals(NATIVE_AUDIO_QUEUE_CHUNKS, queue.size())
        assertEquals(1L, queue.droppedPackets())
        assertEquals(2.toByte(), queue.poll()?.first())
        assertEquals(3.toByte(), queue.poll()?.first())
        assertEquals(4.toByte(), queue.poll()?.first())
        assertEquals(5.toByte(), queue.poll()?.first())
        assertEquals(6.toByte(), queue.poll()?.first())
        assertNull(queue.poll())
    }

    @Test
    fun queueCopiesOfferedPcmAndResetDiscardsPacketsAndRejectsFurtherWrites() {
        val queue = BoundedAudioPcmQueue(packetBytes = 4)
        val offered = byteArrayOf(1, 2, 3, 4)
        assertTrue(queue.offer(offered))
        offered.fill(0)
        assertEquals(byteArrayOf(1, 2, 3, 4).toList(), queue.poll()?.toList())

        assertTrue(queue.offer(byteArrayOf(5, 6, 7, 8)))
        queue.stopAndClear()
        assertEquals(0, queue.size())
        assertNull(queue.poll())
        assertFalse(queue.offer(byteArrayOf(9, 10, 11, 12)))
        assertFalse(queue.offer(byteArrayOf(9)))
    }

    @Test
    fun endpointResetIsTerminalIdempotentAndTiedToOneRequestGenerationAndRole() {
        val endpoint = FakeEndpoint()
        assertTrue(endpoint.isActive())
        assertTrue(endpoint.matchesBinding("request-1", 17, "HostCapture"))
        assertFalse(endpoint.matchesBinding("request-2", 17, "HostCapture"))
        assertFalse(endpoint.matchesBinding("request-1", 18, "HostCapture"))
        assertFalse(endpoint.matchesBinding("request-1", 17, "ControllerPlayback"))

        assertTrue(endpoint.resetAndAwait())
        assertFalse(endpoint.isActive())
        assertTrue(endpoint.resetAndAwait())
        assertEquals(1, endpoint.stopCalls)
    }

    @Test
    fun failedEndpointResetCanBeRetriedAndKeepsTheFirstFailureHistory() {
        val endpoint = RetriableEndpoint(false, true)

        assertFalse(endpoint.resetAndAwait())
        assertFalse(endpoint.isActive())
        assertTrue(endpoint.cleanupFailureObserved())
        assertNotNull(endpoint.lastCleanupFailure())

        assertTrue(endpoint.resetAndAwait())
        assertEquals(2, endpoint.cleanupAttempts())
        assertTrue(endpoint.cleanupFailureObserved())
        assertNull(endpoint.lastCleanupFailure())
    }

    @Test
    fun failedOwnerCleanupBlocksBindingReplacementUntilAReapConfirmsRelease() {
        val registry = NativeAudioEndpointOwnerRegistry()
        val first = RetriableEndpoint(false, true)
        val replacement = FakeEndpoint()

        assertTrue(registry.registerPending(41L, NativeAudioOwnerRole.ControllerPlayback, "binding-1", first))
        val failed = registry.reap(41L, NativeAudioOwnerRole.ControllerPlayback, first)
        assertFalse(failed?.cleanupComplete ?: true)
        assertTrue(failed?.failureObserved == true)
        assertFalse(registry.registerPending(
            41L,
            NativeAudioOwnerRole.ControllerPlayback,
            "binding-2",
            replacement,
        ))

        val recovered = registry.reap(41L, NativeAudioOwnerRole.ControllerPlayback, first)
        assertTrue(recovered?.cleanupComplete == true)
        assertTrue(recovered?.failureObserved == true)
        assertEquals(2, recovered?.attempts ?: 0)
        assertTrue(registry.registerPending(
            41L,
            NativeAudioOwnerRole.ControllerPlayback,
            "binding-2",
            replacement,
        ))
    }

    @Test
    fun roleReapVisitsAllOwnersIncludingRejectedAttachRaceOrphans() {
        val registry = NativeAudioEndpointOwnerRegistry()
        val attached = FakeEndpoint()
        val orphan = RetriableEndpoint(false, true)

        assertTrue(registry.registerPending(52L, NativeAudioOwnerRole.HostCapture, "binding-1", attached))
        assertTrue(registry.markAttached(52L, NativeAudioOwnerRole.HostCapture, "binding-1", attached))
        assertTrue(registry.retainRejectedPending(52L, NativeAudioOwnerRole.HostCapture, "binding-2", orphan))

        val failed = registry.reapAll(52L, NativeAudioOwnerRole.HostCapture)
        assertFalse(failed.cleanupComplete)
        assertEquals(1, registry.owners(52L, NativeAudioOwnerRole.HostCapture).size)
        assertEquals("binding-2", registry.owners(52L, NativeAudioOwnerRole.HostCapture).single().bindingJson)

        val recovered = registry.reapAll(52L, NativeAudioOwnerRole.HostCapture)
        assertTrue(recovered.cleanupComplete)
        assertTrue(recovered.receipts.any { it.bindingJson == "binding-2" && it.failureObserved && it.cleanupComplete })
    }

    @Test
    fun processWideReapMustConfirmOwnersFromEveryHandle() {
        val registry = NativeAudioEndpointOwnerRegistry()
        val staleHandleOwner = RetriableEndpoint(false, true)

        assertTrue(registry.registerPending(
            61L,
            NativeAudioOwnerRole.ControllerPlayback,
            "old-handle-binding",
            staleHandleOwner,
        ))
        val first = registry.reapAllActive(includeHandle = 62L)
        assertFalse(first.cleanupComplete)
        assertTrue(first.receipts.any { it.handle == 61L && !it.cleanupComplete })

        val second = registry.reapAllActive(includeHandle = 62L)
        assertTrue(second.cleanupComplete)
        assertTrue(second.receipts.any { it.handle == 61L && it.cleanupComplete && it.failureObserved })
    }

    private class FakeEndpoint : NativeAudioEndpoint("request-1", 17, "HostCapture") {
        var stopCalls = 0
        override fun stopEndpoint(): Boolean {
            stopCalls++
            return true
        }
    }

    private class RetriableEndpoint(vararg outcomes: Boolean) : NativeAudioEndpoint(
        "request-1",
        17,
        "ControllerPlayback",
    ) {
        private val remainingOutcomes = ArrayDeque(outcomes.toList())
        override fun stopEndpoint(): Boolean = if (remainingOutcomes.isEmpty()) true else remainingOutcomes.removeFirst()
    }
}
