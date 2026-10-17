package com.zhanry.nestlink

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Pure JVM endpoint/queue contracts; does not exercise Android system consent. */
class BrowserHostCapturePortRegressionTest {
    @Test
    fun fullBindingRejectsMissingFieldsUnknownFieldsAndMalformedDigestBytes() {
        val expected = browserBinding()
        val browser = HostCaptureBinding.browserHost(expected)
        val native = HostCaptureBinding.nativeSession(expected)
        assertFalse(browser.sameOwner(native))
        assertFalse(native.sameOwner(browser))
        assertTrue(browser.sameOwner(HostCaptureBinding.browserHost(expected)))
        val keys = JSONObject(expected).keys().asSequence().toList()
        for (key in keys) {
            val missing = JSONObject(expected).apply { remove(key) }
            assertThrows(Exception::class.java) { HostCaptureBinding.browserHost(missing.toString()) }
        }
        val extra = JSONObject(expected).put("endpoint_kind", "BrowserHost")
        assertThrows(IllegalArgumentException::class.java) {
            HostCaptureBinding.browserHost(extra.toString())
        }
        for (digestKey in listOf("controller_key_sha256", "host_key_sha256", "permit_sha256")) {
            for (size in listOf(0, 31, 33)) {
                val malformed = JSONObject(expected).put(digestKey, JSONArray(List(size) { 0 }))
                assertThrows(IllegalArgumentException::class.java) {
                    HostCaptureBinding.browserHost(malformed.toString())
                }
            }
            for (invalid in listOf(-1, 256)) {
                val bytes = JSONArray(List(32) { 0 }).put(0, invalid)
                val malformed = JSONObject(expected).put(digestKey, bytes)
                assertThrows(IllegalArgumentException::class.java) {
                    HostCaptureBinding.browserHost(malformed.toString())
                }
            }
        }
        for (key in listOf("request_id", "session_id", "controller_device_id", "host_device_id")) {
            assertThrows(IllegalArgumentException::class.java) {
                HostCaptureBinding.browserHost(JSONObject(expected).put(key, "").toString())
            }
        }
        assertFalse(browser.sameOwner(HostCaptureBinding.browserHost(browserBinding(generation = 8))))
        assertFalse(browser.sameOwner(HostCaptureBinding.browserHost(browserBinding(permitByte = 10))))
    }

    @Test
    fun browserBindingRejectsCoercedNumbersAndNonStringIdentities() {
        val expected = browserBinding()
        for (key in listOf("controller_key_sha256", "host_key_sha256", "permit_sha256")) {
            // Keep decimal/exponent syntax in the raw JSON; JSONObject serialization
            // would normalize 1.0 back to the legitimate integer token 1.
            val firstByte = Regex("(\"$key\":\\[)[^,\\]]+")
            for (literal in listOf("1.5", "1.0", "1e0", "\"1\"", "true", "null")) {
                val malformed = firstByte.replace(expected) { it.groupValues[1] + literal }
                assertFalse(malformed == expected)
                assertThrows(Exception::class.java) { HostCaptureBinding.browserHost(malformed) }
            }
        }
        for (literal in listOf(
            "7.5", "7.0", "7e0", "\"7\"", "true", "null", "0", "-1",
            "9223372036854775808", "18446744073709551617",
        )) {
            val malformed = expected.replace("\"connection_generation\":7", "\"connection_generation\":$literal")
            assertFalse(malformed == expected)
            assertThrows(Exception::class.java) { HostCaptureBinding.browserHost(malformed) }
        }
        for (key in listOf("request_id", "session_id", "controller_device_id", "host_device_id")) {
            for (value in listOf(1, true, JSONObject.NULL, JSONArray(listOf("alias")), JSONObject())) {
                val malformed = JSONObject(expected).put(key, value).toString()
                assertThrows(Exception::class.java) { HostCaptureBinding.browserHost(malformed) }
            }
        }
    }

    @Test
    fun closedQueueAndRejectedFrameShapesZeroEveryCallerBuffer() {
        val queue = AndroidBrowserRawFrameQueue()
        val closed = byteArrayOf(1, 2, 3, 4)
        assertFalse(queue.offer(1, 1, 10, closed))
        assertZeroed(closed)
        queue.activate()
        for ((width, height, timestamp, size) in listOf(
            listOf(0, 1, 10, 4),
            listOf(1, 0, 10, 4),
            listOf(8193, 1, 10, 4),
            listOf(8192, 8192, 10, 4),
            listOf(1, 1, 0, 4),
            listOf(1, 1, -1, 4),
            listOf(1, 1, 10, 3),
        )) {
            val bytes = ByteArray(size) { 0x35 }
            assertFalse(queue.offer(width, height, timestamp.toLong(), bytes))
            assertZeroed(bytes)
            assertNull(queue.poll())
        }
    }

    @Test
    fun replacingSingleSlotClearsRetiredPixelsAndPollTransfersOnlyOneFrame() {
        val queue = AndroidBrowserRawFrameQueue()
        queue.activate()
        val source = byteArrayOf(1, 2, 3, 4)
        assertTrue(queue.offer(1, 1, 10, source))
        assertZeroed(source)
        val old = queuedFrame(queue)
        val exported = old.copyPixels()
        exported.fill(8)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), old.copyPixels())

        val replacement = byteArrayOf(5, 6, 7, 8)
        assertTrue(queue.offer(1, 1, 20, replacement))
        assertZeroed(replacement)
        assertZeroed(frameBytes(old))
        assertThrows(IllegalStateException::class.java) { old.copyPixels() }
        val latest = queue.poll()
        assertNotNull(latest)
        assertEquals(20L, latest!!.timestampNanos())
        assertArrayEquals(byteArrayOf(5, 6, 7, 8), latest.copyPixels())
        assertNull(queue.poll())
        latest.clear()
        latest.clear()
        assertZeroed(frameBytes(latest))
        assertThrows(IllegalStateException::class.java) { latest.copyPixels() }
    }

    @Test
    fun resizeRetiresPendingPixelsAndStopMakesTheQueueTerminal() {
        val queue = AndroidBrowserRawFrameQueue()
        queue.activate()
        assertTrue(queue.offer(1, 1, 10, byteArrayOf(1, 2, 3, 4)))
        val beforeResize = queuedFrame(queue)
        queue.clearPending()
        assertZeroed(frameBytes(beforeResize))
        assertNull(queue.poll())
        assertTrue(queue.offer(2, 1, 20, ByteArray(8) { 9 }))
        val beforeStop = queuedFrame(queue)
        queue.stopAndClear()
        assertZeroed(frameBytes(beforeStop))
        queue.activate()
        val late = ByteArray(8) { 7 }
        assertFalse(queue.offer(2, 1, 30, late))
        assertZeroed(late)
        assertNull(queue.poll())
    }

    @Test
    fun onlyExactPostProofActivationCanOpenTheEndpointAndItSucceedsOnce() {
        val binding = browserBinding()
        val activations = AtomicInteger()
        val queue = AndroidBrowserRawFrameQueue()
        val endpoint = endpoint(binding, queue, activate = { expected, audio, input ->
            assertEquals(binding, expected)
            assertTrue(audio)
            assertFalse(input)
            activations.incrementAndGet()
            true
        })
        assertFalse(endpoint.isActive())
        assertEquals(0, endpoint.displayWidth())
        assertEquals(0, endpoint.displayHeight())
        assertNull(endpoint.openAudioCapture(binding))
        val premature = byteArrayOf(1, 2, 3, 4)
        assertFalse(queue.offer(1, 1, 10, premature))
        assertZeroed(premature)
        assertFalse(endpoint.activateAfterProof(browserBinding(permitByte = 10), true, false))
        assertEquals(0, activations.get())

        assertTrue(endpoint.activateAfterProof(binding, true, false))
        assertTrue(endpoint.isActive())
        assertEquals(1080, endpoint.displayWidth())
        assertEquals(1920, endpoint.displayHeight())
        assertFalse(endpoint.activateAfterProof(binding, true, false))
        assertEquals(1, activations.get())
    }

    @Test
    fun failedOrThrowingOwnerActivationDoesNotStartPixels() {
        for (throws in listOf(false, true)) {
            val binding = browserBinding()
            val queue = AndroidBrowserRawFrameQueue()
            val activations = AtomicInteger()
            val endpoint = endpoint(binding, queue, activate = { _, _, _ ->
                activations.incrementAndGet()
                if (throws) error("synthetic owner-port failure") else false
            })
            assertFalse(endpoint.activateAfterProof(binding, true, true))
            assertFalse(endpoint.activateAfterProof(binding, true, true))
            assertEquals(1, activations.get())
            assertFalse(endpoint.isActive())
            val input = byteArrayOf(1, 2, 3, 4)
            assertFalse(queue.offer(1, 1, 10, input))
            assertZeroed(input)
            assertNull(endpoint.pollRawFrame())
        }
    }

    @Test
    fun retirementBeforeProofCannotConsumeAnOwnerOrReopenItsQueue() {
        for (stop in listOf(false, true)) {
            val binding = browserBinding()
            val queue = AndroidBrowserRawFrameQueue()
            val activations = AtomicInteger()
            val endpoint = endpoint(binding, queue, activate = { _, _, _ ->
                activations.incrementAndGet()
                true
            })
            if (stop) assertTrue(endpoint.stopAndAwait(binding)) else endpoint.retireFromOwner()
            assertFalse(endpoint.activateAfterProof(binding, true, true))
            assertEquals(0, activations.get())
            assertFalse(endpoint.isActive())
            assertFalse(queue.activate())
            val late = byteArrayOf(1, 2, 3, 4)
            assertFalse(queue.offer(1, 1, 10, late))
            assertZeroed(late)
            assertNull(endpoint.pollRawFrame())
        }
    }

    @Test
    fun simultaneousActivationCallsSpendTheOwnerPortOnce() {
        val entered = CountDownLatch(1)
        val complete = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        val binding = browserBinding()
        val activations = AtomicInteger()
        val endpoint = endpoint(binding, AndroidBrowserRawFrameQueue(), activate = { _, _, _ ->
            activations.incrementAndGet()
            entered.countDown()
            check(complete.await(3, TimeUnit.SECONDS))
            true
        })
        try {
            val first = executor.submit<Boolean> { endpoint.activateAfterProof(binding, false, false) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val concurrent = executor.submit<Boolean> { endpoint.activateAfterProof(binding, true, true) }
            assertFalse(concurrent.get(1, TimeUnit.SECONDS))
            assertEquals(1, activations.get())
            complete.countDown()
            assertTrue(first.get(3, TimeUnit.SECONDS))
            assertTrue(endpoint.isActive())
        } finally {
            complete.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    @Test
    fun stopDuringOwnerActivationIsTerminalWithoutWaitingOnItsCallbackLock() {
        val entered = CountDownLatch(1)
        val complete = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        val binding = browserBinding()
        val queue = AndroidBrowserRawFrameQueue()
        val stops = AtomicInteger()
        val endpoint = endpoint(binding, queue, activate = { _, _, _ ->
            entered.countDown()
            check(complete.await(3, TimeUnit.SECONDS))
            true
        }, stop = { expected ->
            assertEquals(binding, expected)
            stops.incrementAndGet()
            true
        })
        try {
            val activation = executor.submit<Boolean> { endpoint.activateAfterProof(binding, true, true) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val stop = executor.submit<Boolean> { endpoint.stopAndAwait(binding) }
            assertTrue(stop.get(1, TimeUnit.SECONDS))
            assertEquals(1, stops.get())
            complete.countDown()
            assertFalse(activation.get(3, TimeUnit.SECONDS))
            assertFalse(endpoint.isActive())
            val late = byteArrayOf(1, 2, 3, 4)
            assertFalse(queue.offer(1, 1, 10, late))
            assertZeroed(late)
            assertNull(endpoint.pollRawFrame())
        } finally {
            complete.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    @Test
    fun ownerStopFailureOrExceptionCannotReopenOrRetainPendingPixels() {
        for (throws in listOf(false, true)) {
            val binding = browserBinding()
            val queue = AndroidBrowserRawFrameQueue()
            val endpoint = endpoint(binding, queue, stop = {
                if (throws) error("synthetic stop failure") else false
            })
            assertTrue(endpoint.activateAfterProof(binding, false, false))
            assertTrue(queue.offer(1, 1, 10, byteArrayOf(1, 2, 3, 4)))
            val pending = queuedFrame(queue)
            assertFalse(endpoint.stopAndAwait(binding))
            assertFalse(endpoint.isActive())
            assertZeroed(frameBytes(pending))
            assertNull(endpoint.pollRawFrame())
            assertFalse(endpoint.activateAfterProof(binding, false, false))
        }
    }

    @Test
    fun unprovedUnpermittedStaleOrRetiredInputNeverReachesAndroidPorts() {
        val binding = browserBinding()
        val stale = browserBinding(request = "retired", generation = 6)
        val endpoint = endpoint(binding, AndroidBrowserRawFrameQueue())
        assertInputDenied(endpoint, binding)
        assertInputDenied(endpoint, stale)
        assertTrue(endpoint.activateAfterProof(binding, false, false))
        assertInputDenied(endpoint, binding)
        endpoint.retireFromOwner()
        assertInputDenied(endpoint, binding)

        val inputEndpoint = endpoint(binding, AndroidBrowserRawFrameQueue())
        assertTrue(inputEndpoint.activateAfterProof(binding, false, true))
        assertInputDenied(inputEndpoint, stale)
        inputEndpoint.retireFromOwner()
        assertInputDenied(inputEndpoint, binding)
    }

    @Test
    fun stopAndOwnerRetirementCannotSpendTheSameEndpointAgain() {
        for (retire in listOf(false, true)) {
            val binding = browserBinding()
            val queue = AndroidBrowserRawFrameQueue()
            val activations = AtomicInteger()
            val endpoint = endpoint(binding, queue, activate = { _, _, _ ->
                activations.incrementAndGet()
                true
            })
            assertTrue(endpoint.activateAfterProof(binding, false, false))
            assertTrue(queue.offer(1, 1, 10, byteArrayOf(1, 2, 3, 4)))
            val pending = queuedFrame(queue)
            if (retire) endpoint.retireFromOwner() else assertTrue(endpoint.stopAndAwait(binding))
            assertFalse(endpoint.activateAfterProof(binding, false, false))
            assertEquals(1, activations.get())
            assertFalse(endpoint.isActive())
            assertZeroed(frameBytes(pending))
            assertNull(endpoint.pollRawFrame())
        }
    }

    @Test
    fun staleBindingCannotInvokeReplacementActivationOrStopPorts() {
        val oldBinding = browserBinding()
        val replacementBinding = browserBinding(request = "replacement", generation = 8)
        val queue = AndroidBrowserRawFrameQueue()
        val activationCalls = AtomicInteger()
        val stopCalls = AtomicInteger()
        val replacement = endpoint(replacementBinding, queue, activate = { _, _, _ ->
            activationCalls.incrementAndGet()
            true
        }, stop = {
            stopCalls.incrementAndGet()
            true
        })
        assertFalse(replacement.activateAfterProof(oldBinding, true, true))
        assertFalse(replacement.stopAndAwait(oldBinding))
        assertEquals(0, activationCalls.get())
        assertEquals(0, stopCalls.get())
        assertTrue(replacement.activateAfterProof(replacementBinding, false, false))
        assertFalse(replacement.stopAndAwait(oldBinding))
        assertTrue(replacement.isActive())
        assertEquals(0, stopCalls.get())
    }

    @Test
    fun lateSuccessfulActivationCannotReviveRetiredEndpointOrTouchReplacement() {
        val entered = CountDownLatch(1)
        val complete = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        val oldBinding = browserBinding()
        val oldQueue = AndroidBrowserRawFrameQueue()
        val old = endpoint(oldBinding, oldQueue, activate = { _, _, _ ->
            entered.countDown()
            check(complete.await(3, TimeUnit.SECONDS))
            true
        })
        try {
            val pending = executor.submit<Boolean> { old.activateAfterProof(oldBinding, false, false) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            old.retireFromOwner()
            val replacementBinding = browserBinding(request = "replacement", generation = 8)
            val replacementQueue = AndroidBrowserRawFrameQueue()
            val replacement = endpoint(replacementBinding, replacementQueue)
            assertTrue(replacement.activateAfterProof(replacementBinding, false, false))
            assertTrue(replacementQueue.offer(1, 1, 20, byteArrayOf(5, 6, 7, 8)))
            complete.countDown()
            assertFalse(pending.get(3, TimeUnit.SECONDS))
            assertFalse(old.isActive())
            val late = byteArrayOf(1, 2, 3, 4)
            assertFalse(oldQueue.offer(1, 1, 30, late))
            assertZeroed(late)
            assertTrue(replacement.isActive())
            assertArrayEquals(byteArrayOf(5, 6, 7, 8), replacement.pollRawFrame()!!.copyPixels())
        } finally {
            complete.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    @Test
    fun delayedStopAcknowledgementForOldEndpointDoesNotCloseReplacement() {
        val entered = CountDownLatch(1)
        val complete = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        val oldBinding = browserBinding()
        val oldQueue = AndroidBrowserRawFrameQueue()
        val old = endpoint(oldBinding, oldQueue, stop = { expected ->
            assertEquals(oldBinding, expected)
            entered.countDown()
            check(complete.await(3, TimeUnit.SECONDS))
            true
        })
        try {
            assertTrue(old.activateAfterProof(oldBinding, false, false))
            val pending = executor.submit<Boolean> { old.stopAndAwait(oldBinding) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val replacementBinding = browserBinding(request = "replacement", generation = 8)
            val replacementQueue = AndroidBrowserRawFrameQueue()
            val replacement = endpoint(replacementBinding, replacementQueue)
            assertTrue(replacement.activateAfterProof(replacementBinding, false, false))
            assertTrue(replacementQueue.offer(1, 1, 20, byteArrayOf(5, 6, 7, 8)))
            complete.countDown()
            assertTrue(pending.get(3, TimeUnit.SECONDS))
            assertFalse(old.isActive())
            assertTrue(replacement.isActive())
            assertArrayEquals(byteArrayOf(5, 6, 7, 8), replacement.pollRawFrame()!!.copyPixels())
        } finally {
            complete.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    @Test
    fun preparedGeometryBelongsToOneStagedGrantAndCannotActivateCapture() {
        val binding = browserBinding()
        val queue = AndroidBrowserRawFrameQueue()
        var activations = 0
        val endpoint = endpoint(binding, queue, activate = { _, _, _ -> activations++; true })
        assertEquals(0, endpoint.preparedDisplayWidth(browserBinding(permitByte = 10)))
        assertEquals(1080, endpoint.preparedDisplayWidth(binding))
        assertEquals(1920, endpoint.preparedDisplayHeight(binding))
        assertEquals(0, activations)
        assertFalse(endpoint.isActive())
        assertEquals(0, endpoint.displayWidth())
        assertNull(endpoint.pollRawFrame())
        val pixels = byteArrayOf(1, 2, 3, 4)
        assertFalse(queue.offer(1, 1, 10, pixels))
        assertZeroed(pixels)
        endpoint.retireFromOwner()
        assertEquals(0, endpoint.preparedDisplayWidth(binding))
        assertEquals(0, endpoint.preparedDisplayHeight(binding))
        assertFalse(endpoint.activateAfterProof(binding, false, false))
        assertEquals(0, activations)
    }

    @Test
    fun tallLargeAndOddScreensPrepareTheSameBoundedGeometryThatCaptureActivates() {
        val cases = listOf(
            (1080 to 2400) to (864 to 1920),
            (1440 to 2560) to (1080 to 1920),
            (2560 to 1440) to (1920 to 1080),
            (1079 to 1919) to (1078 to 1918),
        )
        for ((screen, expected) in cases) {
            val binding = browserBinding()
            val queue = AndroidBrowserRawFrameQueue()
            val preparedSize = CaptureFramePacker.scaledSize(screen.first, screen.second)
            assertEquals(expected, preparedSize)
            var activations = 0
            val endpoint = endpoint(binding, queue, activate = { _, _, _ ->
                activations++
                true
            }, size = { preparedSize })
            assertEquals(expected.first, endpoint.preparedDisplayWidth(binding))
            assertEquals(expected.second, endpoint.preparedDisplayHeight(binding))
            assertEquals(0, endpoint.preparedDisplayWidth(browserBinding(permitByte = 10)))
            assertEquals(0, activations)
            assertFalse(endpoint.isActive())
            assertNull(endpoint.pollRawFrame())
            assertTrue(endpoint.activateAfterProof(binding, false, false))
            assertEquals(1, activations)
            assertEquals(expected.first, endpoint.displayWidth())
            assertEquals(expected.second, endpoint.displayHeight())
            assertEquals(0, endpoint.preparedDisplayWidth(binding))
            assertFalse(endpoint.activateAfterProof(binding, false, false))
            assertTrue(endpoint.stopAndAwait(binding))
        }
    }

    @Test
    fun ownerCanRetireDuringPreparedGeometryReadWithoutLockInversion() {
        val entered = CountDownLatch(1)
        val complete = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        val binding = browserBinding()
        val endpoint = endpoint(binding, AndroidBrowserRawFrameQueue(), size = {
            entered.countDown()
            check(complete.await(3, TimeUnit.SECONDS))
            1080 to 1920
        })
        try {
            val read = executor.submit<Int> { endpoint.preparedDisplayWidth(binding) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val retired = executor.submit { endpoint.retireFromOwner() }
            retired.get(2, TimeUnit.SECONDS)
            complete.countDown()
            assertEquals(0, read.get(3, TimeUnit.SECONDS).toInt())
        } finally {
            complete.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    private fun endpoint(
        binding: String,
        queue: AndroidBrowserRawFrameQueue,
        activate: (String, Boolean, Boolean) -> Boolean = { _, _, _ -> true },
        stop: (String) -> Boolean = { true },
        size: () -> Pair<Int, Int> = { 1080 to 1920 },
    ): AndroidBrowserRawCaptureEndpoint {
        val owner = HostCaptureBinding.browserHost(binding)
        return AndroidBrowserRawCaptureEndpoint(
            bindingJson = binding,
            boundRequestId = owner.requestId,
            boundGeneration = owner.connectionGeneration,
            queue = queue,
            activateOwner = activate,
            stopOwner = stop,
            displaySize = size,
            audioOwner = { null },
            stopInputOwner = { it == binding },
        )
    }

    private fun browserBinding(
        request: String = "req-1",
        generation: Long = 7,
        permitByte: Int = 9,
    ): String {
        fun digest(value: Int) = JSONArray(List(32) { if (it == 0) value else 0 })
        return JSONObject()
            .put("request_id", request)
            .put("session_id", "session-1")
            .put("controller_device_id", "controller-1")
            .put("host_device_id", "host-1")
            .put("controller_key_sha256", digest(1))
            .put("host_key_sha256", digest(2))
            .put("permit_sha256", digest(permitByte))
            .put("connection_generation", generation)
            .toString()
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

    private fun assertInputDenied(endpoint: AndroidBrowserRawCaptureEndpoint, binding: String) {
        assertFalse(endpoint.isInputActive(binding))
        assertFalse(endpoint.selectInputSource(binding, 0, 0, 0, 1080, 1920))
        assertFalse(endpoint.sendHidKey(binding, 4, true))
        assertFalse(endpoint.dispatchPointer(binding, 10, 20, 1))
        assertFalse(endpoint.commitRemoteText(binding, "stale input"))
        assertFalse(endpoint.releasePointer(binding))
    }
}
