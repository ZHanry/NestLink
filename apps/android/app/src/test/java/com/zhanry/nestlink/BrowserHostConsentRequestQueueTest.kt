package com.zhanry.nestlink

import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserHostConsentRequestQueueTest {
    @Test
    fun boundedQueueRejectsOverflowAndPreservesFifoOrder() {
        val queue = BrowserHostConsentRequestQueue(capacity = 2)

        assertTrue(queue.offer("binding-a"))
        assertTrue(queue.offer("binding-b"))
        assertFalse(queue.offer("binding-c"))

        assertEquals("binding-a", queue.poll())
        assertTrue(queue.offer("binding-c"))
        assertEquals("binding-b", queue.poll())
        assertEquals("binding-c", queue.poll())
        assertNull(queue.poll())
    }

    @Test
    fun removalUsesTheCompleteSerializedBinding() {
        val queue = BrowserHostConsentRequestQueue(capacity = 3)
        val first = "{\"request_id\":\"req-1\",\"connection_generation\":7,\"permit_sha256\":[1]}"
        val replacement = "{\"request_id\":\"req-1\",\"connection_generation\":7,\"permit_sha256\":[2]}"
        val next = "{\"request_id\":\"req-2\",\"connection_generation\":8,\"permit_sha256\":[3]}"

        assertTrue(queue.offer(first))
        assertTrue(queue.offer(replacement))
        assertTrue(queue.offer(next))
        assertTrue(queue.remove(first))
        assertFalse(queue.remove("{\"request_id\":\"req-1\"}"))

        assertEquals(replacement, queue.poll())
        assertEquals(next, queue.poll())
        assertNull(queue.poll())
    }

    @Test
    fun suspendedReceiverWakesForTheNextChallenge() = runBlocking {
        val queue = BrowserHostConsentRequestQueue(capacity = 1)
        val received = async { queue.receive() }
        yield()

        assertTrue(queue.offer("binding"))
        assertEquals("binding", received.await())
    }
}
