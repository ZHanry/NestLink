package com.zhanry.nestlink

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserHostConsentRequestsTest {
    @Test
    fun cancellationWaitsForEnqueueAndThenRemovesThatExactRequest() {
        val queue = BrowserHostConsentRequestQueue(capacity = 1)
        val requests = BrowserHostConsentRequests(queue)
        val pendingStateReached = CountDownLatch(1)
        val allowQueueOffer = CountDownLatch(1)
        val cancelStarted = CountDownLatch(1)
        val requestDone = CountDownLatch(1)
        val cancelDone = CountDownLatch(1)

        val requester = Thread {
            assertTrue(
                requests.request(
                    "exact-binding",
                    onPending = {
                        pendingStateReached.countDown()
                        check(allowQueueOffer.await(2, TimeUnit.SECONDS))
                    },
                    onCapacityFailure = {},
                ),
            )
            requestDone.countDown()
        }
        requester.start()
        assertTrue(pendingStateReached.await(2, TimeUnit.SECONDS))

        val canceller = Thread {
            cancelStarted.countDown()
            requests.cancel("exact-binding") {}
            cancelDone.countDown()
        }
        canceller.start()
        assertTrue(cancelStarted.await(2, TimeUnit.SECONDS))
        val cancelledBeforeOffer = cancelDone.await(50, TimeUnit.MILLISECONDS)

        allowQueueOffer.countDown()
        assertTrue(requestDone.await(2, TimeUnit.SECONDS))
        assertTrue(cancelDone.await(2, TimeUnit.SECONDS))
        requester.join(2_000)
        canceller.join(2_000)

        assertFalse(cancelledBeforeOffer)
        assertEquals("cancelled", requests.state("exact-binding"))
        assertNull(queue.poll())
    }
}
