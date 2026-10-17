package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteVideoRetirementTest {
    @Test
    fun lateFrameCommitDoesNotRecycleAfterAComponentReacquiresTheLease() {
        var released = 0
        val retirement = RemoteVideoRetirement { released += 1 }
        val barrier = FakeFrameCommitBarrier()

        assertTrue(retirement.acquireForDisplay())
        retirement.releaseFromDisplay(barrier)
        retirement.releaseOwner()
        assertEquals(1, barrier.pendingCount)

        // A new Compose consumer appears before the old removal callback runs.
        assertTrue(retirement.acquireForDisplay())
        barrier.commitNext()
        assertEquals(0, released)

        retirement.releaseFromDisplay(barrier)
        assertEquals(1, barrier.pendingCount)
        barrier.commitNext()
        assertEquals(1, released)
        assertFalse(retirement.acquireForDisplay())
    }

    @Test
    fun unavailableCommitSourceRetainsStorageUntilAnAttachedBarrierCanRetry() {
        var released = 0
        val retirement = RemoteVideoRetirement { released += 1 }
        val unavailable = FakeFrameCommitBarrier(available = false)
        val attached = FakeFrameCommitBarrier()

        assertTrue(retirement.acquireForDisplay())
        retirement.releaseFromDisplay(unavailable)
        retirement.releaseOwner()
        assertEquals(0, released)
        assertEquals(0, unavailable.pendingCount)

        retirement.retry(attached)
        assertEquals(1, attached.pendingCount)
        attached.commitNext()
        assertEquals(1, released)
    }

    @Test
    fun commitFromDetachedViewCannotAuthorizeReleaseAfterReattachment() {
        var released = 0
        val retirement = RemoteVideoRetirement { released += 1 }
        val barrier = FakeFrameCommitBarrier()

        assertTrue(retirement.acquireForDisplay())
        retirement.releaseFromDisplay(barrier)
        retirement.releaseOwner()
        retirement.cancelPendingCommit(barrier)
        retirement.retry(barrier)
        assertEquals(2, barrier.pendingCount)

        barrier.commitNext()
        assertEquals(0, released)
        barrier.commitNext()
        assertEquals(1, released)
    }

    @Test
    fun neverPresentedImageReleasesImmediately() {
        var released = 0
        val retirement = RemoteVideoRetirement { released += 1 }

        retirement.disposeUnpresented()

        assertEquals(1, released)
        assertFalse(retirement.acquireForDisplay())
    }

    private class FakeFrameCommitBarrier(
        private val available: Boolean = true,
    ) : RemoteVideoFrameCommitBarrier {
        private val callbacks = ArrayDeque<() -> Unit>()
        val pendingCount: Int get() = callbacks.size

        override fun afterNextFrameCommit(callback: () -> Unit, onUnavailable: () -> Unit): Boolean {
            if (!available) return false
            callbacks.addLast(callback)
            return true
        }

        fun commitNext() {
            callbacks.removeFirst().invoke()
        }
    }
}
