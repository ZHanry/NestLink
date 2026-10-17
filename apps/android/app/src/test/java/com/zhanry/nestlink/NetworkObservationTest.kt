package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkObservationTest {
    @Test
    fun lateBlockedCallbackFromOldDefaultCannotBlockReplacement() {
        val observation = DefaultNetworkObservation()
        observation.observeDefaultNetwork(17L)
        assertTrue(observation.observeBlockedStatus(17L, blocked = true))
        assertTrue(observation.isBlocked(17L))

        observation.observeDefaultNetwork(18L)
        assertFalse(observation.observeBlockedStatus(17L, blocked = true))
        assertFalse(observation.isBlocked(18L))
    }

    @Test
    fun lateUnblockedCallbackFromOldDefaultCannotClearReplacementBlock() {
        val observation = DefaultNetworkObservation()
        observation.observeDefaultNetwork(18L)
        assertTrue(observation.observeBlockedStatus(18L, blocked = true))

        assertFalse(observation.observeBlockedStatus(17L, blocked = false))
        assertTrue(observation.isBlocked(18L))
    }

    @Test
    fun staleCapabilitiesAndLinkCallbacksAreRejectedForReplacementDefault() {
        val observation = DefaultNetworkObservation()
        observation.observeDefaultNetwork(18L)

        assertFalse(observation.isCurrentDefault(17L))
        assertTrue(observation.isCurrentDefault(18L))
    }

    @Test
    fun rejectsTargetThatWasNotTheDefaultBeforeSnapshotRead() {
        var reads = 0
        val snapshot = readStableDefaultNetworkSnapshot(
            expectedNetworkHandle = 17L,
            currentDefaultNetworkHandle = { 18L },
            readSnapshot = { reads += 1; "facts" },
        )

        assertNull(snapshot)
        assertEquals(0, reads)
    }

    @Test
    fun rejectsSnapshotWhenDefaultChangesWhileFactsAreRead() {
        var defaultReads = 0
        val snapshot = readStableDefaultNetworkSnapshot(
            expectedNetworkHandle = 17L,
            currentDefaultNetworkHandle = { if (defaultReads++ == 0) 17L else 18L },
            readSnapshot = { "facts" },
        )

        assertNull(snapshot)
        assertEquals(2, defaultReads)
    }

    @Test
    fun acceptsSnapshotWhenTheSameNetworkStaysDefault() {
        val snapshot = readStableDefaultNetworkSnapshot(
            expectedNetworkHandle = 17L,
            currentDefaultNetworkHandle = { 17L },
            readSnapshot = { "facts" },
        )

        assertEquals("facts", snapshot)
    }
}
