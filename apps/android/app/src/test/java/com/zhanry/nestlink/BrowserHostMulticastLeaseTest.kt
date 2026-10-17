package com.zhanry.nestlink

import org.junit.Assert.*
import org.junit.Test

class BrowserHostMulticastLeaseTest {
    private class Port : BrowserMulticastPort {
        var held = false
        var acquires = 0
        var releases = 0
        var failAcquire = false
        var failRelease = false
        override fun acquire() {
            acquires++
            held = true
            check(!failAcquire)
        }
        override fun isHeld() = held
        override fun release() {
            releases++
            check(!failRelease)
            held = false
        }
    }

    @Test fun noLockBeforeStagingAndStaleOwnerCannotStop() {
        val port = Port()
        val lease = BrowserHostMulticastLease<String>({ 0L })
        assertEquals(0, port.acquires)
        assertTrue(lease.stage("binding-one") { port })
        assertFalse(lease.stop("binding-two"))
        assertTrue(port.held)
        assertTrue(lease.stop("binding-one"))
        assertFalse(port.held)
    }

    @Test fun repeatedStagingCannotExtendUnprovedDeadline() {
        var clock = 0L
        val port = Port()
        val lease = BrowserHostMulticastLease<String>({ clock }, 60L)
        assertTrue(lease.stage("one") { port })
        clock = 59L
        assertTrue(lease.stage("one") { error("Do not acquire twice") })
        assertTrue(lease.poll("one", false))
        clock = 60L
        assertFalse(lease.poll("one", false))
        assertFalse(port.held)
        assertEquals(1, port.acquires)
    }

    @Test fun provedLeaseKeepsDiscoveryAcrossIceRestartsUntilRevoked() {
        var clock = 0L
        val port = Port()
        val lease = BrowserHostMulticastLease<String>({ clock }, 60L)
        lease.stage("one") { port }
        assertTrue(lease.poll("one", true))
        clock = 5_000L
        assertTrue(lease.poll("one", true))
        assertTrue(port.held)
        assertFalse(lease.poll("one", false))
        assertFalse(port.held)
    }

    @Test fun monotonicRollbackClosesTheOwner() {
        var clock = 100L
        val port = Port()
        val lease = BrowserHostMulticastLease<String>({ clock })
        lease.stage("one") { port }
        clock = 99L
        assertFalse(lease.poll("one", true))
        assertFalse(port.held)
    }

    @Test fun releaseFailureRetainsOwnerAndBlocksReplacementUntilRetry() {
        val port = Port().apply { failRelease = true }
        val lease = BrowserHostMulticastLease<String>({ 0L })
        lease.stage("one") { port }
        assertTrue(runCatching { lease.stop("one") }.isFailure)
        assertFalse(lease.stage("two") { error("Old owner remains") })
        assertTrue(port.held)
        assertFalse(lease.stage("one") { error("Closing owner must not resume") })
        assertFalse(lease.poll("one", true))
        port.failRelease = false
        lease.retryPendingCleanup()
        assertTrue(lease.stage("two") { null })
    }

    @Test fun acquireFailureRetainsPossibleResourceForCleanup() {
        val port = Port().apply { failAcquire = true }
        val lease = BrowserHostMulticastLease<String>({ 0L })
        assertTrue(runCatching { lease.stage("one") { port } }.isFailure)
        assertFalse(lease.stage("two") { error("Must not replace") })
        assertTrue(lease.stop("one"))
        assertFalse(port.held)
    }

    @Test fun stalePollCannotChangeActiveBinding() {
        val port = Port()
        val lease = BrowserHostMulticastLease<String>({ 0L })
        lease.stage("one") { port }
        assertFalse(lease.poll("two", false))
        assertTrue(port.held)
        assertTrue(lease.poll("one", true))
    }

    @Test fun absentWifiServiceHasNoPlatformResourceButStillExpires() {
        var clock = 0L
        val lease = BrowserHostMulticastLease<String>({ clock }, 1L)
        assertTrue(lease.stage("one") { null })
        clock = 1L
        assertFalse(lease.poll("one", false))
    }
}
