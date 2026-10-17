package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserHostActivationLeaseGateTest {
    @Test
    fun revocationWhileActivationWaitsInHandlerPreventsAllSystemCalls() {
        var leaseActive = true
        var queriedBinding: String? = null
        var systemCalls = 0
        val gate = BrowserHostActivationLeaseGate { binding ->
            queriedBinding = binding
            leaseActive
        }

        // Rust's initial check and JNI activation have already succeeded; the
        // worker is now dequeued after the lease was revoked.
        leaseActive = false
        val activated = gate.runIfActive("exact-binding") {
            systemCalls++
        }

        assertFalse(activated)
        assertEquals("exact-binding", queriedBinding)
        assertEquals(0, systemCalls)
    }

    @Test
    fun liveExactBindingRunsTheActivationStage() {
        var calls = 0
        val gate = BrowserHostActivationLeaseGate { binding -> binding == "live-binding" }

        assertTrue(gate.runIfActive("live-binding") { calls++ })
        assertFalse(gate.runIfActive("stale-binding") { calls++ })
        assertEquals(1, calls)
    }
}
