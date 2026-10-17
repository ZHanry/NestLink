package com.zhanry.nestlink

/**
 * Rechecks a proof-bound live lease at the last application boundary before
 * an Android media or input resource is created.
 */
internal class BrowserHostActivationLeaseGate(
    private val leaseIsActive: (String) -> Boolean,
) {
    fun isActive(bindingJson: String): Boolean =
        runCatching { leaseIsActive(bindingJson) }.getOrDefault(false)

    fun runIfActive(bindingJson: String, operation: () -> Unit): Boolean {
        if (!isActive(bindingJson)) return false
        operation()
        return true
    }
}
