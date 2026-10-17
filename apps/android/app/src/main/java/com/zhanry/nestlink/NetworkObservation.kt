package com.zhanry.nestlink

/**
 * Accepts facts only when the target network was the default both before and
 * after collection. The reader must obtain facts from [expectedNetworkHandle].
 */
internal inline fun <T : Any> readStableDefaultNetworkSnapshot(
    expectedNetworkHandle: Long,
    currentDefaultNetworkHandle: () -> Long?,
    readSnapshot: () -> T?,
): T? {
    if (currentDefaultNetworkHandle() != expectedNetworkHandle) return null
    val snapshot = readSnapshot() ?: return null
    if (currentDefaultNetworkHandle() != expectedNetworkHandle) return null
    return snapshot
}

/** Mutable state for one ConnectivityManager default-network callback. */
internal class DefaultNetworkObservation {
    private var currentDefaultNetworkHandle: Long? = null
    private var blockedObservation: BlockedObservation? = null

    fun observeDefaultNetwork(networkHandle: Long?) {
        if (currentDefaultNetworkHandle == networkHandle) return
        currentDefaultNetworkHandle = networkHandle
        blockedObservation = null
    }

    fun isCurrentDefault(networkHandle: Long): Boolean =
        currentDefaultNetworkHandle == networkHandle

    /** Returns false and leaves state untouched for late callbacks from old networks. */
    fun observeBlockedStatus(networkHandle: Long, blocked: Boolean): Boolean {
        if (!isCurrentDefault(networkHandle)) return false
        blockedObservation = BlockedObservation(networkHandle, blocked)
        return true
    }

    fun isBlocked(networkHandle: Long?): Boolean =
        networkHandle != null && blockedObservation?.let {
            it.networkHandle == networkHandle && it.blocked
        } == true

    private data class BlockedObservation(val networkHandle: Long, val blocked: Boolean)
}
