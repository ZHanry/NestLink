package com.zhanry.nestlink

import kotlinx.coroutines.flow.Flow

/** Keeps each consent state transition atomic with its queue operation. */
internal class BrowserHostConsentRequests(
    private val queue: BrowserHostConsentRequestQueue = BrowserHostConsentRequestQueue(),
) {
    private val lock = Any()
    private val state = HashMap<String, String>()

    fun asFlow(): Flow<String> = queue.asFlow()

    fun request(
        bindingJson: String,
        onPending: () -> Unit,
        onCapacityFailure: () -> Unit,
    ): Boolean = synchronized(lock) {
        when (state[bindingJson]) {
            "pending", "granted" -> return@synchronized true
            null -> Unit
            else -> return@synchronized false
        }
        state[bindingJson] = "pending"
        onPending()
        if (!queue.offer(bindingJson)) {
            state.remove(bindingJson, "pending")
            onCapacityFailure()
            return@synchronized false
        }
        true
    }

    fun state(bindingJson: String): String = synchronized(lock) {
        state[bindingJson] ?: "cancelled"
    }

    fun markGranted(bindingJson: String): Boolean = synchronized(lock) {
        if (state[bindingJson] != "pending") return@synchronized false
        state[bindingJson] = "granted"
        queue.remove(bindingJson)
        true
    }

    fun markDenied(bindingJson: String, onDenied: () -> Unit): Boolean = synchronized(lock) {
        if (state[bindingJson] != "pending") return@synchronized false
        state[bindingJson] = "denied"
        queue.remove(bindingJson)
        onDenied()
        true
    }

    fun <T : Any> takeGranted(bindingJson: String, reserve: () -> T?): T? = synchronized(lock) {
        if (state[bindingJson] != "granted") return@synchronized null
        val endpoint = reserve() ?: return@synchronized null
        state.remove(bindingJson, "granted")
        endpoint
    }

    fun cancel(bindingJson: String, onCancelled: () -> Unit) = synchronized(lock) {
        state.remove(bindingJson)
        queue.remove(bindingJson)
        onCancelled()
    }

    fun clear() = synchronized(lock) {
        state.clear()
        queue.clear()
    }
}
