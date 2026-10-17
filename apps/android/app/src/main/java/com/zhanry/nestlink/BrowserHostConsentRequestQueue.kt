package com.zhanry.nestlink

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.util.ArrayDeque

/**
 * A bounded FIFO for consent challenges. Queue removal compares the complete
 * serialized binding so cancellation cannot retire a replacement request.
 */
internal class BrowserHostConsentRequestQueue(
    private val capacity: Int = MAX_PENDING_BROWSER_HOST_CONSENT_REQUESTS,
) {
    private val lock = Any()
    private val pending = ArrayDeque<String>()
    private val wakeup = Channel<Unit>(Channel.CONFLATED)

    init {
        require(capacity > 0)
    }

    fun offer(bindingJson: String): Boolean {
        val accepted = synchronized(lock) {
            if (pending.size >= capacity) {
                false
            } else {
                pending.addLast(bindingJson)
                true
            }
        }
        if (accepted) wakeup.trySend(Unit)
        return accepted
    }

    fun remove(bindingJson: String): Boolean = synchronized(lock) {
        pending.remove(bindingJson)
    }

    fun clear() = synchronized(lock) {
        pending.clear()
    }

    fun poll(): String? = synchronized(lock) {
        pending.pollFirst()
    }

    suspend fun receive(): String {
        while (true) {
            poll()?.let { return it }
            wakeup.receive()
        }
    }

    fun asFlow(): Flow<String> = flow {
        while (true) emit(receive())
    }

    private companion object {
        const val MAX_PENDING_BROWSER_HOST_CONSENT_REQUESTS = 16
    }
}
