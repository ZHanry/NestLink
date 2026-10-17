package com.zhanry.nestlink

/** Roles are separate owner slots even though app-core currently exposes one session per handle. */
internal enum class NativeAudioOwnerRole {
    HostCapture,
    ControllerPlayback,
}

internal data class NativeAudioEndpointOwner(
    val handle: Long,
    val role: NativeAudioOwnerRole,
    val bindingJson: String,
    val endpoint: NativeAudioEndpoint,
    val attached: Boolean,
)

/** Keeps the first failed reset as history while allowing later reap attempts to confirm cleanup. */
internal data class NativeAudioCleanupReceipt(
    val ownerId: Long,
    val handle: Long,
    val role: NativeAudioOwnerRole,
    val bindingJson: String,
    val attempts: Int,
    val failureObserved: Boolean,
    val cleanupComplete: Boolean,
    val detail: String?,
)

internal data class NativeAudioCleanupSummary(
    val cleanupComplete: Boolean,
    val receipts: List<NativeAudioCleanupReceipt>,
)

/**
 * Process-owned references for AudioRecord/AudioTrack endpoints. JNI attach can
 * reject an endpoint after attempting reset, so Kotlin must retain that exact
 * object until a later reset confirms both release and worker termination.
 */
internal class NativeAudioEndpointOwnerRegistry {
    private data class Key(val handle: Long, val role: NativeAudioOwnerRole)
    private data class Entry(
        val ownerId: Long,
        val bindingJson: String,
        val endpoint: NativeAudioEndpoint,
        var attached: Boolean,
    )

    private val lock = Any()
    private val owners = mutableMapOf<Key, MutableList<Entry>>()
    private val receipts = LinkedHashMap<Long, NativeAudioCleanupReceipt>()
    private var nextOwnerId = 1L

    fun registerPending(
        handle: Long,
        role: NativeAudioOwnerRole,
        bindingJson: String,
        endpoint: NativeAudioEndpoint,
    ): Boolean = synchronized(lock) {
        require(handle > 0L)
        require(bindingJson.isNotBlank())
        val key = Key(handle, role)
        if (owners[key].orEmpty().isNotEmpty()) return@synchronized false
        owners.getOrPut(key) { mutableListOf() }
            .add(Entry(nextOwnerId++, bindingJson, endpoint, attached = false))
        true
    }

    /** Retains a device created during an unexpected owner-slot race, without allowing it to attach. */
    fun retainRejectedPending(
        handle: Long,
        role: NativeAudioOwnerRole,
        bindingJson: String,
        endpoint: NativeAudioEndpoint,
    ): Boolean = synchronized(lock) {
        require(handle > 0L)
        require(bindingJson.isNotBlank())
        val key = Key(handle, role)
        val entries = owners.getOrPut(key) { mutableListOf() }
        entries.add(Entry(nextOwnerId++, bindingJson, endpoint, attached = false))
        true
    }

    fun markAttached(
        handle: Long,
        role: NativeAudioOwnerRole,
        bindingJson: String,
        endpoint: NativeAudioEndpoint,
    ): Boolean = synchronized(lock) {
        val entry = owners[Key(handle, role)]?.firstOrNull {
            it.endpoint === endpoint && it.bindingJson == bindingJson
        } ?: return@synchronized false
        entry.attached = true
        true
    }

    fun owner(handle: Long, role: NativeAudioOwnerRole): NativeAudioEndpointOwner? = synchronized(lock) {
        val entry = owners[Key(handle, role)]?.firstOrNull() ?: return@synchronized null
        NativeAudioEndpointOwner(handle, role, entry.bindingJson, entry.endpoint, entry.attached)
    }

    fun owners(handle: Long, role: NativeAudioOwnerRole): List<NativeAudioEndpointOwner> = synchronized(lock) {
        owners[Key(handle, role)].orEmpty().map {
            NativeAudioEndpointOwner(handle, role, it.bindingJson, it.endpoint, it.attached)
        }
    }

    /** Rechecks a timed-out reset and removes the strong owner reference only after confirmed cleanup. */
    fun reap(
        handle: Long,
        role: NativeAudioOwnerRole,
        expectedEndpoint: NativeAudioEndpoint? = null,
    ): NativeAudioCleanupReceipt? {
        val key = Key(handle, role)
        val entry = synchronized(lock) {
            owners[key]?.firstOrNull { expectedEndpoint == null || it.endpoint === expectedEndpoint }
        }
        if (entry == null) return synchronized(lock) {
            receipts.values.lastOrNull { it.handle == handle && it.role == role }
        }

        val stopped = runCatching { entry.endpoint.resetAndAwait() }.getOrDefault(false)
        val attemptCount = entry.endpoint.cleanupAttempts()
        val endpointFailure = entry.endpoint.lastCleanupFailure()
        val receipt = synchronized(lock) {
            val current = owners[key]
            val previous = receipts[entry.ownerId]
            val hadFailure = (previous?.failureObserved == true) ||
                entry.endpoint.cleanupFailureObserved() || !stopped
            val updated = NativeAudioCleanupReceipt(
                ownerId = entry.ownerId,
                handle = handle,
                role = role,
                bindingJson = entry.bindingJson,
                attempts = maxOf(previous?.attempts ?: 0, attemptCount),
                failureObserved = hadFailure,
                cleanupComplete = stopped,
                detail = if (stopped) previous?.detail else endpointFailure
                    ?: previous?.detail
                    ?: "Android audio device cleanup is not confirmed",
            )
            receipts[entry.ownerId] = updated
            trimHistoryLocked()
            if (stopped && current?.remove(entry) == true && current.isEmpty()) owners.remove(key)
            updated
        }
        return receipt
    }

    /** One bounded reap per active role; callers may invoke again after a late worker exit. */
    fun reapAll(handle: Long): NativeAudioCleanupSummary {
        val activeRoles = NativeAudioOwnerRole.entries
            .map { role -> reapAll(handle, role) }
        val currentRoles = synchronized(lock) { owners.keys.any { it.handle == handle } }
        val history = synchronized(lock) {
            receipts.values.filter { it.handle == handle }
        }
        return NativeAudioCleanupSummary(!currentRoles && activeRoles.all { it.cleanupComplete }, history)
    }

    /** Reaps every process-owned endpoint before any app-core handle is closed. */
    fun reapAllActive(includeHandle: Long? = null): NativeAudioCleanupSummary {
        val handles = activeHandles().toMutableSet()
        if (includeHandle != null) handles.add(includeHandle)
        val cleanups = handles.map(::reapAll)
        val remaining = activeHandles()
        val history = (handles + remaining).flatMap(::receipts).distinctBy { it.ownerId }
        return NativeAudioCleanupSummary(
            cleanupComplete = remaining.isEmpty() && cleanups.all { it.cleanupComplete },
            receipts = history,
        )
    }

    /** Reaps every owner for one role, including rejected attach-race orphans. */
    fun reapAll(handle: Long, role: NativeAudioOwnerRole): NativeAudioCleanupSummary {
        val endpoints = synchronized(lock) {
            owners[Key(handle, role)].orEmpty().map { it.endpoint }
        }
        for (endpoint in endpoints) reap(handle, role, endpoint)
        val remaining = synchronized(lock) { owners[Key(handle, role)].orEmpty().isNotEmpty() }
        val history = synchronized(lock) {
            receipts.values.filter { it.handle == handle && it.role == role }
        }
        return NativeAudioCleanupSummary(!remaining, history)
    }

    fun receipts(handle: Long): List<NativeAudioCleanupReceipt> = synchronized(lock) {
        receipts.values.filter { it.handle == handle }
    }

    fun activeHandles(): Set<Long> = synchronized(lock) { owners.keys.mapTo(mutableSetOf()) { it.handle } }

    private fun trimHistoryLocked() {
        while (receipts.size > MAX_RECEIPTS) {
            val first = receipts.entries.firstOrNull() ?: return
            val activeOwnerIds = owners.values.asSequence().flatten().map { it.ownerId }.toSet()
            if (first.key in activeOwnerIds) {
                // An active failed cleanup is never evicted from the receipt history.
                val next = receipts.entries.drop(1).firstOrNull { it.key !in activeOwnerIds } ?: return
                receipts.remove(next.key)
            } else {
                receipts.remove(first.key)
            }
        }
    }

    private companion object {
        const val MAX_RECEIPTS = 128
    }
}

internal val nativeAudioEndpointOwners = NativeAudioEndpointOwnerRegistry()
