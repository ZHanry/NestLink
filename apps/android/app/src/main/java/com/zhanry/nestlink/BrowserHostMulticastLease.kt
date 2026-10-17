package com.zhanry.nestlink

internal interface BrowserMulticastPort {
    fun acquire()
    fun isHeld(): Boolean
    fun release()
}

/**
 * Owns one Wi-Fi receive lock for one complete BrowserHost binding. Before
 * endpoint proof it expires after 60 seconds; after proof every watchdog tick
 * must confirm the actual Rust lease. A failed release retains the old owner.
 */
internal class BrowserHostMulticastLease<K : Any>(
    private val elapsedMillis: () -> Long,
    private val proofWaitMillis: Long = 60_000L,
) {
    private class Owner<K>(
        val binding: K,
        val port: BrowserMulticastPort?,
        val started: Long,
        var lastObserved: Long,
        var proved: Boolean = false,
        var closing: Boolean = false,
    )

    private var owner: Owner<K>? = null

    init { require(proofWaitMillis in 1L..60_000L) }

    @Synchronized
    fun stage(binding: K, createPort: () -> BrowserMulticastPort?): Boolean {
        owner?.let { return !it.closing && it.binding == binding }
        val now = elapsedMillis()
        check(now >= 0L) { "Invalid multicast monotonic clock" }
        val port = createPort()
        // Retain ownership before acquire: a platform failure may occur after
        // acquiring the underlying resource and still require a later release.
        owner = Owner(binding, port, now, now)
        port?.acquire()
        check(port == null || port.isHeld()) { "Wi-Fi multicast receive lock was not acquired" }
        return true
    }

    @Synchronized
    fun poll(binding: K, liveLease: Boolean): Boolean {
        val current = owner ?: return false
        if (current.binding != binding) return false
        if (current.closing) return false
        val now = elapsedMillis()
        if (now < current.lastObserved ||
            (!liveLease && (current.proved || now - current.started >= proofWaitMillis))
        ) {
            stop(binding)
            return false
        }
        current.lastObserved = now
        current.proved = current.proved || liveLease
        check(current.port == null || current.port.isHeld()) { "Wi-Fi multicast receive lock was lost" }
        return true
    }

    @Synchronized
    fun stop(binding: K): Boolean {
        val current = owner ?: return true
        if (current.binding != binding) return false
        current.closing = true
        current.port?.let { port ->
            if (port.isHeld()) port.release()
            check(!port.isHeld()) { "Wi-Fi multicast receive lock did not release" }
        }
        owner = null
        return true
    }

    @Synchronized
    fun retryPendingCleanup() {
        owner?.takeIf { it.closing }?.let { check(stop(it.binding)) }
    }
}
