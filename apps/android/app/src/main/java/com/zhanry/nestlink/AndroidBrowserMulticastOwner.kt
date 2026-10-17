package com.zhanry.nestlink

import android.content.Context
import android.net.wifi.WifiManager
import android.os.SystemClock

/** Process-wide retention prevents replacement while an old lock needs cleanup. */
internal object AndroidBrowserMulticastOwner {
    private val lease = BrowserHostMulticastLease<HostCaptureBinding.BrowserHost>(SystemClock::elapsedRealtime)

    fun stage(context: Context, bindingJson: String): Boolean {
        val binding = parse(bindingJson) ?: return false
        lease.retryPendingCleanup()
        return lease.stage(binding) {
            context.applicationContext.getSystemService(WifiManager::class.java)?.let { wifi ->
                val lock = wifi.createMulticastLock("NestLink browser discovery").apply {
                    setReferenceCounted(false)
                }
                object : BrowserMulticastPort {
                    override fun acquire() = lock.acquire()
                    override fun isHeld(): Boolean = lock.isHeld
                    override fun release() = lock.release()
                }
            }
        }
    }

    fun poll(bindingJson: String, liveLease: Boolean): Boolean =
        parse(bindingJson)?.let { lease.poll(it, liveLease) } ?: false

    fun stop(bindingJson: String): Boolean =
        parse(bindingJson)?.let(lease::stop) ?: false

    private fun parse(json: String): HostCaptureBinding.BrowserHost? {
        if (json.length > 8 * 1024) return null
        return runCatching { HostCaptureBinding.browserHost(json) }.getOrNull()
    }
}
