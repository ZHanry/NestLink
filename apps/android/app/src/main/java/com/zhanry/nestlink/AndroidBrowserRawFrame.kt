package com.zhanry.nestlink

import androidx.annotation.Keep
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One packed BGRA frame transferred to the Rust WebRTC CaptureDevice.
 * This object is a one-use local JNI value, never UI state or a wire message.
 */
@Keep
internal class AndroidBrowserRawFrame(
    private val frameWidth: Int,
    private val frameHeight: Int,
    private val capturedAtNanos: Long,
    private val bytes: ByteArray,
) {
    private val cleared = AtomicBoolean(false)

    @Keep fun width(): Int = frameWidth
    @Keep fun height(): Int = frameHeight
    @Keep fun timestampNanos(): Long = capturedAtNanos

    /** JNI gets a bounded copy; the Kotlin-owned frame is cleared in finally. */
    @Keep
    fun copyPixels(): ByteArray {
        check(!cleared.get()) { "browser frame was already cleared" }
        return bytes.copyOf()
    }

    @Keep
    fun clear() {
        if (cleared.compareAndSet(false, true)) bytes.fill(0)
    }
}

/** A one-slot, replace-oldest queue. There is never a backlog of screen pixels. */
@Keep
internal class AndroidBrowserRawFrameQueue {
    private var accepting = false
    private var retired = false
    private var latest: AndroidBrowserRawFrame? = null

    @Synchronized
    fun activate(): Boolean {
        if (retired || accepting) return false
        clearLocked()
        accepting = true
        return true
    }

    @Synchronized
    fun offer(width: Int, height: Int, capturedAtNanos: Long, bgra: ByteArray): Boolean {
        val expected = width.toLong() * height.toLong() * 4L
        if (!accepting || width !in 1..8192 || height !in 1..8192 ||
            expected <= 0L || expected > 64L * 1024 * 1024 || expected != bgra.size.toLong() ||
            capturedAtNanos <= 0L
        ) {
            bgra.fill(0)
            return false
        }
        latest?.clear()
        latest = AndroidBrowserRawFrame(width, height, capturedAtNanos, bgra.copyOf())
        bgra.fill(0)
        return true
    }

    @Synchronized
    fun poll(): AndroidBrowserRawFrame? {
        if (!accepting) return null
        return latest.also { latest = null }
    }

    @Synchronized
    fun stopAndClear() {
        retired = true
        accepting = false
        clearLocked()
    }

    /** Retire pixels across a resize while keeping this proved owner's queue open. */
    @Synchronized
    fun clearPending() {
        clearLocked()
    }

    private fun clearLocked() {
        latest?.clear()
        latest = null
    }
}

/**
 * Rust retains this endpoint only for the exact proved BrowserHost binding.
 * Only an exact post-proof activation can open this endpoint's queue;
 * projection setup and UI consent alone leave it closed.
 */
@Keep
internal class AndroidBrowserRawCaptureEndpoint(
    private val bindingJson: String,
    private val boundRequestId: String,
    private val boundGeneration: Long,
    private val queue: AndroidBrowserRawFrameQueue,
    private val activateOwner: (String, Boolean, Boolean) -> Boolean,
    private val stopOwner: (String) -> Boolean,
    private val displaySize: () -> Pair<Int, Int>,
    private val audioOwner: (String) -> BrowserHostAudioCaptureEndpoint?,
    private val stopInputOwner: (String) -> Boolean,
) {
    private enum class Lifecycle { Ready, Activating, Active, Retired }

    private val lifecycleGate = Any()
    private var lifecycle = Lifecycle.Ready
    @Volatile private var active = false
    @Volatile private var inputActive = false

    @Keep
    fun matchesBinding(expectedBindingJson: String): Boolean =
        expectedBindingJson == bindingJson && boundRequestId.isNotBlank() && boundGeneration > 0L

    @Keep fun isActive(): Boolean = active

    @Keep
    fun activateAfterProof(expectedBindingJson: String, audio: Boolean, input: Boolean): Boolean {
        if (!matchesBinding(expectedBindingJson)) return false
        synchronized(lifecycleGate) {
            if (lifecycle != Lifecycle.Ready) return false
            // Consume the endpoint before crossing into the service, including failures.
            lifecycle = Lifecycle.Activating
        }
        // A service callback can wait for a worker which retires this endpoint.
        // Never retain lifecycleGate while crossing that boundary.
        val started = runCatching {
            activateOwner(expectedBindingJson, audio, input)
        }.getOrDefault(false)
        return synchronized(lifecycleGate) {
            if (lifecycle != Lifecycle.Activating) return@synchronized false
            if (!started || !queue.activate()) {
                retireLocked()
                return@synchronized false
            }
            inputActive = input
            active = true
            lifecycle = Lifecycle.Active
            true
        }
    }

    @Keep fun displayWidth(): Int = if (active) displaySize().first else 0
    @Keep fun displayHeight(): Int = if (active) displaySize().second else 0

    /** Read-only candidate geometry of this staged system selection. */
    private fun preparedDisplaySize(expectedBindingJson: String): Pair<Int, Int>? {
        val ready = synchronized(lifecycleGate) {
            matchesBinding(expectedBindingJson) && lifecycle == Lifecycle.Ready
        }
        if (!ready) return null
        // The service owns its own lock and may retire this endpoint. Never
        // hold lifecycleGate across that callback.
        val size = displaySize()
        return synchronized(lifecycleGate) { size.takeIf { lifecycle == Lifecycle.Ready } }
    }

    @Keep fun preparedDisplayWidth(expectedBindingJson: String): Int =
        preparedDisplaySize(expectedBindingJson)?.first ?: 0

    @Keep fun preparedDisplayHeight(expectedBindingJson: String): Int =
        preparedDisplaySize(expectedBindingJson)?.second ?: 0

    @Keep
    fun openAudioCapture(expectedBindingJson: String): BrowserHostAudioCaptureEndpoint? =
        if (matchesBinding(expectedBindingJson) && active) audioOwner(expectedBindingJson) else null

    @Keep
    fun isInputActive(expectedBindingJson: String): Boolean =
        hasActiveInput(expectedBindingJson) &&
            HostCaptureService.isBrowserHostInputActive(expectedBindingJson)

    private fun hasActiveInput(expectedBindingJson: String): Boolean =
        matchesBinding(expectedBindingJson) && active && inputActive

    @Keep
    fun selectInputSource(
        expectedBindingJson: String,
        source: Int,
        left: Int,
        top: Int,
        width: Int,
        height: Int,
    ): Boolean = hasActiveInput(expectedBindingJson) &&
        HostCaptureService.selectBrowserHostInputSource(
            expectedBindingJson, source, left, top, width, height,
        )

    @Keep
    fun sendHidKey(expectedBindingJson: String, usage: Int, down: Boolean): Boolean =
        hasActiveInput(expectedBindingJson) &&
            HostCaptureService.sendBrowserHostHidKey(expectedBindingJson, usage, down)

    @Keep
    fun dispatchPointer(expectedBindingJson: String, x: Int, y: Int, phase: Int): Boolean =
        hasActiveInput(expectedBindingJson) &&
            HostCaptureService.dispatchBrowserHostPointer(expectedBindingJson, x, y, phase)

    @Keep
    fun commitRemoteText(expectedBindingJson: String, text: String): Boolean =
        hasActiveInput(expectedBindingJson) &&
            HostCaptureService.commitBrowserHostText(expectedBindingJson, text)

    @Keep
    fun releasePointer(expectedBindingJson: String): Boolean =
        hasActiveInput(expectedBindingJson) &&
            HostCaptureService.releaseBrowserHostPointer(expectedBindingJson)

    @Keep
    fun stopInputAndAwait(expectedBindingJson: String): Boolean {
        if (!matchesBinding(expectedBindingJson)) return false
        if (!runCatching { stopInputOwner(expectedBindingJson) }.getOrDefault(false)) return false
        inputActive = false
        return true
    }

    @Keep
    fun retireFromOwner() {
        synchronized(lifecycleGate) { retireLocked() }
    }

    private fun retireLocked() {
        lifecycle = Lifecycle.Retired
        active = false
        inputActive = false
        queue.stopAndClear()
    }

    @Keep
    fun pollRawFrame(): AndroidBrowserRawFrame? = if (active) queue.poll() else null

    /** Owner shutdown is acknowledged only after the MediaProjection worker exits. */
    @Keep
    fun stopAndAwait(expectedBindingJson: String): Boolean {
        if (!matchesBinding(expectedBindingJson)) return false
        synchronized(lifecycleGate) { retireLocked() }
        return runCatching { stopOwner(expectedBindingJson) }.getOrDefault(false)
    }
}
