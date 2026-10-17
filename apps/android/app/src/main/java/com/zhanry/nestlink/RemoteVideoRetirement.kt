package com.zhanry.nestlink

import android.os.Build
import android.os.Handler
import android.os.Looper
import android.view.View
import java.lang.ref.WeakReference

/** A callback fires only after a frame excluding the retired image reaches the swap chain. */
internal fun interface RemoteVideoFrameCommitBarrier {
    fun afterNextFrameCommit(callback: () -> Unit, onUnavailable: () -> Unit): Boolean
}

/** Registers a hardware-rendered frame commit and returns completion to the main thread. */
internal class AndroidViewFrameCommitBarrier(
    view: View,
) : RemoteVideoFrameCommitBarrier {
    private val viewReference = WeakReference(view)
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun afterNextFrameCommit(
        callback: () -> Unit,
        onUnavailable: () -> Unit,
    ): Boolean {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            val posted = mainHandler.post {
                if (!registerOnMain(callback, onUnavailable)) onUnavailable()
            }
            if (!posted) onUnavailable()
            return posted
        }

        val registered = registerOnMain(callback, onUnavailable)
        if (!registered) onUnavailable()
        return registered
    }

    private fun registerOnMain(callback: () -> Unit, onUnavailable: () -> Unit): Boolean {
        val view = viewReference.get() ?: return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
            !view.isAttachedToWindow || !view.isHardwareAccelerated
        ) return false

        val observer = view.viewTreeObserver
        if (!observer.isAlive) return false

        return runCatching {
            observer.registerFrameCommitCallback {
                // Render callbacks may run off the UI thread. Posting ensures bitmap release runs
                // after the committed frame callback has returned and on the main thread.
                if (!mainHandler.post { callback() }) onUnavailable()
            }
            view.invalidate()
            true
        }.getOrDefault(false)
    }
}

/** Tracks Compose consumers and waits for a real frame commit before releasing rendered pixels. */
internal class RemoteVideoRetirement(
    private val releaseStorage: () -> Unit,
) {
    private val lock = Any()
    private var ownerRetained = true
    private var displayConsumers = 0
    private var everDisplayed = false
    private var awaitingFrameCommit = false
    private var frameCommitRequested = false
    private var frameCommitToken = 0L
    private var removalCommitted = false
    private var recycled = false
    private var lastBarrier: RemoteVideoFrameCommitBarrier? = null

    fun acquireForDisplay(): Boolean = synchronized(lock) {
        if (recycled) {
            false
        } else {
            displayConsumers += 1
            everDisplayed = true
            awaitingFrameCommit = false
            removalCommitted = false
            true
        }
    }

    fun releaseFromDisplay(barrier: RemoteVideoFrameCommitBarrier) {
        val shouldRequest = synchronized(lock) {
            if (displayConsumers == 0) {
                false
            } else {
                displayConsumers -= 1
                if (displayConsumers == 0) {
                    awaitingFrameCommit = true
                    removalCommitted = false
                    true
                } else {
                    false
                }
            }
        }
        if (shouldRequest) requestFrameCommit(barrier)
    }

    fun releaseOwner() {
        var releaseNow = false
        var requestWith: RemoteVideoFrameCommitBarrier? = null
        synchronized(lock) {
            ownerRetained = false
            if (!recycled && displayConsumers == 0) {
                if (!everDisplayed || removalCommitted) {
                    recycled = true
                    releaseNow = true
                } else {
                    awaitingFrameCommit = true
                    requestWith = lastBarrier
                }
            }
        }
        if (releaseNow) releaseStorage()
        else requestWith?.let(::requestFrameCommit)
    }

    /** A frame rejected before publication has no renderer consumer and can be released now. */
    fun disposeUnpresented() {
        val releaseNow = synchronized(lock) {
            if (recycled) {
                false
            } else if (displayConsumers == 0) {
                ownerRetained = false
                recycled = true
                true
            } else {
                ownerRetained = false
                awaitingFrameCommit = true
                false
            }
        }
        if (releaseNow) releaseStorage()
        else retryWithLastBarrier()
    }

    /** Retry a pending retirement after a view becomes attached and hardware-rendered. */
    fun retry(barrier: RemoteVideoFrameCommitBarrier) {
        val shouldRequest = synchronized(lock) {
            awaitingFrameCommit && displayConsumers == 0
        }
        if (shouldRequest) requestFrameCommit(barrier)
    }

    /** Invalidate callbacks owned by a detached view so a later attach can register a fresh one. */
    fun cancelPendingCommit(barrier: RemoteVideoFrameCommitBarrier) {
        synchronized(lock) {
            if (frameCommitRequested && lastBarrier === barrier) {
                frameCommitRequested = false
                frameCommitToken += 1
            }
        }
    }

    private fun retryWithLastBarrier() {
        val barrier = synchronized(lock) { lastBarrier }
        barrier?.let(::requestFrameCommit)
    }

    private fun requestFrameCommit(barrier: RemoteVideoFrameCommitBarrier) {
        val requestToken = synchronized(lock) {
            if (recycled || !awaitingFrameCommit || displayConsumers != 0 ||
                (frameCommitRequested && lastBarrier === barrier)
            ) {
                null
            } else {
                // A different View owns the current render target; callbacks from the old tree
                // become stale as soon as this request advances the token.
                lastBarrier = barrier
                frameCommitToken += 1
                frameCommitRequested = true
                frameCommitToken
            }
        }
        if (requestToken == null) return

        val registered = barrier.afterNextFrameCommit(
            callback = { onFrameCommit(requestToken) },
            onUnavailable = { clearFrameCommitRequest(requestToken) },
        )
        if (!registered) clearFrameCommitRequest(requestToken)
    }

    private fun clearFrameCommitRequest(requestToken: Long) {
        synchronized(lock) {
            if (frameCommitToken == requestToken) frameCommitRequested = false
        }
    }

    private fun onFrameCommit(requestToken: Long) {
        val releaseNow = synchronized(lock) {
            if (!frameCommitRequested || frameCommitToken != requestToken) return@synchronized false
            frameCommitRequested = false
            if (displayConsumers != 0) {
                // A component reacquired the lease before this late callback. Its visible frame
                // wins; a later release must wait for a fresh commit after removal.
                awaitingFrameCommit = false
                removalCommitted = false
                false
            } else {
                awaitingFrameCommit = false
                removalCommitted = true
                if (!ownerRetained && !recycled) {
                    recycled = true
                    true
                } else {
                    false
                }
            }
        }
        if (releaseNow) releaseStorage()
    }
}
