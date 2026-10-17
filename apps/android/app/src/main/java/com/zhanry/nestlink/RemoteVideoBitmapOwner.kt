package com.zhanry.nestlink

import android.graphics.Bitmap
import java.util.Collections
import java.util.IdentityHashMap

/** Bounds display bitmaps until their renderer frame has safely retired. */
internal class RemoteVideoBitmapOwner(
    private val maxOutstandingBitmaps: Int = 3,
) {
    private val lock = Any()
    private var reservations = 0
    private val liveLeases = Collections.newSetFromMap(
        IdentityHashMap<RemoteVideoBitmapLease, Boolean>(),
    )

    init {
        require(maxOutstandingBitmaps >= 1)
    }

    fun reserve(): RemoteVideoBitmapReservation? = synchronized(lock) {
        if (liveLeases.size + reservations >= maxOutstandingBitmaps) return null
        reservations += 1
        RemoteVideoBitmapReservation(this)
    }

    internal fun commit(
        reservation: RemoteVideoBitmapReservation,
        bitmap: Bitmap,
    ): RemoteVideoBitmapLease = synchronized(lock) {
        check(reservation.active) { "remote video bitmap reservation is no longer active" }
        reservation.active = false
        reservations -= 1
        RemoteVideoBitmapLease(this, bitmap).also(liveLeases::add)
    }

    internal fun cancel(reservation: RemoteVideoBitmapReservation) = synchronized(lock) {
        if (reservation.active) {
            reservation.active = false
            reservations -= 1
        }
    }

    internal fun recycle(lease: RemoteVideoBitmapLease, bitmap: Bitmap) {
        bitmap.recycle()
        synchronized(lock) { liveLeases.remove(lease) }
    }

    fun releaseAll() {
        val leases = synchronized(lock) { liveLeases.toList() }
        leases.forEach(RemoteVideoBitmapLease::releaseOwner)
    }

    fun retryPendingRetirements(barrier: RemoteVideoFrameCommitBarrier) {
        val leases = synchronized(lock) { liveLeases.toList() }
        leases.forEach { it.retryRetirement(barrier) }
    }

    fun cancelPendingRetirements(barrier: RemoteVideoFrameCommitBarrier) {
        val leases = synchronized(lock) { liveLeases.toList() }
        leases.forEach { it.cancelPendingRetirement(barrier) }
    }

    internal val outstandingCount: Int
        get() = synchronized(lock) { liveLeases.size + reservations }
}

internal class RemoteVideoBitmapReservation internal constructor(
    private val owner: RemoteVideoBitmapOwner,
) : AutoCloseable {
    internal var active = true

    fun commit(bitmap: Bitmap): RemoteVideoBitmapLease = owner.commit(this, bitmap)

    override fun close() = owner.cancel(this)
}

internal class RemoteVideoBitmapLease internal constructor(
    private val owner: RemoteVideoBitmapOwner,
    val bitmap: Bitmap,
) {
    private val retirement = RemoteVideoRetirement { owner.recycle(this, bitmap) }

    fun acquireForDisplay(): Boolean = retirement.acquireForDisplay()

    fun releaseFromDisplay(barrier: RemoteVideoFrameCommitBarrier) =
        retirement.releaseFromDisplay(barrier)

    /** Called when this image is no longer the current presentation in the ViewModel. */
    fun releaseOwner() = retirement.releaseOwner()

    /** Safe for a converted frame that was never published to Compose. */
    fun disposeUnpresented() = retirement.disposeUnpresented()

    internal fun retryRetirement(barrier: RemoteVideoFrameCommitBarrier) = retirement.retry(barrier)

    internal fun cancelPendingRetirement(barrier: RemoteVideoFrameCommitBarrier) =
        retirement.cancelPendingCommit(barrier)
}
