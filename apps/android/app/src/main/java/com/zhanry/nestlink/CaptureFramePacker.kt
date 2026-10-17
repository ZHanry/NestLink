package com.zhanry.nestlink

/** Converts ImageReader's RGBA_8888 plane into the bounded BGRA input VP8 expects. */
internal object CaptureFramePacker {
    private const val MAX_SOURCE_DIMENSION = 16_384
    private const val MAX_SOURCE_PIXELS = 64L * 1024 * 1024
    private const val MAX_FRAME_BYTES = 64L * 1024 * 1024

    fun scaledSize(width: Int, height: Int, maxDimension: Int = 1920): Pair<Int, Int> {
        require(
            width in 2..MAX_SOURCE_DIMENSION && height in 2..MAX_SOURCE_DIMENSION &&
                width.toLong() * height.toLong() <= MAX_SOURCE_PIXELS && maxDimension >= 2,
        ) {
            "screen content dimensions exceed the capture budget"
        }
        val scale = minOf(1.0, maxDimension.toDouble() / maxOf(width, height))
        fun even(value: Double): Int = (value.toInt().coerceAtLeast(2) / 2) * 2
        val scaledWidth = even(width * scale)
        val scaledHeight = even(height * scale)
        require(scaledWidth.toLong() * scaledHeight.toLong() * 4 <= MAX_FRAME_BYTES) {
            "scaled screen frame exceeds the capture budget"
        }
        return scaledWidth to scaledHeight
    }

    fun rgbaToBgra(
        source: ByteArray,
        width: Int,
        height: Int,
        rowStride: Int,
        pixelStride: Int,
    ): ByteArray {
        require(
            width in 1..8192 && height in 1..8192 &&
                width.toLong() * height.toLong() * 4 <= 64L * 1024 * 1024,
        ) {
            "screen frame exceeds the capture budget"
        }
        require(pixelStride >= 4 && rowStride.toLong() >= width.toLong() * pixelStride.toLong()) {
            "screen frame has invalid pixel strides"
        }
        val output = ByteArray(Math.multiplyExact(Math.multiplyExact(width, height), 4))
        for (y in 0 until height) {
            val row = Math.multiplyExact(y, rowStride)
            for (x in 0 until width) {
                val inputIndex = Math.addExact(row, Math.multiplyExact(x, pixelStride))
                require(inputIndex.toLong() + 4 <= source.size.toLong()) { "screen frame plane is truncated" }
                val outputIndex = (y * width + x) * 4
                output[outputIndex] = source[inputIndex + 2]
                output[outputIndex + 1] = source[inputIndex + 1]
                output[outputIndex + 2] = source[inputIndex]
                output[outputIndex + 3] = source[inputIndex + 3]
            }
        }
        return output
    }
}

internal data class CaptureLayout(
    val contentWidth: Int,
    val contentHeight: Int,
    val width: Int,
    val height: Int,
    val epoch: Long,
)

internal data class CaptureLayoutUpdate(
    val layout: CaptureLayout,
    val contentSizeChanged: Boolean,
    val outputSizeChanged: Boolean,
)

/** Worker-owned layout generation for MediaProjection content resize callbacks. */
internal class CaptureLayoutTracker {
    var current: CaptureLayout? = null
        private set

    fun accepts(epoch: Long): Boolean = current?.epoch == epoch

    fun initialize(contentWidth: Int, contentHeight: Int): CaptureLayout {
        check(current == null) { "capture layout is already initialized" }
        val (width, height) = CaptureFramePacker.scaledSize(contentWidth, contentHeight)
        return CaptureLayout(contentWidth, contentHeight, width, height, epoch = 1L)
            .also { current = it }
    }

    fun resize(contentWidth: Int, contentHeight: Int): CaptureLayoutUpdate {
        val previous = checkNotNull(current) { "capture layout is not initialized" }
        val (width, height) = CaptureFramePacker.scaledSize(contentWidth, contentHeight)
        val contentSizeChanged = contentWidth != previous.contentWidth || contentHeight != previous.contentHeight
        val outputSizeChanged = width != previous.width || height != previous.height
        val epoch = if (contentSizeChanged) Math.addExact(previous.epoch, 1L) else previous.epoch
        val updated = CaptureLayout(contentWidth, contentHeight, width, height, epoch)
        current = updated
        return CaptureLayoutUpdate(updated, contentSizeChanged, outputSizeChanged)
    }

    /** Retire queued frames when re-enabling the same source after a View pause. */
    fun advanceEpoch(): CaptureLayout {
        val previous = checkNotNull(current) { "capture layout is not initialized" }
        return previous.copy(epoch = Math.addExact(previous.epoch, 1L)).also { current = it }
    }
}
