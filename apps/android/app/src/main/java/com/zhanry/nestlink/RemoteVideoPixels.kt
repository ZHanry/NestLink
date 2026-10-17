package com.zhanry.nestlink

import android.graphics.Bitmap

internal data class ArgbVideoPixels(
    val width: Int,
    val height: Int,
    val pixels: IntArray,
)

/** Bounded conversion from Rust's packed BGRA decoder buffer to Android ARGB pixels. */
internal object RemoteVideoPixels {
    private const val MAX_SOURCE_DIMENSION = 8192
    private const val MAX_FRAME_BYTES = 64L * 1024 * 1024
    private const val MAX_PRESENTATION_DIMENSION = 1280

    fun bgraToArgb(
        bgra: ByteArray,
        width: Int,
        height: Int,
        maxDimension: Int = MAX_PRESENTATION_DIMENSION,
    ): ArgbVideoPixels {
        val sourcePixels = width.toLong() * height.toLong()
        require(
            width in 1..MAX_SOURCE_DIMENSION && height in 1..MAX_SOURCE_DIMENSION &&
                sourcePixels * 4 <= MAX_FRAME_BYTES && maxDimension >= 1 &&
                sourcePixels * 4 == bgra.size.toLong(),
        ) {
            "decoded video exceeds the Android frame budget or has invalid geometry"
        }

        val scale = minOf(1.0, maxDimension.toDouble() / maxOf(width, height))
        val outputWidth = (width * scale).toInt().coerceAtLeast(1)
        val outputHeight = (height * scale).toInt().coerceAtLeast(1)
        val output = IntArray(Math.multiplyExact(outputWidth, outputHeight))
        for (y in 0 until outputHeight) {
            val sourceY = y.toLong() * height / outputHeight
            for (x in 0 until outputWidth) {
                val sourceX = x.toLong() * width / outputWidth
                val source = ((sourceY * width + sourceX) * 4).toInt()
                val blue = bgra[source].toInt() and 0xff
                val green = bgra[source + 1].toInt() and 0xff
                val red = bgra[source + 2].toInt() and 0xff
                val alpha = bgra[source + 3].toInt() and 0xff
                output[y * outputWidth + x] =
                    (alpha shl 24) or (red shl 16) or (green shl 8) or blue
            }
        }
        return ArgbVideoPixels(outputWidth, outputHeight, output)
    }

    fun toBitmap(frame: NativeDecodedVideoFrame): Bitmap {
        var pixels: IntArray? = null
        try {
            val argb = bgraToArgb(frame.bgra, frame.width, frame.height)
            pixels = argb.pixels
            return Bitmap.createBitmap(
                argb.pixels,
                argb.width,
                argb.height,
                Bitmap.Config.ARGB_8888,
            )
        } finally {
            pixels?.fill(0)
            frame.bgra.fill(0)
        }
    }
}
