package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteVideoPixelsTest {
    @Test
    fun convertsBgraBytesToArgbWithCorrectChannelsAndAlpha() {
        val converted = RemoteVideoPixels.bgraToArgb(
            byteArrayOf(1, 2, 3, 255.toByte(), 10, 20, 30, 128.toByte()),
            width = 2,
            height = 1,
        )

        assertEquals(2, converted.width)
        assertEquals(1, converted.height)
        assertEquals(0xff030201.toInt(), converted.pixels[0])
        assertEquals(0x801e140a.toInt(), converted.pixels[1])
    }

    @Test
    fun downscalesWithinDimensionBudgetWithoutChangingAspectRatio() {
        val converted = RemoteVideoPixels.bgraToArgb(
            ByteArray(4 * 4 * 4) { index -> index.toByte() },
            width = 4,
            height = 4,
            maxDimension = 2,
        )

        assertEquals(2, converted.width)
        assertEquals(2, converted.height)
        assertEquals(4, converted.pixels.size)
    }

    @Test
    fun defaultPresentationBudgetLimitsTheLongEdgeTo1280Pixels() {
        val converted = RemoteVideoPixels.bgraToArgb(
            ByteArray(1920 * 1080 * 4),
            width = 1920,
            height = 1080,
        )

        assertEquals(1280, converted.width)
        assertEquals(720, converted.height)
        converted.pixels.fill(0)
    }

    @Test
    fun rejectsInvalidGeometryAndTruncatedDecodedPixels() {
        assertThrows(IllegalArgumentException::class.java) {
            RemoteVideoPixels.bgraToArgb(byteArrayOf(), width = 0, height = 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RemoteVideoPixels.bgraToArgb(byteArrayOf(1, 2, 3), width = 1, height = 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RemoteVideoPixels.bgraToArgb(ByteArray(16), width = 2, height = 2, maxDimension = 0)
        }
    }

    @Test
    fun decodedFrameMustMatchTheCurrentAuthorizedLayoutInEveryField() {
        val layout = NativeRemoteVideoLayout(
            connectionGeneration = 7,
            layoutEpoch = 3,
            source = 0,
            width = 640,
            height = 360,
        )
        val frame = NativeDecodedVideoFrame(
            connectionGeneration = 7,
            layoutEpoch = 3,
            source = 0,
            sequence = 12,
            pts90Khz = 90_000,
            width = 640,
            height = 360,
            bgra = ByteArray(4),
        )

        assertTrue(frame.matches(layout))
        assertFalse(frame.copy(connectionGeneration = 8).matches(layout))
        assertFalse(frame.copy(layoutEpoch = 4).matches(layout))
        assertFalse(frame.copy(source = 1).matches(layout))
        assertFalse(frame.copy(width = 320).matches(layout))
        assertFalse(frame.copy(height = 240).matches(layout))
        frame.bgra.fill(0)
    }
}
