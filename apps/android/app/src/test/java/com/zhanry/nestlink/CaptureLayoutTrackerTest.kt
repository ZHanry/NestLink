package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureLayoutTrackerTest {
    @Test
    fun portraitLandscapeResizeAdvancesLayoutEpochAndBoundsOutput() {
        val layouts = CaptureLayoutTracker()
        val portrait = layouts.initialize(1440, 2560)
        assertEquals(1080 to 1920, portrait.width to portrait.height)
        assertEquals(1L, portrait.epoch)

        val landscape = layouts.resize(2560, 1440)
        assertTrue(landscape.outputSizeChanged)
        assertEquals(1920 to 1080, landscape.layout.width to landscape.layout.height)
        assertEquals(2L, landscape.layout.epoch)
        assertFalse(layouts.accepts(portrait.epoch))
        assertTrue(layouts.accepts(landscape.layout.epoch))

        val appWindow = layouts.resize(1280, 720)
        assertTrue(appWindow.outputSizeChanged)
        assertEquals(1280 to 720, appWindow.layout.width to appWindow.layout.height)
        assertEquals(3L, appWindow.layout.epoch)
    }

    @Test
    fun changedContentSizeInvalidatesLayoutEvenWhenEncodedGeometryIsUnchanged() {
        val layouts = CaptureLayoutTracker()
        val initial = layouts.initialize(1000, 700)

        val update = layouts.resize(1001, 701)

        assertTrue(update.contentSizeChanged)
        assertFalse(update.outputSizeChanged)
        assertEquals(initial.width to initial.height, update.layout.width to update.layout.height)
        assertEquals(initial.epoch + 1L, update.layout.epoch)
        assertFalse(layouts.accepts(initial.epoch))
        assertTrue(layouts.accepts(update.layout.epoch))
        assertEquals(1001 to 701, update.layout.contentWidth to update.layout.contentHeight)
    }

    @Test
    fun duplicateContentSizeCallbackIsIdempotent() {
        val layouts = CaptureLayoutTracker()
        val initial = layouts.initialize(1000, 700)

        val update = layouts.resize(1000, 700)

        assertFalse(update.contentSizeChanged)
        assertFalse(update.outputSizeChanged)
        assertEquals(initial, update.layout)
        assertTrue(layouts.accepts(initial.epoch))
    }

    @Test
    fun reactivatingSameSourceStillAdvancesItsLayoutEpoch() {
        val layouts = CaptureLayoutTracker()
        val initial = layouts.initialize(1920, 1080)

        val resumed = layouts.advanceEpoch()

        assertEquals(initial.width to initial.height, resumed.width to resumed.height)
        assertEquals(initial.epoch + 1L, resumed.epoch)
        assertEquals(resumed, layouts.current)
        assertFalse(layouts.accepts(initial.epoch))
        assertTrue(layouts.accepts(resumed.epoch))
    }

    @Test
    fun maximumSourcePixelBudgetProducesBoundedEvenOutput() {
        val layout = CaptureLayoutTracker().initialize(8192, 8192)

        assertEquals(1920 to 1920, layout.width to layout.height)
        assertEquals(0, layout.width % 2)
        assertEquals(0, layout.height % 2)
    }

    @Test
    fun invalidAndOverBudgetDimensionsAreRejectedWithoutChangingLayout() {
        val layouts = CaptureLayoutTracker()
        val initial = layouts.initialize(1080, 1920)

        listOf(
            0 to 1920,
            -1 to 1080,
            1 to 1080,
            16_385 to 100,
            16_384 to 8_193,
            Int.MAX_VALUE to Int.MAX_VALUE,
        ).forEach { (width, height) ->
            assertThrows(IllegalArgumentException::class.java) {
                layouts.resize(width, height)
            }
            assertEquals(initial, layouts.current)
        }
    }

    @Test
    fun uninitializedLayoutCannotResizeOrAdvance() {
        val layouts = CaptureLayoutTracker()

        assertThrows(IllegalStateException::class.java) { layouts.resize(1280, 720) }
        assertThrows(IllegalStateException::class.java) { layouts.advanceEpoch() }
        assertNull(layouts.current)
    }
}
