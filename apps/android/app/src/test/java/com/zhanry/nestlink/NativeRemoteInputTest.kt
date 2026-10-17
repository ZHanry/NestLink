package com.zhanry.nestlink

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class NativeRemoteInputTest {
    private val layout = NativeRemoteInputLayout(
        NativeInputBinding("request-1", 7, 0, 3, 9),
        left = 100,
        top = 40,
        width = 2400,
        height = 1080,
    )

    @Test
    fun mapsFittedVideoCoordinatesIntoHostLogicalBounds() {
        assertEquals(100 to 40, mapVideoPointToInput(0f, 0f, 1920f, 864f, layout))
        assertEquals(1300 to 580, mapVideoPointToInput(960f, 432f, 1920f, 864f, layout))
        assertEquals(2499 to 1119, mapVideoPointToInput(1919.9f, 863.9f, 1920f, 864f, layout))
    }

    @Test
    fun rejectsOutsideAndInvalidVideoCoordinates() {
        assertNull(mapVideoPointToInput(-0.1f, 0f, 1920f, 864f, layout))
        assertNull(mapVideoPointToInput(1920f, 0f, 1920f, 864f, layout))
        assertNull(mapVideoPointToInput(Float.NaN, 1f, 1920f, 864f, layout))
        assertNull(mapVideoPointToInput(1f, 1f, 0f, 864f, layout))
    }

    @Test
    fun nativeJsonMatchesRustSerdeBindingsAndActions() {
        val binding = JSONObject(layout.binding.toJson())
        assertEquals("request-1", binding.getString("request_id"))
        assertEquals(7L, binding.getLong("connection_generation"))
        assertEquals(0, binding.getInt("source"))
        assertEquals(3L, binding.getLong("input_epoch"))
        assertEquals(9L, binding.getLong("layout_epoch"))
        assertEquals(layout, NativeRemoteInputLayout.parse(layout.toJson()))

        val textJson = JSONObject(NativeInputAction.Text("你好").toJson())
        assertEquals("text", textJson.getString("kind"))
        // Parsing the emitted JSON verifies the original Chinese value survives either escaped or literal encoding.
        assertEquals("你好", textJson.getString("value"))

        val pointerJson = JSONObject(NativeInputAction.Pointer(1, false, 140, 90).toJson())
        assertEquals("pointer", pointerJson.getString("kind"))
        val pointer = pointerJson.getJSONObject("value")
        assertEquals(1, pointer.getInt("button"))
        assertFalse(pointer.getBoolean("down"))
        assertEquals(140, pointer.getInt("x"))
        assertEquals(90, pointer.getInt("y"))
    }

    @Test
    fun parserTreatsMissingNullAndMalformedLayoutsAsUnavailable() {
        assertNull(NativeRemoteInputLayout.parse(null))
        assertNull(NativeRemoteInputLayout.parse("null"))
        assertNull(NativeRemoteInputLayout.parse("{"))
    }

    @Test
    fun parserRejectsInvalidEpochsAndOverflowingBounds() {
        val invalidEpoch = layout.copy(
            binding = layout.binding.copy(inputEpoch = 0),
        )
        val overflowingBounds = layout.copy(left = Int.MAX_VALUE)

        assertNull(NativeRemoteInputLayout.parse(invalidEpoch.toJson()))
        assertNull(NativeRemoteInputLayout.parse(overflowingBounds.toJson()))
    }
}
