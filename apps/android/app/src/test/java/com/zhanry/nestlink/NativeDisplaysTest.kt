package com.zhanry.nestlink

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class NativeDisplaysTest {
    private val requestId = "12345678-1234-4234-8234-123456789abc"
    private val displays = listOf(
        NativeDisplayDescriptor(42, -64, 0, 64, 48, "left"),
        NativeDisplayDescriptor(77, 0, 0, 64, 48, "right"),
    )
    private val catalog = key(1, displays)
    private val selected = NativeDisplaySelection(catalog, 1, 42, 1, 1)
    private val initial = NativeDisplays(catalog, displays, true, selected, null)

    private fun key(revision: Long, entries: List<NativeDisplayDescriptor>): NativeDisplayCatalog {
        val provisional = NativeDisplayCatalog(requestId, 9, revision, List(32) { 0 })
        return provisional.copy(sha256 = NativeDisplays.catalogHash(provisional, entries))
    }

    private fun json(state: NativeDisplays): JSONObject = JSONObject()
        .put("is_host", false).put("catalog", state.catalog?.toJson() ?: JSONObject.NULL)
        .put("displays", JSONArray(state.displays.map { display ->
            JSONObject().put("source", display.source.toLong() and 0xffff_ffffL)
                .put("left", display.left).put("top", display.top).put("width", display.width)
                .put("height", display.height).put("label", display.label)
        }))
        .put("local_approval_required", false)
        .put("approved_sources", JSONArray(state.displays.map { it.source.toLong() and 0xffff_ffffL }))
        .put("initial_source", state.displays.firstOrNull()?.source ?: JSONObject.NULL)
        .put("catalog_acknowledged", state.acknowledged)
        .put("selected", state.selected?.let { selection ->
            JSONObject().put("catalog", selection.catalog.toJson()).put("sequence", selection.sequence)
                .put("source", selection.source.toLong() and 0xffff_ffffL)
                .put("layout_epoch", selection.layoutEpoch).put("input_epoch", selection.inputEpoch)
        } ?: JSONObject.NULL)
        .put("pending", state.pending?.let { JSONObject(it.toJson()) } ?: JSONObject.NULL)

    @Test
    fun catalogueHashMatchesIndependentBigEndianContractVector() {
        assertEquals("041961e59832ad1a21deff89a8de482f4bc17104215395f466e10ef6c233966e",
            catalog.sha256.joinToString("") { "%02x".format(it) })
        assertEquals(initial, NativeDisplays.parse(json(initial).toString()))
        val request = checkNotNull(initial.request(77))
        val encoded = JSONObject(request.toJson())
        assertEquals(77, encoded.getInt("source"))
        assertEquals(2L, encoded.getLong("sequence"))
        assertEquals(catalog.toJson().toString(), encoded.getJSONObject("catalog").toString())
        assertNull(initial.request(42))
        assertNull(initial.request(99))
    }

    @Test
    fun pendingFenceSurvivesAckAndRejectsOldPollsAndForeignBindings() {
        val request = checkNotNull(initial.request(77))
        assertFalse(initial.observes(request))
        val switching = initial.copy(pending = request)
        assertNull(switching.confirmed)
        assertTrue(switching.observes(request))
        assertNull(switching.request(42))
        val confirmed = initial.copy(selected = selected.copy(sequence = 2, source = 77, layoutEpoch = 2, inputEpoch = 2))
        assertTrue(confirmed.observes(request))
        assertFalse(confirmed.copy(selected = confirmed.selected?.copy(source = 42)).observes(request))
        assertFalse(confirmed.copy(selected = confirmed.selected?.copy(catalog = catalog.copy(connectionGeneration = 10))).observes(request))
        assertEquals(confirmed, NativeDisplays.parse(json(confirmed).toString()))
        assertTrue(confirmed.accepts(NativeRemoteVideoLayout(9, 2, 77, 64, 48)))
        assertFalse(confirmed.accepts(NativeRemoteVideoLayout(9, 1, 42, 64, 48)))
        assertFalse(confirmed.accepts(NativeRemoteVideoLayout(9, 2, 77, 48, 64)))
    }

    @Test
    fun sameGrantResizeSuspendsDuringBeginAndCommitUntilNewSelection() {
        val rotated = displays.map { it.copy(width = 48, height = 64) }
        val nextKey = key(2, rotated)
        val pending = NativeDisplaySelectionRequest(nextKey, 2, 42)
        val begin = initial.copy(acknowledged = false, pending = pending)
        assertEquals(begin, NativeDisplays.parse(json(begin).toString()))
        assertNull(begin.confirmed)
        val commit = begin.copy(catalog = nextKey, displays = rotated, acknowledged = true)
        assertEquals(commit, NativeDisplays.parse(json(commit).toString()))
        assertNull(commit.confirmed)
        val complete = commit.copy(pending = null, selected = selected.copy(catalog = nextKey, sequence = 2, layoutEpoch = 2, inputEpoch = 0))
        assertEquals(complete, NativeDisplays.parse(json(complete).toString()))
        assertTrue(complete.accepts(NativeRemoteVideoLayout(9, 2, 42, 48, 64)))
        assertFalse(complete.accepts(NativeRemoteVideoLayout(9, 1, 42, 64, 48)))
    }

    @Test
    fun parserRejectsCorruptedHashesForeignSelectionAndUnapprovedSources() {
        fun rejects(edit: (JSONObject) -> Unit) {
            val value = json(initial)
            edit(value)
            assertNull(NativeDisplays.parse(value.toString()))
        }
        rejects { it.getJSONObject("catalog").getJSONArray("sha256").put(0, 255) }
        rejects { it.getJSONArray("approved_sources").put(1, 99) }
        rejects { it.getJSONObject("selected").getJSONObject("catalog").put("connection_generation", 8) }
        rejects { it.getJSONArray("displays").getJSONObject(0).put("width", 8193) }
        rejects { it.getJSONObject("catalog").put("revision", 1.5) }
        rejects { it.getJSONObject("catalog").put("revision", "1") }
        rejects { it.put("is_host", true) }
        rejects { it.put("local_approval_required", true) }
        assertNull(NativeDisplays.parse("{"))
        assertNull(NativeDisplays.parse(null))
    }

    @Test
    fun uint32SourceSurvivesJsonAndSignedJniBitPattern() {
        val unsigned = listOf(displays[0], displays[1].copy(source = -1))
        val key = key(1, unsigned)
        val state = initial.copy(catalog = key, displays = unsigned, selected = selected.copy(catalog = key))
        assertEquals(state, NativeDisplays.parse(json(state).toString()))
        assertEquals(0xffff_ffffL, JSONObject(checkNotNull(state.request(-1)).toJson()).getLong("source"))
        val input = NativeRemoteInputLayout(NativeInputBinding(requestId, 9, -1, 1, 1), 0, 0, 64, 48)
        assertEquals(input, NativeRemoteInputLayout.parse(input.toJson()))
    }

    @Test
    fun verifiedInputMapsEncodedCornersWithoutOverflowAndRejectsOutside() {
        val layout = VerifiedPointerLayout(1080, 1920, 0, 0, 1440, 2560)
        assertTrue(layout.matchesSource(0, 0, 0, 1080, 1920))
        assertFalse(layout.matchesSource(1, 0, 0, 1080, 1920))
        assertFalse(layout.matchesSource(0, 0, 0, 1440, 2560))
        assertFalse(layout.matchesSource(0, 1, 0, 1080, 1920))
        assertEquals(0 to 0, layout.map(0, 0))
        assertEquals(1439 to 2559, layout.map(1079, 1919))
        assertNull(layout.map(-1, 0))
        assertNull(layout.map(1080, 0))
        assertNull(layout.map(0, 1920))
        val negativeOrigin = VerifiedPointerLayout(8192, 1, -32768, -100, 32768, 1)
        assertEquals(-32768 to -100, negativeOrigin.map(0, 0))
        assertEquals(-1 to -100, negativeOrigin.map(8191, 0))
        assertThrows(IllegalArgumentException::class.java) { VerifiedPointerLayout(0, 1, 0, 0, 1, 1) }
        assertThrows(IllegalArgumentException::class.java) { VerifiedPointerLayout(1, 1, Int.MAX_VALUE, 0, 2, 1) }
    }
}
