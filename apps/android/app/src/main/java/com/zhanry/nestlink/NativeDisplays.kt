package com.zhanry.nestlink

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

internal data class NativeDisplayCatalog(
    val requestId: String,
    val connectionGeneration: Long,
    val revision: Long,
    val sha256: List<Int>,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("request_id", requestId)
        .put("connection_generation", connectionGeneration)
        .put("revision", revision)
        .put("sha256", JSONArray(sha256))
}

internal data class NativeDisplayDescriptor(
    val source: Int,
    val left: Int,
    val top: Int,
    val width: Int,
    val height: Int,
    val label: String,
)

internal data class NativeDisplaySelectionRequest(
    val catalog: NativeDisplayCatalog,
    val sequence: Long,
    val source: Int,
) {
    fun toJson(): String = JSONObject()
        .put("catalog", catalog.toJson())
        .put("sequence", sequence)
        .put("source", source.toLong() and 0xffff_ffffL)
        .toString()
}

internal data class NativeDisplaySelection(
    val catalog: NativeDisplayCatalog,
    val sequence: Long,
    val source: Int,
    val layoutEpoch: Long,
    val inputEpoch: Long,
)

internal data class NativeDisplays(
    val catalog: NativeDisplayCatalog?,
    val displays: List<NativeDisplayDescriptor>,
    val acknowledged: Boolean,
    val selected: NativeDisplaySelection?,
    val pending: NativeDisplaySelectionRequest?,
) {
    val confirmed: NativeDisplaySelection?
        get() = selected?.takeIf { acknowledged && pending == null && it.catalog == catalog }

    fun matchesSession(requestId: String, generation: Long): Boolean =
        catalog?.let { it.requestId == requestId && it.connectionGeneration == generation } ?: true

    /** Retained after ACK too: an older in-flight poll must never remove this fence. */
    fun observes(request: NativeDisplaySelectionRequest): Boolean {
        if (pending == request) return true
        val current = selected ?: return false
        if (current.catalog.requestId != request.catalog.requestId ||
            current.catalog.connectionGeneration != request.catalog.connectionGeneration
        ) return false
        if (current.sequence == request.sequence) {
            return current.catalog == request.catalog && current.source == request.source
        }
        return current.sequence > request.sequence && current.catalog.revision >= request.catalog.revision
    }

    fun accepts(layout: NativeRemoteVideoLayout): Boolean = confirmed?.let { selection ->
        selection.catalog.connectionGeneration == layout.connectionGeneration &&
            selection.source == layout.source && selection.layoutEpoch == layout.layoutEpoch &&
            displays.any { it.source == layout.source && it.width == layout.width && it.height == layout.height }
    } == true

    fun request(source: Int): NativeDisplaySelectionRequest? {
        val selection = confirmed ?: return null
        if (selection.sequence == Long.MAX_VALUE || selection.source == source || displays.none { it.source == source }) return null
        return NativeDisplaySelectionRequest(selection.catalog, selection.sequence + 1, source)
    }

    companion object {
        fun parse(json: String?): NativeDisplays? {
            if (json.isNullOrBlank() || json.length > 32_768) return null
            return runCatching {
                val item = JSONObject(json)
                require(!item.getBoolean("is_host") && !item.getBoolean("local_approval_required"))
                val catalog = item.objectOrNull("catalog")?.let(::parseCatalog)
                val entries = item.getJSONArray("displays")
                require(entries.length() <= 64)
                val displays = (0 until entries.length()).map { index ->
                    val entry = entries.getJSONObject(index)
                    NativeDisplayDescriptor(
                        entry.uint32("source"), entry.strictInt("left"), entry.strictInt("top"),
                        entry.strictInt("width"), entry.strictInt("height"), entry.getString("label"),
                    ).also {
                        require(it.width in 1..8192 && it.height in 1..8192)
                        require(it.width.toLong() * it.height * 4 <= 64L * 1024 * 1024)
                        require(it.left.toLong() + it.width <= Int.MAX_VALUE && it.top.toLong() + it.height <= Int.MAX_VALUE)
                        require(it.label.isNotEmpty() && it.label.toByteArray(Charsets.UTF_8).size <= 80 && it.label.none(Char::isISOControl))
                    }
                }
                require(displays.sumOf { it.width.toLong() * it.height * 4 } <= 128L * 1024 * 1024)
                require(displays.zipWithNext().all { (a, b) -> Integer.compareUnsigned(a.source, b.source) < 0 })
                val approved = item.getJSONArray("approved_sources")
                require(approved.length() == displays.size)
                require(displays.indices.all { approved.uint32(it) == displays[it].source })
                if (catalog != null) {
                    require(displays.isNotEmpty() && catalog.sha256 == catalogHash(catalog, displays))
                } else require(displays.isEmpty())
                val acknowledged = item.getBoolean("catalog_acknowledged")
                val selected = item.objectOrNull("selected")?.let { selection ->
                    NativeDisplaySelection(
                        parseCatalog(selection.getJSONObject("catalog")), selection.positiveLong("sequence"),
                        selection.uint32("source"), selection.positiveLong("layout_epoch"),
                        selection.strictLong("input_epoch").also { require(it >= 0) },
                    )
                }
                val pending = item.objectOrNull("pending")?.let { request ->
                    NativeDisplaySelectionRequest(
                        parseCatalog(request.getJSONObject("catalog")), request.positiveLong("sequence"), request.uint32("source"),
                    )
                }
                if (catalog == null) require(!acknowledged && selected == null && pending == null)
                if (selected != null) {
                    val currentCatalog = checkNotNull(catalog)
                    require(displays.any { it.source == selected.source })
                    require(selected.catalog.requestId == currentCatalog.requestId && selected.catalog.connectionGeneration == currentCatalog.connectionGeneration)
                    require(selected.catalog == currentCatalog || pending != null && selected.catalog.revision + 1 == currentCatalog.revision)
                }
                if (pending != null) {
                    val currentCatalog = checkNotNull(catalog)
                    require(displays.any { it.source == pending.source })
                    require(pending.catalog.requestId == currentCatalog.requestId && pending.catalog.connectionGeneration == currentCatalog.connectionGeneration)
                    require(pending.catalog == currentCatalog || !acknowledged && currentCatalog.revision < Long.MAX_VALUE && pending.catalog.revision == currentCatalog.revision + 1)
                    require(pending.sequence == (selected?.sequence?.let { Math.addExact(it, 1) } ?: 1L))
                }
                if (acknowledged) require(catalog != null)
                NativeDisplays(catalog, displays, acknowledged, selected, pending)
            }.getOrNull()
        }

        private fun parseCatalog(item: JSONObject): NativeDisplayCatalog {
            val requestId = item.getString("request_id")
            val id = UUID.fromString(requestId)
            require(id.toString() == requestId && (id.mostSignificantBits != 0L || id.leastSignificantBits != 0L))
            val hash = item.getJSONArray("sha256")
            require(hash.length() == 32)
            val bytes = (0 until 32).map { hash.strictLong(it).also { value -> require(value in 0..255) }.toInt() }
            require(bytes.any { it != 0 })
            return NativeDisplayCatalog(requestId, item.positiveLong("connection_generation"), item.positiveLong("revision"), bytes)
        }

        /** Byte-for-byte match of protocol-spec/native-displays.rs canonical hashing. */
        internal fun catalogHash(catalog: NativeDisplayCatalog, displays: List<NativeDisplayDescriptor>): List<Int> {
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use { output ->
                output.write("NestLink/native-displays/v1\u0000".toByteArray(Charsets.UTF_8))
                val id = UUID.fromString(catalog.requestId)
                output.writeLong(id.mostSignificantBits)
                output.writeLong(id.leastSignificantBits)
                output.writeLong(catalog.connectionGeneration)
                output.writeLong(catalog.revision)
                output.writeByte(displays.size)
                for (display in displays) {
                    output.writeInt(display.source)
                    output.writeInt(display.left)
                    output.writeInt(display.top)
                    output.writeInt(display.width)
                    output.writeInt(display.height)
                    val label = display.label.toByteArray(Charsets.UTF_8)
                    output.writeByte(label.size)
                    output.write(label)
                }
            }
            return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()).map { it.toInt() and 255 }
        }
    }
}

private fun JSONObject.objectOrNull(key: String): JSONObject? = if (isNull(key)) null else getJSONObject(key)
private fun JSONObject.strictLong(key: String): Long = get(key).let {
    require(it is Int || it is Long)
    (it as Number).toLong()
}
private fun JSONArray.strictLong(index: Int): Long = get(index).let {
    require(it is Int || it is Long)
    (it as Number).toLong()
}
private fun JSONObject.positiveLong(key: String): Long = strictLong(key).also { require(it > 0) }
private fun JSONObject.strictInt(key: String): Int = strictLong(key).also { require(it in Int.MIN_VALUE..Int.MAX_VALUE) }.toInt()
private fun JSONObject.uint32(key: String): Int = strictLong(key).also { require(it in 0..0xffff_ffffL) }.toInt()
private fun JSONArray.uint32(index: Int): Int = strictLong(index).also { require(it in 0..0xffff_ffffL) }.toInt()

/** The host grants encoded coordinates; only this verified mapping reaches Accessibility. */
internal data class VerifiedPointerLayout(
    val encodedWidth: Int,
    val encodedHeight: Int,
    val left: Int,
    val top: Int,
    val physicalWidth: Int,
    val physicalHeight: Int,
) {
    init {
        require(encodedWidth in 1..8192 && encodedHeight in 1..8192)
        require(physicalWidth in 1..32768 && physicalHeight in 1..32768)
        require(left.toLong() + physicalWidth <= Int.MAX_VALUE && top.toLong() + physicalHeight <= Int.MAX_VALUE)
    }

    fun matchesSource(source: Int, sourceLeft: Int, sourceTop: Int, width: Int, height: Int): Boolean =
        source == 0 && sourceLeft == 0 && sourceTop == 0 && width == encodedWidth && height == encodedHeight

    fun map(x: Int, y: Int): Pair<Int, Int>? {
        if (x !in 0 until encodedWidth || y !in 0 until encodedHeight) return null
        val mappedX = left.toLong() + x.toLong() * (physicalWidth - 1) / (encodedWidth - 1).coerceAtLeast(1)
        val mappedY = top.toLong() + y.toLong() * (physicalHeight - 1) / (encodedHeight - 1).coerceAtLeast(1)
        return mappedX.toInt() to mappedY.toInt()
    }
}
