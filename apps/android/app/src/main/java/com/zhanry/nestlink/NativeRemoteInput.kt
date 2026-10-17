package com.zhanry.nestlink

import org.json.JSONObject
import kotlin.math.floor

/** The exact connection and source generation that owns an input layout. */
internal data class NativeInputBinding(
    val requestId: String,
    val connectionGeneration: Long,
    val source: Int,
    val inputEpoch: Long,
    val layoutEpoch: Long,
) {
    fun toJson(): String = JSONObject()
        .put("request_id", requestId)
        .put("connection_generation", connectionGeneration)
        .put("source", source.toLong() and 0xffff_ffffL)
        .put("input_epoch", inputEpoch)
        .put("layout_epoch", layoutEpoch)
        .toString()

    fun matches(session: NativeSessionRow, video: NativeRemoteVideoLayout): Boolean =
        requestId == session.requestId && connectionGeneration == session.connectionGeneration &&
            connectionGeneration == video.connectionGeneration && source == video.source &&
            layoutEpoch == video.layoutEpoch

    fun matchesVideoLayout(video: NativeRemoteVideoLayout): Boolean =
        connectionGeneration == video.connectionGeneration && source == video.source &&
            layoutEpoch == video.layoutEpoch
}

internal data class NativeRemoteInputLayout(
    val binding: NativeInputBinding,
    val left: Int,
    val top: Int,
    val width: Int,
    val height: Int,
) {
    fun toJson(): String = JSONObject()
        .put("binding", JSONObject(binding.toJson()))
        .put("left", left)
        .put("top", top)
        .put("width", width)
        .put("height", height)
        .toString()

    companion object {
        fun parse(json: String?): NativeRemoteInputLayout? {
            if (json.isNullOrBlank() || json.trim() == "null") return null
            return runCatching {
                val item = JSONObject(json)
                val bindingJson = item.getJSONObject("binding")
                val binding = NativeInputBinding(
                    requestId = bindingJson.getString("request_id"),
                    connectionGeneration = bindingJson.getLong("connection_generation"),
                    source = bindingJson.getLong("source").also { require(it in 0..0xffff_ffffL) }.toInt(),
                    inputEpoch = bindingJson.getLong("input_epoch"),
                    layoutEpoch = bindingJson.getLong("layout_epoch"),
                )
                NativeRemoteInputLayout(
                    binding = binding,
                    left = item.getInt("left"),
                    top = item.getInt("top"),
                    width = item.getInt("width"),
                    height = item.getInt("height"),
                )
            }.getOrNull()?.takeIf { it.isValid() }
        }
    }

    fun isValid(): Boolean = binding.requestId.isNotBlank() &&
        binding.connectionGeneration > 0 &&
        binding.inputEpoch > 0 && binding.layoutEpoch > 0 &&
        width in 1..32768 && height in 1..32768 &&
        left.toLong() + width <= Int.MAX_VALUE && top.toLong() + height <= Int.MAX_VALUE
}

/** Matches the serde-tagged Rust `NativeInputAction` representation. */
internal sealed interface NativeInputAction {
    fun toJson(): String

    data class Key(val code: Int, val down: Boolean) : NativeInputAction {
        override fun toJson(): String = JSONObject()
            .put("kind", "key")
            .put("value", JSONObject().put("code", code).put("down", down))
            .toString()
    }

    data class Pointer(
        val button: Int?,
        val down: Boolean,
        val x: Int,
        val y: Int,
    ) : NativeInputAction {
        override fun toJson(): String = JSONObject()
            .put("kind", "pointer")
            .put("value", JSONObject()
                .put("button", button ?: JSONObject.NULL)
                .put("down", down)
                .put("x", x)
                .put("y", y))
            .toString()
    }

    data class Text(val text: String) : NativeInputAction {
        override fun toJson(): String = JSONObject()
            .put("kind", "text")
            .put("value", text)
            .toString()
    }
}

/** Maps the fitted video content into the host's actual logical input rectangle. */
internal fun mapVideoPointToInput(
    localX: Float,
    localY: Float,
    videoWidth: Float,
    videoHeight: Float,
    inputLayout: NativeRemoteInputLayout,
): Pair<Int, Int>? {
    if (!inputLayout.isValid() || !localX.isFinite() || !localY.isFinite() ||
        !videoWidth.isFinite() || !videoHeight.isFinite() || videoWidth <= 0f || videoHeight <= 0f ||
        localX < 0f || localY < 0f || localX >= videoWidth || localY >= videoHeight
    ) return null

    val x = inputLayout.left + floor(localX / videoWidth * inputLayout.width)
        .toInt().coerceIn(0, inputLayout.width - 1)
    val y = inputLayout.top + floor(localY / videoHeight * inputLayout.height)
        .toInt().coerceIn(0, inputLayout.height - 1)
    return x to y
}
