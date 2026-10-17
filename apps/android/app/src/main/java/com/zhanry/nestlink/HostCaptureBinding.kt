package com.zhanry.nestlink

import org.json.JSONObject

/**
 * A single MediaProjection grant is pinned to exactly one local endpoint kind.
 * Similar request/generation pairs cannot authorize the other endpoint.
 */
internal sealed interface HostCaptureBinding {
    val requestId: String
    val connectionGeneration: Long
    val bindingJson: String

    data class NativeSession(
        override val requestId: String,
        override val connectionGeneration: Long,
        override val bindingJson: String,
    ) : HostCaptureBinding

    data class BrowserHost(
        override val requestId: String,
        override val connectionGeneration: Long,
        override val bindingJson: String,
    ) : HostCaptureBinding

    companion object {
        fun nativeSession(bindingJson: String): HostCaptureBinding.NativeSession =
            parse(bindingJson).let { (request, generation) ->
                HostCaptureBinding.NativeSession(request, generation, bindingJson)
            }

        fun browserHost(bindingJson: String): HostCaptureBinding.BrowserHost =
            parse(bindingJson, requireBrowserFields = true).let { (request, generation) ->
                HostCaptureBinding.BrowserHost(request, generation, bindingJson)
            }

        private fun parse(bindingJson: String, requireBrowserFields: Boolean = false): Pair<String, Long> {
            require(bindingJson.isNotBlank() && bindingJson.length <= 8192)
            val value = JSONObject(bindingJson)
            val requestId = value.get("request_id") as? String
                ?: throw IllegalArgumentException("request_id must be a string")
            val generation = value.get("connection_generation").integralLongOrNull()
                ?: throw IllegalArgumentException("connection_generation must be an integer")
            require(requestId.isNotBlank() && generation > 0)
            if (requireBrowserFields) {
                val required = setOf(
                    "request_id", "session_id", "controller_device_id", "host_device_id",
                    "controller_key_sha256", "host_key_sha256", "permit_sha256",
                    "connection_generation",
                )
                val keys = value.keys().asSequence().toSet()
                require(keys == required) { "expected the complete BrowserHost binding" }
                for (key in listOf("session_id", "controller_device_id", "host_device_id")) {
                    require(value.get(key) is String && (value.get(key) as String).isNotBlank()) {
                        "${key} must be a non-empty string"
                    }
                }
                for (key in listOf("controller_key_sha256", "host_key_sha256", "permit_sha256")) {
                    val digest = value.getJSONArray(key)
                    require(digest.length() == 32 && (0 until digest.length()).all { index ->
                        digest.get(index).integralLongOrNull()?.let { it in 0L..255L } == true
                    }) { "invalid BrowserHost binding digest" }
                }
            }
            return requestId to generation
        }

        private fun Any?.integralLongOrNull(): Long? = when (this) {
            is Byte -> toLong()
            is Short -> toLong()
            is Int -> toLong()
            is Long -> this
            else -> null
        }
    }
}

/** Compares both the tagged owner class and every byte of its stable binding. */
internal fun HostCaptureBinding.sameOwner(other: HostCaptureBinding): Boolean =
    this::class == other::class && requestId == other.requestId &&
        connectionGeneration == other.connectionGeneration && bindingJson == other.bindingJson
