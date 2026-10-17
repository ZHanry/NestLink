package com.zhanry.nestlink

import org.json.JSONArray
import org.json.JSONObject

internal data class RemotePasswordViewRow(
    val revision: Long,
    val permissions: List<Int>,
    val paths: List<Int>,
    val expiresAtUnixMs: Long,
    val active: Boolean,
)

internal data class RemotePasswordOfferRow(
    val requestId: String,
    val settings: RemotePasswordViewRow,
)

internal fun parseRemotePasswordView(json: String): RemotePasswordViewRow = JSONObject(json).let { value ->
    RemotePasswordViewRow(
        revision = value.getLong("revision").also { require(it >= 0L) },
        permissions = value.getJSONArray("permissions").toIntList(),
        paths = value.getJSONArray("paths").toIntList(),
        expiresAtUnixMs = value.getLong("expires_at_unix_ms").also { require(it >= 0L) },
        active = value.getBoolean("active"),
    ).also { scope ->
        require(scope.permissions.distinct().size == scope.permissions.size)
        require(scope.paths.distinct().size == scope.paths.size)
        require(scope.permissions.all { it in 1..7 })
        require(scope.paths.all { it == 1 || it == 2 })
        require(!scope.active || (1 in scope.permissions && scope.paths.isNotEmpty() && scope.expiresAtUnixMs > 0L))
    }
}

internal fun parseRemotePasswordOffer(requestId: String, json: String): RemotePasswordOfferRow =
    RemotePasswordOfferRow(requestId, parseRemotePasswordView(json))

internal fun remotePasswordBytes(value: String): Int {
    val encoded = value.toByteArray(Charsets.UTF_8)
    return try {
        encoded.size
    } finally {
        encoded.fill(0)
    }
}

internal fun remotePasswordLengthIsValid(value: String): Boolean = remotePasswordBytes(value) in 12..1_024

internal fun remotePasswordExpiry(nowUnixMs: Long, days: Int): Long? {
    if (nowUnixMs < 0L || days !in listOf(1, 7, 30)) return null
    return runCatching { Math.addExact(nowUnixMs, Math.multiplyExact(days.toLong(), 86_400_000L)) }.getOrNull()
}

internal fun remotePasswordSettingsJson(
    expectedRevision: Long,
    permissions: List<Int>,
    paths: List<Int>,
    expiresAtUnixMs: Long,
): String {
    require(expectedRevision >= 0L)
    require(permissions.distinct().size == permissions.size && 1 in permissions && permissions.all { it in 1..7 })
    require(paths.isNotEmpty() && paths.distinct().size == paths.size && paths.all { it == 1 || it == 2 })
    require(expiresAtUnixMs > 0L)
    return JSONObject()
        .put("expected_revision", expectedRevision)
        .put("permissions", JSONArray(permissions))
        .put("paths", JSONArray(paths))
        .put("expires_at_unix_ms", expiresAtUnixMs)
        .toString()
}

private fun JSONArray.toIntList(): List<Int> = List(length()) { index -> getInt(index) }
