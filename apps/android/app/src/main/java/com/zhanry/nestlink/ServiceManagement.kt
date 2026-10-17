package com.zhanry.nestlink

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

internal data class ServiceContextRow(val generation: Long, val accountId: String, val sessionId: String) {
    fun json(): JSONObject = JSONObject().put("generation", generation)
        .put("account_id", accountId).put("session_id", sessionId)
}
internal data class ServiceActionBinding(
    val handle: Long,
    val context: ServiceContextRow,
    val authRevision: Long,
)

internal fun parseServiceContext(json: String): ServiceContextRow = JSONObject(json).let { value ->
    ServiceContextRow(
        generation = value.getLong("generation"),
        accountId = value.getString("account_id").also { require(it.isNotBlank()) },
        sessionId = value.getString("session_id").also { require(it.isNotBlank()) },
    ).also { require(it.generation > 0L) }
}

/** A reply is usable only for the exact Core context observed before and after its action. */
internal fun serviceResponseIsCurrent(
    binding: ServiceActionBinding,
    responseContext: ServiceContextRow,
    liveContext: ServiceContextRow,
    currentHandle: Long,
    currentAccountId: String,
    currentUiContext: ServiceContextRow?,
    currentAuthRevision: Long,
): Boolean = binding.handle > 0L && binding.handle == currentHandle &&
    binding.context.accountId == currentAccountId &&
    binding.context == responseContext && binding.context == liveContext &&
    (currentUiContext == null || currentUiContext == binding.context) &&
    binding.authRevision == currentAuthRevision

internal data class ServiceSourceRow(val address: String, val prefix: Int)
internal data class ServiceLimitRow(
    val maximumConnections: Int,
    val bytesPerSecond: Long,
    val maximumBytes: Long,
    val idleTimeoutSeconds: Int,
)
internal data class ServiceDefinitionRow(
    val name: String,
    val hostDeviceId: String,
    val edgeNodeId: String,
    val protocol: String,
    val ingress: String,
    val allowedSources: List<ServiceSourceRow>,
    val limits: ServiceLimitRow,
) {
    fun json(): JSONObject {
        val requested = JSONObject().put("protocol", protocol)
        when (protocol) {
            "http", "https" -> requested.put("hostname", ingress)
            "tcp", "udp" -> requested.put("port", ingress.toIntOrNull() ?: error(uiText(UiTextKey.ENTER_AN_INTEGER_FOR_THE_INGRESS_504FC)))
            else -> error(uiText(UiTextKey.CHOOSE_AN_INGRESS_PROTOCOL_B2082))
        }
        return JSONObject().put("name", name).put("host_device_id", hostDeviceId)
            .put("edge_node_id", edgeNodeId).put("requested_ingress", requested)
            .put("allowed_sources", JSONArray().also { result ->
                allowedSources.forEach { result.put(JSONObject().put("address", it.address).put("prefix", it.prefix)) }
            }).put("limits", JSONObject().put("maximum_connections", limits.maximumConnections)
                .put("bytes_per_second", limits.bytesPerSecond).put("maximum_bytes", limits.maximumBytes)
                .put("idle_timeout_seconds", limits.idleTimeoutSeconds))
    }
}
internal data class ServiceRow(
    val id: String,
    val revision: Long,
    val definition: ServiceDefinitionRow,
    val approval: String,
    val publication: String,
    val targetId: String?,
    val approvalExpiresAtUnixMs: Long?,
)
internal data class ServicePageRow(val securityEpoch: Long, val rows: List<ServiceRow>, val nextId: String?, val more: Boolean)
internal data class ServiceOperationRow(val id: Long, val status: String, val remoteEffect: String, val failure: String?) {
    fun notice(): String = when {
        status == "succeeded" -> uiText(UiTextKey.THE_SERVICE_OPERATION_COMPLETED_THE_LIST_E5817)
        remoteEffect == "committed" -> uiText(UiTextKey.THE_CONFIGURATION_WAS_SAVED_BUT_THE_A35D1)
        remoteEffect == "unknown" -> uiText(UiTextKey.IT_IS_UNKNOWN_WHETHER_THE_SERVER_100FB)
        else -> uiText(UiTextKey.THE_SERVICE_OPERATION_DID_NOT_COMPLETE_ACAB4, failure?.let { "（${it}）" }.orEmpty())
    }
}
internal data class ServiceManagementRow(
    val context: ServiceContextRow,
    val snapshotRevision: Long,
    val page: ServicePageRow?,
    val selected: ServiceRow?,
    val operation: ServiceOperationRow,
    val listError: String?,
    val selectedError: String?,
)

/** Editor input only. Validation and permissions remain in the Rust Core. */
internal data class ServiceEditorDraft(
    val id: String = UUID.randomUUID().toString(),
    val revision: Long? = null,
    val name: String = "",
    val hostDeviceId: String = "",
    val edgeNodeId: String = "",
    val protocol: String = "tcp",
    val ingress: String = "29100",
    val sources: String = "",
    val maximumConnections: String = "8",
    val bytesPerSecond: String = "1048576",
    val maximumBytes: String = "1073741824",
    val idleTimeoutSeconds: String = "60",
    val savedDefinition: ServiceDefinitionRow? = null,
) {
    fun definition(): ServiceDefinitionRow = ServiceDefinitionRow(
        name = name.trim(), hostDeviceId = hostDeviceId, edgeNodeId = edgeNodeId.trim(),
        protocol = protocol, ingress = if (protocol in listOf("tcp", "udp"))
            (ingress.trim().toIntOrNull() ?: error(uiText(UiTextKey.ENTER_AN_INTEGER_FOR_THE_INGRESS_504FC))).toString() else ingress.trim(),
        allowedSources = sources.lineSequence().map(String::trim).filter(String::isNotEmpty).map { line ->
            val parts = line.split('/')
            require(parts.size == 2) { uiText(UiTextKey.ENTER_ONE_SOURCE_CIDR_PER_LINE_DCB0B) }
            ServiceSourceRow(parts[0], parts[1].toIntOrNull() ?: error(uiText(UiTextKey.ENTER_AN_INTEGER_FOR_THE_SOURCE_C1855)))
        }.toList(),
        limits = ServiceLimitRow(
            maximumConnections.toIntOrNull() ?: error(uiText(UiTextKey.ENTER_AN_INTEGER_FOR_MAXIMUM_CONNECTIONS_746FD)),
            bytesPerSecond.toLongOrNull() ?: error(uiText(UiTextKey.ENTER_AN_INTEGER_FOR_BYTES_PER_5452D)),
            maximumBytes.toLongOrNull() ?: error(uiText(UiTextKey.ENTER_AN_INTEGER_FOR_TOTAL_BYTES_C9B0E)),
            idleTimeoutSeconds.toIntOrNull() ?: error(uiText(UiTextKey.ENTER_AN_INTEGER_FOR_IDLE_TIMEOUT_97BE7)),
        ),
    )
    fun command(): JSONObject {
        val definition = definition().json()
        return if (revision == null) {
            serviceCommand("create_service", JSONObject().put("create", JSONObject().put("id", id).put("definition", definition)))
        } else {
            serviceCommand("update_service", JSONObject().put("service_id", id)
                .put("update", JSONObject().put("expected_revision", revision).put("definition", definition)))
        }
    }
    fun reconcile(state: ServiceManagementRow?): ServiceEditorDraft {
        val currentDefinition = runCatching { definition() }.getOrNull() ?: return this
        val actual = (state?.page?.rows.orEmpty() + listOfNotNull(state?.selected))
            .filter { it.id == id && it.definition == currentDefinition && it.approval != "revoked" &&
                (revision == null || it.revision >= revision) }
            .maxByOrNull { it.revision } ?: return this
        return copy(revision = actual.revision, savedDefinition = actual.definition)
    }
    fun unchanged(): Boolean = savedDefinition != null && runCatching { definition() }.getOrNull() == savedDefinition

    companion object {
        fun edit(row: ServiceRow): ServiceEditorDraft = with(row.definition) {
            ServiceEditorDraft(
                id = row.id, revision = row.revision, name = name, hostDeviceId = hostDeviceId,
                edgeNodeId = edgeNodeId, protocol = protocol, ingress = ingress,
                sources = allowedSources.joinToString("\n") { "${it.address}/${it.prefix}" },
                maximumConnections = limits.maximumConnections.toString(), bytesPerSecond = limits.bytesPerSecond.toString(),
                maximumBytes = limits.maximumBytes.toString(), idleTimeoutSeconds = limits.idleTimeoutSeconds.toString(),
                savedDefinition = this,
            )
        }
    }
}

internal fun serviceCommand(action: String, parameters: JSONObject): JSONObject =
    JSONObject().put("action", action).put("parameters", parameters)

internal fun serviceListCommand(afterId: String? = null): JSONObject = serviceCommand(
    "load_services_page", JSONObject().put("after_id", afterId ?: JSONObject.NULL).put("limit", 25),
)
internal fun serviceRequest(context: ServiceContextRow?, command: JSONObject): String =
    JSONObject().put("context", context?.json() ?: JSONObject.NULL).put("command", command).toString()

internal fun servicePublicationLabel(value: String): String = when (value) {
    "not_published" -> uiText(UiTextKey.NOT_PUBLISHED_926F4)
    "published" -> uiText(UiTextKey.PUBLISHED_D3347)
    "stopping" -> uiText(UiTextKey.SESSION_STOPPING)
    else -> uiText(UiTextKey.PUBLICATION_STATUS_NEEDS_VERIFICATION_24B00, value)
}
internal fun serviceApprovalLabel(value: String): String = when (value) {
    "pending" -> uiText(UiTextKey.WAITING_FOR_THE_LOCAL_USER_ON_9FF06)
    "approved_target" -> uiText(UiTextKey.TARGET_APPROVED_778F0)
    "invalidated" -> uiText(UiTextKey.TARGET_APPROVAL_EXPIRED_OR_INVALIDATED_46B10)
    "revoked" -> uiText(UiTextKey.REVOKED_FEF96)
    else -> uiText(UiTextKey.TARGET_APPROVAL_STATUS_NEEDS_VERIFICATION_EE71C, value)
}

private fun JSONObject.nullableText(key: String): String? = if (isNull(key)) null else getString(key)
private fun JSONObject.nullableLong(key: String): Long? = if (isNull(key)) null else getLong(key)
private fun serviceFailure(section: JSONObject, key: String = "error"): String? = section.optJSONObject(key)?.let { failure ->
    listOfNotNull(failure.optString("kind").takeIf(String::isNotBlank), failure.nullableText("code")).joinToString(" / ")
}
private fun parseServiceRow(value: JSONObject): ServiceRow {
    val definition = value.getJSONObject("definition")
    val ingress = definition.getJSONObject("requested_ingress")
    val protocol = ingress.getString("protocol")
    val limits = definition.getJSONObject("limits")
    val sources = definition.getJSONArray("allowed_sources")
    return ServiceRow(
        id = value.getString("id"), revision = value.getLong("revision"),
        definition = ServiceDefinitionRow(
            name = definition.getString("name"), hostDeviceId = definition.getString("host_device_id"),
            edgeNodeId = definition.getString("edge_node_id"), protocol = protocol,
            ingress = when (protocol) { "http", "https" -> ingress.getString("hostname"); "tcp", "udp" -> ingress.getInt("port").toString(); else -> error(uiText(UiTextKey.THE_SERVER_RETURNED_AN_UNKNOWN_INGRESS_BE86E)) },
            allowedSources = List(sources.length()) { index -> sources.getJSONObject(index).let { ServiceSourceRow(it.getString("address"), it.getInt("prefix")) } },
            limits = ServiceLimitRow(limits.getInt("maximum_connections"), limits.getLong("bytes_per_second"), limits.getLong("maximum_bytes"), limits.getInt("idle_timeout_seconds")),
        ),
        approval = value.getString("approval"), publication = value.getString("publication"),
        targetId = value.nullableText("target_id"), approvalExpiresAtUnixMs = value.nullableLong("approval_expires_at_unix_ms"),
    )
}
internal fun parseServiceManagement(json: String): ServiceManagementRow {
    val root = JSONObject(json)
    val context = root.getJSONObject("context")
    val listSection = root.getJSONObject("services")
    val selectedSection = root.getJSONObject("selected_service")
    val operation = root.getJSONObject("operation")
    val page = listSection.optJSONObject("data")?.let { data ->
        val rows = data.getJSONArray("services")
        val more = data.getBoolean("more")
        val next = data.nullableText("next_id")
        require(!more || !next.isNullOrBlank()) { uiText(UiTextKey.THE_SERVICE_PAGE_HAS_NO_NEXT_44367) }
        ServicePageRow(data.getLong("security_epoch"), List(rows.length()) { parseServiceRow(rows.getJSONObject(it)) }, next, more)
    }
    return ServiceManagementRow(
        context = ServiceContextRow(context.getLong("generation"), context.getString("account_id"), context.getString("session_id")),
        snapshotRevision = root.getLong("snapshot_revision"), page = page,
        selected = selectedSection.optJSONObject("data")?.let(::parseServiceRow),
        operation = ServiceOperationRow(operation.getLong("id"), operation.getString("status"), operation.getString("remote_effect"), serviceFailure(operation, "failure")),
        listError = serviceFailure(listSection), selectedError = serviceFailure(selectedSection),
    )
}
