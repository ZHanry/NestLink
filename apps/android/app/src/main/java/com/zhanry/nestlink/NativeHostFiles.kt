package com.zhanry.nestlink

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONObject

internal data class NativeHostArtifactRow(
    val id: String, val kind: String, val displayName: String, val phase: String, val size: Long?,
    val ownerStopped: Boolean, val cleanupPending: Boolean, val published: Boolean, val verified: Boolean,
    val error: String?, val cleanupError: String?,
)
internal data class NativeHostFilesRow(
    val receiveApproved: Boolean = false,
    val reservedBytes: Long = 0,
    val artifacts: List<NativeHostArtifactRow> = emptyList(),
    val exports: Map<String, NativeSafExportRow> = emptyMap(),
)

internal fun NativeHostArtifactRow.canExport(): Boolean =
    kind == "receive" && published && verified && ownerStopped && !cleanupPending

internal fun parseNativeHostFiles(json: String, identity: NativeFileSessionIdentity): NativeHostFilesRow {
    require(identity.isHost) { uiText(UiTextKey.A_CONTROLLER_SESSION_CANNOT_APPROVE_LOCAL_A9869) }
    val payload = JSONObject(json)
    val actual = payload.getJSONObject("identity")
    val binding = actual.getJSONObject("binding")
    require(binding.getString("request_id") == identity.requestId && binding.getLong("connection_generation") == identity.connectionGeneration && actual.getLong("core_generation") == identity.coreGeneration) { uiText(UiTextKey.THE_LOCAL_FILE_STATUS_BELONGS_TO_F2E3B) }
    return parseLocalHostFilesPayload(payload)
}

internal fun parseLocalHostFilesPayload(payload: JSONObject): NativeHostFilesRow {
    val items = payload.getJSONArray("artifacts")
    require(items.length() <= 8) { uiText(UiTextKey.LOCAL_FILE_STATUS_EXCEEDS_CAPACITY_E8B2C) }
    val artifacts = List(items.length()) { index ->
        val item = items.getJSONObject(index)
        NativeHostArtifactRow(
            id = item.getString("id"), kind = item.getString("kind"), displayName = item.getString("display_name"),
            phase = item.getString("phase"), size = if (item.isNull("size")) null else item.getLong("size"),
            ownerStopped = item.optBoolean("owner_stopped", false), cleanupPending = item.optBoolean("cleanup_pending", true),
            published = item.optBoolean("published", false), verified = item.optBoolean("verified", false),
            error = if (item.isNull("error")) null else item.getString("error"),
            cleanupError = if (item.isNull("cleanup_error")) null else item.getString("cleanup_error"),
        )
    }
    val exports = payload.getJSONArray("exports")
    require(exports.length() <= 32) { uiText(UiTextKey.LOCAL_EXPORT_STATUS_EXCEEDS_CAPACITY_0BDD4) }
    val parsedExports = buildMap {
        repeat(exports.length()) { index ->
            val entry = exports.getJSONObject(index)
            val artifactId = entry.getString("artifact_id")
            put(artifactId, parseNativeSafExport(entry.getJSONObject("status").toString(), artifactId))
        }
    }
    val reservedBytes = payload.getLong("reserved_bytes")
    require(reservedBytes in 0..4L * 1024 * 1024 * 1024) { uiText(UiTextKey.THE_LOCAL_FILE_CAPACITY_RESERVATION_IS_A1A56) }
    return NativeHostFilesRow(payload.optBoolean("receive_approved", false), reservedBytes, artifacts, parsedExports)
}

@Composable
internal fun ColumnScope.HostFilesScreen(
    state: MobileState, model: NestLinkViewModel, onPickShare: () -> Unit, onPickExport: (String) -> Unit,
) {
    val session = state.fileSession ?: return
    val host = state.hostFiles
    var confirmShare by remember(session.identityJson) { mutableStateOf(false) }
    var confirmReceive by remember(session.identityJson) { mutableStateOf(false) }
    Text(uiText(UiTextKey.LOCAL_SHARING_AND_RECEIVING_1B4B5), style = MaterialTheme.typography.headlineSmall)
    Text(uiText(UiTextKey.CONSENT_IS_LIMITED_TO_THIS_SESSION_2E904), style = MaterialTheme.typography.bodySmall)
    Text(uiText(UiTextKey.FILES_8_FILES_RESERVED_4_GIB_RESERVED_568EE, host.artifacts.size, formatFileBytes(host.reservedBytes)), style = MaterialTheme.typography.bodySmall)
    if (session.canRead) OutlinedButton(onClick = { confirmShare = true }, enabled = !state.fileBusy && !state.filePickerPending && state.canStartAnotherFileTask(), modifier = Modifier.fillMaxWidth()) { Text(uiText(UiTextKey.CHOOSE_AND_SHARE_LOCAL_FILES_6D4B8)) }
    if (session.canWrite) {
        OutlinedButton(
            onClick = { if (host.receiveApproved) model.approveNativeHostReceive(false) else confirmReceive = true },
            enabled = (!state.fileBusy || host.receiveApproved) && !state.filePickerPending, modifier = Modifier.fillMaxWidth(),
        ) { Text(if (host.receiveApproved) uiText(UiTextKey.STOP_RECEIVING_NEW_FILES_B6905) else uiText(UiTextKey.APPROVE_A_NEW_PRIVATE_RECEIVING_AREA_23EFF)) }
    }
    if (!session.canRead) Text(uiText(UiTextKey.THE_CURRENT_SESSION_IS_NOT_AUTHORIZED_261CC), style = MaterialTheme.typography.bodySmall)
    if (!session.canWrite) Text(uiText(UiTextKey.THE_CURRENT_SESSION_IS_NOT_AUTHORIZED_0C6CA), style = MaterialTheme.typography.bodySmall)
    Text(uiText(UiTextKey.ONLY_SNAPSHOTS_AND_NAMES_OF_SELECTED_09E8D), style = MaterialTheme.typography.bodySmall)
    LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(host.artifacts, key = { it.id }) { artifact ->
            Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text(artifact.displayName, style = MaterialTheme.typography.titleSmall)
                    Text("${if (artifact.kind == "receive") uiText(UiTextKey.RECEIVED_FILE_2B9C2) else uiText(UiTextKey.SHARED_SNAPSHOT_63B63)} · ${hostFilePhaseLabel(artifact.phase)}${artifact.size?.let { " · ${formatFileBytes(it)}" }.orEmpty()}", style = MaterialTheme.typography.bodySmall)
                    if (!artifact.ownerStopped) Text(uiText(UiTextKey.FILE_READS_OR_WRITES_ARE_STILL_DAC0F), style = MaterialTheme.typography.bodySmall)
                    if (artifact.cleanupPending) Text(uiText(UiTextKey.PRIVATE_CLEANUP_IS_INCOMPLETE_AND_ITS_33CED), style = MaterialTheme.typography.bodySmall)
                    artifact.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    artifact.cleanupError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    val export = host.exports[artifact.id]
                    export?.let {
                        Text(uiText(UiTextKey.EXPORT_4D606, hostFilePhaseLabel(it.phase), formatFileBytes(it.copiedBytes), formatFileBytes(it.totalBytes)), style = MaterialTheme.typography.bodySmall)
                        it.error?.let { error -> Text(error, color = MaterialTheme.colorScheme.error) }
                        it.destinationCleanupError?.let { error -> Text(error, color = MaterialTheme.colorScheme.error) }
                        if (it.ownerRetained()) TextButton(onClick = { model.cancelNativeHostExport(it.exportId) }, enabled = !state.localClosePending) { Text(uiText(UiTextKey.CANCEL_EXPORT_AND_WAIT_FOR_CLEANUP_0C66A)) }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (artifact.canExport()) {
                            Button(onClick = { onPickExport(artifact.id) }, enabled = !state.fileBusy && !state.filePickerPending && export?.ownerRetained() != true) { Text(uiText(UiTextKey.SAVE_WITH_SYSTEM_DIALOG_5B981)) }
                        }
                        TextButton(onClick = { model.discardNativeHostFile(artifact.id) }, enabled = !state.localClosePending && !state.filePickerPending) { Text(if (artifact.kind == "share") uiText(UiTextKey.REVOKE_SHARING_AND_CLEAN_UP_84C27) else uiText(UiTextKey.DELETE_PRIVATE_RECEIVED_FILE_A1568)) }
                    }
                }
            }
        }
    }
    if (state.fileBusy) Text(uiText(UiTextKey.PROCESSING_LOCAL_FILES_02F96), style = MaterialTheme.typography.bodySmall)
    if (state.fileError.isNotBlank()) Text(state.fileError, color = MaterialTheme.colorScheme.error)
    if (confirmShare) AlertDialog(
        onDismissRequest = { confirmShare = false }, title = { Text(uiText(UiTextKey.SHARE_THE_SELECTED_FILES_AND_THEIR_07D81)) },
        text = { Text(uiText(UiTextKey.THE_FILES_YOU_CHOOSE_NEXT_BECOME_9B8D6)) },
        confirmButton = { TextButton(onClick = { confirmShare = false; onPickShare() }) { Text(uiText(UiTextKey.CHOOSE_AND_SHARE_016B5)) } }, dismissButton = { TextButton(onClick = { confirmShare = false }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
    )
    if (confirmReceive) AlertDialog(
        onDismissRequest = { confirmReceive = false }, title = { Text(uiText(UiTextKey.APPROVE_A_NEW_PRIVATE_RECEIVING_AREA_EFE4E)) },
        text = { Text(uiText(UiTextKey.ONLY_THE_CURRENT_SESSION_CAN_RECEIVE_4A9CF)) },
        confirmButton = { TextButton(onClick = { confirmReceive = false; model.approveNativeHostReceive(true) }) { Text(uiText(UiTextKey.APPROVE_RECEIVING_FOR_THIS_SESSION_D0443)) } }, dismissButton = { TextButton(onClick = { confirmReceive = false }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
    )
}

internal fun hostFilePhaseLabel(phase: String): String = when (phase) {
    "preparing", "prepared" -> uiText(UiTextKey.PREPARING_SNAPSHOT_09E7B)
    "shared" -> uiText(UiTextKey.SNAPSHOT_SHARED_9339A)
    "receiving" -> uiText(UiTextKey.RECEIVING_5F8B6)
    "received" -> uiText(UiTextKey.RECEIVED_ACTUAL_PUBLICATION_STATUS_RETAINED_F24B2)
    "running" -> uiText(UiTextKey.EXPORTING_9AAF6)
    "completed" -> uiText(UiTextKey.COMPLETED_F2846)
    "cancelled" -> uiText(UiTextKey.CANCELLED_A3777)
    "failed" -> uiText(UiTextKey.INCOMPLETE_6707D)
    else -> phase
}
