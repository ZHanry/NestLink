package com.zhanry.nestlink

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.time.Instant

@Composable
internal fun ColumnScope.ServicesScreen(state: MobileState, model: NestLinkViewModel) {
    var editor by remember(state.handle, state.accountId) { mutableStateOf<ServiceEditorDraft?>(null) }
    var editorContext by remember(state.handle, state.accountId) { mutableStateOf<ServiceContextRow?>(null) }
    var revoke by remember(state.handle, state.accountId) { mutableStateOf<ServiceRow?>(null) }
    val services = state.services
    val page = services?.page
    LaunchedEffect(services) { editor = editor?.reconcile(services) }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(uiText(UiTextKey.SERVICE_PUBLISHING_6E26D), style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
        TextButton(onClick = { model.refreshServices() }, enabled = !state.busy) { Text(uiText(UiTextKey.REFRESH_AEE88)) }
    }
    Text(uiText(UiTextKey.MANAGE_SERVICES_ON_OTHER_DEVICES_AFTER_046A8), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(8.dp))
    OutlinedButton(onClick = {
        editor = ServiceEditorDraft()
        editorContext = services?.context
    }, enabled = !state.busy && services != null && editor == null, modifier = Modifier.fillMaxWidth()) { Text(uiText(UiTextKey.NEW_SERVICE_84F2E)) }
    if (state.busy) CircularProgressIndicator(modifier = Modifier.padding(8.dp))
    LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (services == null) item {
            Text(uiText(UiTextKey.THE_SERVICE_LIST_HAS_NOT_BEEN_932AD), modifier = Modifier.padding(vertical = 12.dp))
        }
        services?.listError?.let { error -> item {
            Text(uiText(UiTextKey.THE_LIST_COULD_NOT_BE_LOADED_DE677, error), color = MaterialTheme.colorScheme.error)
        } }
        if (page != null && page.rows.isEmpty()) item {
            Text(uiText(UiTextKey.THERE_ARE_NO_SERVICES_ON_THIS_4E392), modifier = Modifier.padding(vertical = 12.dp))
        }
        items(page?.rows.orEmpty(), key = { it.id }) { row ->
            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(row.definition.name, style = MaterialTheme.typography.titleMedium)
                Text("${row.definition.protocol.uppercase()}  ${row.definition.ingress}")
                Text(servicePublicationLabel(row.publication), color = MaterialTheme.colorScheme.primary)
                Text(serviceApprovalLabel(row.approval), style = MaterialTheme.typography.bodySmall)
                Text(uiText(UiTextKey.HOST_04166, row.definition.hostDeviceId), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(uiText(UiTextKey.EDGE_CONFIGURATION_REVISION_AF163, row.definition.edgeNodeId, row.revision), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { model.inspectService(row.id) }, enabled = !state.busy) { Text(uiText(UiTextKey.INSPECT_STATUS_90B0A)) }
                    TextButton(onClick = {
                        editor = ServiceEditorDraft.edit(row)
                        editorContext = services?.context
                    }, enabled = !state.busy && row.approval != "revoked" && editor == null) { Text(uiText(UiTextKey.EDIT_05183)) }
                    TextButton(onClick = { revoke = row }, enabled = !state.busy && row.approval != "revoked") { Text(uiText(UiTextKey.REVOKE_926A5)) }
                }
                HorizontalDivider()
            }
        }
        page?.let { loaded -> item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { model.refreshServices() }, enabled = !state.busy) { Text(uiText(UiTextKey.FIRST_PAGE_E59AE)) }
                OutlinedButton(onClick = { loaded.nextId?.let(model::refreshServices) }, enabled = !state.busy && loaded.more && loaded.nextId != null) { Text(uiText(UiTextKey.NEXT_PAGE_8A854)) }
            }
        } }
        services?.selected?.let { selected -> item {
            Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.small) {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(uiText(UiTextKey.LAST_VERIFIED_87E33, selected.definition.name), style = MaterialTheme.typography.titleSmall)
                    Text(servicePublicationLabel(selected.publication))
                    Text(serviceApprovalLabel(selected.approval))
                    selected.targetId?.let { Text(uiText(UiTextKey.APPROVED_TARGET_ID_A0B5B, it), style = MaterialTheme.typography.bodySmall) }
                    selected.approvalExpiresAtUnixMs?.let { expiry ->
                        Text(uiText(UiTextKey.APPROVAL_EXPIRES_61F1C, Instant.ofEpochMilli(expiry)), style = MaterialTheme.typography.bodySmall)
                    }
                    services.selectedError?.let { Text(uiText(UiTextKey.A_LATER_OPERATION_DID_NOT_COMPLETE_6340A, it), color = MaterialTheme.colorScheme.error) }
                }
            }
        } }
        editor?.let { draft -> item {
            ServiceEditor(
                draft = draft,
                onChange = { editor = it },
                devices = state.devices.filter { !it.revoked && it.id != state.ownDeviceId &&
                    !it.platform.equals("android", ignoreCase = true) && "host" in it.capabilities },
                busy = state.busy,
                sameContext = editorContext != null && editorContext == services?.context,
                onSave = { model.saveService(draft) },
                onClose = { editor = null; editorContext = null },
            )
        } }
    }
    revoke?.let { row ->
        AlertDialog(
            onDismissRequest = { if (!state.busy) revoke = null },
            title = { Text(uiText(UiTextKey.REVOKE_SERVICE_D211A)) },
            text = { Text(uiText(UiTextKey.REVOKE_REVISION_OF_THE_SERVER_CHECKS_FB567, row.definition.name, row.revision)) },
            confirmButton = { TextButton(onClick = { model.revokeService(row); revoke = null }, enabled = !state.busy) { Text(uiText(UiTextKey.REVOKE_SERVICE_CD10D)) } },
            dismissButton = { TextButton(onClick = { revoke = null }, enabled = !state.busy) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
        )
    }
}

@Composable
private fun ServiceEditor(
    draft: ServiceEditorDraft,
    onChange: (ServiceEditorDraft) -> Unit,
    devices: List<DeviceRow>,
    busy: Boolean,
    sameContext: Boolean,
    onSave: () -> Unit,
    onClose: () -> Unit,
) {
    var choosingHost by remember(draft.id) { mutableStateOf(false) }
    var confirmClose by remember(draft.id) { mutableStateOf(false) }
    val chosenHost = devices.firstOrNull { it.id == draft.hostDeviceId }
    Surface(color = MaterialTheme.colorScheme.surface, shape = MaterialTheme.shapes.medium) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(if (draft.revision == null) uiText(UiTextKey.NEW_SERVICE_CONFIGURATION_A3342) else uiText(UiTextKey.EDIT_SERVICE_CONFIGURATION_27D2B), style = MaterialTheme.typography.titleLarge)
            Text("${draft.id}${draft.revision?.let { uiText(UiTextKey.REVISION_19E71, it) }.orEmpty()}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            ServiceField(uiText(UiTextKey.SERVICE_NAME_5DF7B), draft.name, { onChange(draft.copy(name = it)) }, !busy)
            OutlinedButton(onClick = { choosingHost = true }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text(chosenHost?.let { uiText(UiTextKey.HOST_04166, it.name) } ?: if (draft.hostDeviceId.isBlank()) uiText(UiTextKey.CHOOSE_TARGET_DEVICE_BA996) else uiText(UiTextKey.CHOOSE_TARGET_DEVICE_AGAIN_C22FB, draft.hostDeviceId))
            }
            if (devices.isEmpty()) Text(uiText(UiTextKey.THERE_ARE_NO_OTHER_ELIGIBLE_HOSTS_42455), style = MaterialTheme.typography.bodySmall)
            ServiceField(uiText(UiTextKey.EDGE_NODE_ID_E5B34), draft.edgeNodeId, { onChange(draft.copy(edgeNodeId = it)) }, !busy)
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                listOf("http", "https", "tcp", "udp").forEach { protocol ->
                    OutlinedButton(onClick = { onChange(draft.copy(protocol = protocol, ingress = if (protocol in listOf("http", "https")) "" else "29100")) }, enabled = !busy && draft.protocol != protocol) { Text(protocol.uppercase()) }
                }
            }
            ServiceField(if (draft.protocol in listOf("http", "https")) uiText(UiTextKey.INGRESS_HOSTNAME_5BE4F) else uiText(UiTextKey.INGRESS_PORT_74574), draft.ingress, { onChange(draft.copy(ingress = it)) }, !busy)
            ServiceField(uiText(UiTextKey.ALLOWED_SOURCES_ONE_CIDR_PER_LINE_3F9E4), draft.sources, { onChange(draft.copy(sources = it)) }, !busy, singleLine = false)
            Text(uiText(UiTextKey.AN_EMPTY_LIST_DENIES_ALL_VISITORS_73786), style = MaterialTheme.typography.bodySmall)
            ServiceField(uiText(UiTextKey.MAXIMUM_CONCURRENT_CONNECTIONS_AAC7A), draft.maximumConnections, { onChange(draft.copy(maximumConnections = it)) }, !busy)
            ServiceField(uiText(UiTextKey.BYTES_PER_SECOND_LIMIT_43523), draft.bytesPerSecond, { onChange(draft.copy(bytesPerSecond = it)) }, !busy)
            ServiceField(uiText(UiTextKey.TOTAL_BYTES_LIMIT_C479B), draft.maximumBytes, { onChange(draft.copy(maximumBytes = it)) }, !busy)
            ServiceField(uiText(UiTextKey.IDLE_TIMEOUT_SECONDS_AF0AF), draft.idleTimeoutSeconds, { onChange(draft.copy(idleTimeoutSeconds = it)) }, !busy)
            Text(uiText(UiTextKey.SAVING_SUBMITS_INGRESS_SETTINGS_ONLY_THE_755BE), style = MaterialTheme.typography.bodySmall)
            if (!sameContext) Text(uiText(UiTextKey.YOUR_SIGN_IN_SESSION_CHANGED_THE_04457), color = MaterialTheme.colorScheme.error)
            Button(onClick = onSave, enabled = !busy && sameContext && chosenHost != null && !draft.unchanged(), modifier = Modifier.fillMaxWidth()) { Text(if (draft.unchanged()) uiText(UiTextKey.CONFIGURATION_SAVED_985C5) else uiText(UiTextKey.SAVE_CONFIGURATION_6E584)) }
            TextButton(onClick = { if (draft.unchanged()) onClose() else confirmClose = true }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text(uiText(UiTextKey.CLOSE_EDITOR_64280)) }
        }
    }
    if (choosingHost) AlertDialog(
        onDismissRequest = { choosingHost = false }, title = { Text(uiText(UiTextKey.CHOOSE_ANOTHER_DEVICE_A2EFA)) },
        text = { LazyColumn { items(devices, key = { it.id }) { device ->
            TextButton(onClick = { onChange(draft.copy(hostDeviceId = device.id)); choosingHost = false }) { Column { Text(device.name); Text(device.id, style = MaterialTheme.typography.bodySmall) } }
        } } }, confirmButton = { TextButton(onClick = { choosingHost = false }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
    )
    if (confirmClose) AlertDialog(
        onDismissRequest = { confirmClose = false }, title = { Text(uiText(UiTextKey.CLOSE_THE_CURRENT_DRAFT_4385F)) },
        text = { Text(uiText(UiTextKey.UNCONFIRMED_CHANGES_WILL_BE_DISCARDED_IF_E7781)) },
        confirmButton = { TextButton(onClick = { confirmClose = false; onClose() }) { Text(uiText(UiTextKey.DISCARD_DRAFT_70403)) } },
        dismissButton = { TextButton(onClick = { confirmClose = false }) { Text(uiText(UiTextKey.KEEP_DRAFT_F5140)) } },
    )
}

@Composable
private fun ServiceField(label: String, value: String, changed: (String) -> Unit, enabled: Boolean, singleLine: Boolean = true) {
    OutlinedTextField(value = value, onValueChange = { if (it.length <= 4096) changed(it) },
        label = { Text(label) }, enabled = enabled, singleLine = singleLine,
        minLines = if (singleLine) 1 else 3, maxLines = if (singleLine) 1 else 8, modifier = Modifier.fillMaxWidth())
}
